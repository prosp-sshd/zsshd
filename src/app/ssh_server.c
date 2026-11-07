#include "ssh_server.h"

#if defined(PLATFORM_PS5)

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <libssh/sftp.h>
#include <libssh/sftpserver.h>

#include "shell.h"
#include "pal_notification.h"
#include "zsshd_version.h"
#include "zsshd_config.h"
#include "firstrun.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#ifndef ZSSHD_PORT
#define ZSSHD_PORT 22
#endif
#ifndef ZSSHD_DIR
#define ZSSHD_DIR "/data/zsshd"
#endif
#define ZSSHD_HOSTKEY  ZSSHD_DIR "/hostkey"
#define ZSSHD_PASSWORD ZSSHD_DIR "/password"
#define ZSSHD_AUTHKEYS ZSSHD_DIR "/authorized_keys"

static ssh_bind g_bind = NULL;
static volatile sig_atomic_t g_running = 0;
/* /data/zsshd/passwordauth: 0 turns password login off (public key only);
 * default 1. Read once at startup, like the other settings. */
static int g_password_auth = 1;

/* Per-session state threaded through the libssh callbacks. */
struct session_state {
  int authenticated;
  int channel_wanted_shell;
  int pty_requested;
  int exec_requested;
  char exec_cmd[2048];
  int sftp_requested;
  int pty_rows;
  int pty_cols;
  sftp_session sftp;
  struct ssh_channel_callbacks_struct sftp_data_cb;
  /* SFTP bytes received but not yet answered (see sftp_queue_cb): the
   * unanswered bytes are sftp_in[sftp_in_off .. sftp_in_len). */
  uint8_t *sftp_in;
  size_t sftp_in_off;
  size_t sftp_in_len;
  size_t sftp_in_cap;
  ssh_channel channel;
};

/* --- auth helpers ----------------------------------------------------- */

/* Login needs a credential: a password file (unless password login is turned
 * off) or an authorized_keys file. With neither, every login is refused; there
 * is no passwordless ("none") login. Both files are checked per login, so
 * adding one takes effect without a restart. */
static int password_auth_configured(void) {
  return g_password_auth && access(ZSSHD_PASSWORD, F_OK) == 0;
}
static int pubkey_auth_configured(void) {
  return access(ZSSHD_AUTHKEYS, F_OK) == 0;
}

/* --- auth callbacks --------------------------------------------------- */

static int auth_password_cb(ssh_session session, const char *user,
                            const char *password, void *userdata) {
  (void)session;
  (void)user;
  struct session_state *st = (struct session_state *)userdata;

  if (!g_password_auth) {
    return SSH_AUTH_DENIED; /* password login turned off */
  }
  FILE *f = fopen(ZSSHD_PASSWORD, "r");
  if (!f) {
    return SSH_AUTH_DENIED; /* password method not configured */
  }
  char stored[256];
  char *line = fgets(stored, sizeof(stored), f);
  fclose(f);
  if (!line) {
    return SSH_AUTH_DENIED;
  }
  stored[strcspn(stored, "\r\n")] = '\0';
  if (stored[0] == '\0') {
    return SSH_AUTH_DENIED; /* an empty password is no credential */
  }

  if (strcmp(stored, password) == 0) {
    st->authenticated = 1;
    return SSH_AUTH_SUCCESS;
  }
  return SSH_AUTH_DENIED;
}

/* Returns 1 if the offered public key matches a line in authorized_keys. */
static int pubkey_in_authorized(ssh_key offered) {
  FILE *f = fopen(ZSSHD_AUTHKEYS, "r");
  if (!f) {
    return 0;
  }
  char line[4096];
  int matched = 0;
  while (fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }
    /* authorized_keys lines are "<type> <base64> [comment]"; libssh wants
     * just the base64 blob with its type prefix. strtok_r, not strtok: every
     * session runs this on its own thread, and strtok keeps one position for
     * the whole process, so two logins at once can mis-parse each other's
     * line and deny a valid key. */
    char *save = NULL;
    char *type = strtok_r(line, " \t", &save);
    char *b64 = type ? strtok_r(NULL, " \t", &save) : NULL;
    if (!type || !b64) {
      continue;
    }
    ssh_key candidate = NULL;
    if (ssh_pki_import_pubkey_base64(b64, ssh_key_type_from_name(type),
                                     &candidate) != SSH_OK) {
      continue;
    }
    if (ssh_key_cmp(offered, candidate, SSH_KEY_CMP_PUBLIC) == 0) {
      matched = 1;
    }
    ssh_key_free(candidate);
    if (matched) {
      break;
    }
  }
  fclose(f);
  return matched;
}

static int auth_pubkey_cb(ssh_session session, const char *user,
                          struct ssh_key_struct *pubkey, char signature_state,
                          void *userdata) {
  (void)session;
  (void)user;
  struct session_state *st = (struct session_state *)userdata;

  if (!pubkey_auth_configured()) {
    return SSH_AUTH_DENIED;
  }
  /* Probe phase: tell the client the key is acceptable so it will sign. */
  if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
    return pubkey_in_authorized(pubkey) ? SSH_AUTH_SUCCESS : SSH_AUTH_DENIED;
  }
  /* Signature phase: only accept a cryptographically valid signature from a
   * key we actually trust. */
  if (signature_state == SSH_PUBLICKEY_STATE_VALID &&
      pubkey_in_authorized(pubkey)) {
    st->authenticated = 1;
    return SSH_AUTH_SUCCESS;
  }
  return SSH_AUTH_DENIED;
}

/* --- channel callbacks ------------------------------------------------ */

static int pty_request_cb(ssh_session session, ssh_channel channel,
                          const char *term, int cols, int rows, int px, int py,
                          void *userdata) {
  (void)session;
  (void)channel;
  (void)term;
  (void)px;
  (void)py;
  struct session_state *st = (struct session_state *)userdata;
  st->pty_requested = 1;
  st->pty_cols = cols;
  st->pty_rows = rows;
  return 0; /* accept the pty */
}

static int shell_request_cb(ssh_session session, ssh_channel channel,
                            void *userdata) {
  (void)session;
  (void)channel;
  struct session_state *st = (struct session_state *)userdata;
  st->channel_wanted_shell = 1;
  return 0; /* accept the shell */
}

static int exec_request_cb(ssh_session session, ssh_channel channel,
                           const char *command, void *userdata) {
  (void)session;
  (void)channel;
  struct session_state *st = (struct session_state *)userdata;
  snprintf(st->exec_cmd, sizeof(st->exec_cmd), "%s", command ? command : "");
  st->exec_requested = 1;
  return 0; /* accept the exec request */
}

/* --- SFTP ------------------------------------------------------------- */

/* libssh's default SFTP data callback answers each request while it is still
 * inside the receive callback. There the session socket's poll handle is
 * locked, so libssh only waits for POLLOUT on it. With many reads in flight
 * (sftp's default is 64 x 32 KB) the replies use up the client's channel
 * window (OpenSSH: 2 MB). channel_write then waits for a WINDOW_ADJUST it can
 * never read, and the session hangs for good. Seen on a console with OpenSSH's
 * sftp: 3 of 3 default gets of a 100 MB file stopped at 4063232-4128768
 * bytes, while -R 2..32 finished (libssh issue #181).
 *
 * So the callback only queues the bytes and returns, and handle_session
 * answers whole packets after ssh_event_dopoll returns. A write that waits
 * for window there can read the adjust. Data that arrives during that wait
 * goes back through this callback into the queue. */

/* Largest SFTP packet accepted (length field). OpenSSH sends at most 256 KB. */
#define SFTP_MAX_PACKET (4u * 1024u * 1024u)

static int sftp_queue_cb(ssh_session session, ssh_channel channel,
                         void *data, uint32_t len, int is_stderr,
                         void *userdata) {
  (void)session;
  (void)channel;
  (void)is_stderr;
  struct session_state *st = (struct session_state *)userdata;
  if (len == 0) {
    return 0;
  }
  if (st->sftp_in_len + len > st->sftp_in_cap && st->sftp_in_off > 0) {
    /* Reuse the answered space at the front before growing. Safe while
     * sftp_process_queue is inside libssh's callback: the packet it is
     * answering was already copied out by libssh (see there). */
    st->sftp_in_len -= st->sftp_in_off;
    memmove(st->sftp_in, st->sftp_in + st->sftp_in_off, st->sftp_in_len);
    st->sftp_in_off = 0;
  }
  if (st->sftp_in_len + len > st->sftp_in_cap) {
    size_t cap = st->sftp_in_cap ? st->sftp_in_cap : 65536;
    while (cap < st->sftp_in_len + len) {
      cap *= 2;
    }
    uint8_t *p = realloc(st->sftp_in, cap);
    if (!p) {
      return SSH_ERROR;
    }
    st->sftp_in = p;
    st->sftp_in_cap = cap;
  }
  memcpy(st->sftp_in + st->sftp_in_len, data, len);
  st->sftp_in_len += len;
  return (int)len;
}

/* Answers every whole packet in the queue, outside any libssh callback. A
 * partial packet at the end stays queued for the next poll. Returns -1 when
 * the session should end (bad packet, out of memory, request failed). */
static int sftp_process_queue(ssh_session session, struct session_state *st) {
  while (st->sftp_in_len - st->sftp_in_off >= 5) {
    uint8_t *p = st->sftp_in + st->sftp_in_off;
    uint32_t plen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                    ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    if (plen < 1 || plen > SFTP_MAX_PACKET) {
      printf("[zsshd] sftp: bad packet length %u\n", (unsigned)plen);
      return -1;
    }
    size_t total = (size_t)plen + 4;
    if (st->sftp_in_len - st->sftp_in_off < total) {
      break; /* wait for the rest of this packet */
    }
    /* Mark the packet answered before answering it: the answer can poll the
     * socket, and new data then lands in (and may move) the queue. The packet
     * itself is passed in place, with no copy: libssh's callback copies it
     * into its own buffer (sftp_decode_channel_data_to_packet) before it does
     * any I/O, and reads `p` no more once it has decoded exactly `total`
     * bytes, so a move of the queue after that cannot touch it. */
    st->sftp_in_off += total;

    int rc = sftp_channel_default_data_callback(session, st->channel, p,
                                                (uint32_t)total, 0, &st->sftp);
    if (rc != (int)total) {
      return -1; /* libssh has already closed the channel */
    }
    if (st->sftp_in_off == st->sftp_in_len) {
      st->sftp_in_off = st->sftp_in_len = 0; /* empty: start at the front */
    }
  }
  return 0;
}

static int subsystem_request_cb(ssh_session session, ssh_channel channel,
                                const char *subsystem, void *userdata) {
  struct session_state *st = (struct session_state *)userdata;
  if (strcmp(subsystem, "sftp") != 0) {
    return SSH_ERROR; /* only the sftp subsystem is supported */
  }
  /* Spin up libssh's built-in SFTP server on this channel. */
  if (sftp_channel_default_subsystem_request(session, channel, subsystem,
                                             &st->sftp) != SSH_OK) {
    return SSH_ERROR;
  }
  /* Channel data only goes into a queue here; handle_session answers it after
   * the poll returns (sftp_process_queue). A separate callback struct from the
   * control callbacks, added on top of them. */
  memset(&st->sftp_data_cb, 0, sizeof(st->sftp_data_cb));
  st->sftp_data_cb.userdata = st;
  st->sftp_data_cb.channel_data_function = sftp_queue_cb;
  ssh_callbacks_init(&st->sftp_data_cb);
  ssh_add_channel_callbacks(channel, &st->sftp_data_cb);
  st->sftp_requested = 1;
  return SSH_OK;
}

static ssh_channel channel_open_cb(ssh_session session, void *userdata) {
  struct session_state *st = (struct session_state *)userdata;
  if (st->channel) {
    return NULL; /* one session channel is enough for now */
  }
  st->channel = ssh_channel_new(session);
  return st->channel;
}

/* --- per-connection handler ------------------------------------------- */

/* After our channel close, give the client up to 2 s to answer with its own
 * close and drop the connection. Disconnecting at once cuts the TCP stream
 * before OpenSSH has read the exit status and sent its close, so it prints
 * "Connection to <host> closed by remote host." and exits non-zero even for
 * a good upload or exec. */
static void wait_client_close(ssh_session session, ssh_event event) {
  (void)ssh_blocking_flush(session, 1000); /* push our close out first */
  for (int i = 0; i < 20 && ssh_is_connected(session); i++) {
    if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
      return; /* the client closed the connection */
    }
  }
}

static void *handle_session(void *arg) {
  ssh_session session = (ssh_session)arg;
  struct session_state st;
  memset(&st, 0, sizeof(st));

  /* The server callbacks go in before the key exchange, as in libssh's own
   * example servers. The client sends its SERVICE_REQUEST right after its
   * NEWKEYS; when both arrive in one read, libssh handles the request inside
   * ssh_handle_key_exchange. With no server callbacks set yet, libssh queues
   * it as a message that nothing here ever answers, and the client waits at
   * auth until it times out (about 1 in 6000 loopback connections on macOS). */
  struct ssh_server_callbacks_struct server_cb;
  memset(&server_cb, 0, sizeof(server_cb));
  server_cb.userdata = &st;
  server_cb.auth_password_function = auth_password_cb;
  server_cb.auth_pubkey_function = auth_pubkey_cb;
  server_cb.channel_open_request_session_function = channel_open_cb;
  ssh_callbacks_init(&server_cb);
  ssh_set_server_callbacks(session, &server_cb);

  /* No "none" method: it has no callback, so libssh answers it with an auth
   * failure. Password is offered unless turned off in passwordauth. */
  int methods = SSH_AUTH_METHOD_PUBLICKEY;
  if (g_password_auth) {
    methods |= SSH_AUTH_METHOD_PASSWORD;
  }
  ssh_set_auth_methods(session, methods);

  if (ssh_handle_key_exchange(session) != SSH_OK) {
    printf("[zsshd] key exchange failed: %s\n", ssh_get_error(session));
    goto done;
  }

  struct ssh_channel_callbacks_struct channel_cb;
  memset(&channel_cb, 0, sizeof(channel_cb));
  channel_cb.userdata = &st;
  channel_cb.channel_pty_request_function = pty_request_cb;
  channel_cb.channel_shell_request_function = shell_request_cb;
  channel_cb.channel_exec_request_function = exec_request_cb;
  channel_cb.channel_subsystem_request_function = subsystem_request_cb;
  ssh_callbacks_init(&channel_cb);

  ssh_event event = ssh_event_new();
  ssh_event_add_session(event, session);

  /* Pump the event loop until the client authenticates and asks for a shell
   * on a session channel. */
  int set_channel_cb = 0;
  while (g_running && !(st.authenticated &&
                        (st.channel_wanted_shell || st.exec_requested ||
                         st.sftp_requested))) {
    if (ssh_event_dopoll(event, 500) == SSH_ERROR) {
      break;
    }
    if (st.channel && !set_channel_cb) {
      ssh_set_channel_callbacks(st.channel, &channel_cb);
      set_channel_cb = 1;
    }
  }

  if (st.authenticated && st.channel) {
    if (st.sftp_requested) {
      /* SFTP: the poll queues incoming requests (sftp_queue_cb); they are
       * answered here, outside the poll, until the client is done. */
      while (g_running && ssh_channel_is_open(st.channel) &&
             !ssh_channel_is_eof(st.channel)) {
        /* Drain first: the INIT can arrive in the same poll as the
         * subsystem request, before this loop starts. */
        if (sftp_process_queue(session, &st) != 0) {
          break;
        }
        if (ssh_event_dopoll(event, 500) == SSH_ERROR) {
          break;
        }
      }
      /* Requests that came in with the client's EOF. */
      if (ssh_channel_is_open(st.channel)) {
        (void)sftp_process_queue(session, &st);
      }
      /* A subsystem ends with an exit status too (OpenSSH's sshd sends 0).
       * Sent before sftp_free: that sends EOF, closes and frees the channel
       * (at once if the client already closed it), so st.channel must not be
       * used after it. Sending the exit status, EOF and close after sftp_free
       * crashed the whole process when the client closed first. */
      if (ssh_channel_is_open(st.channel)) {
        ssh_channel_request_send_exit_status(st.channel, 0);
      }
      if (st.sftp) {
        sftp_free(st.sftp);
        st.sftp = NULL;
      } else {
        ssh_channel_send_eof(st.channel);
        ssh_channel_close(st.channel);
      }
      st.channel = NULL;
      free(st.sftp_in);
      st.sftp_in = NULL;
      wait_client_close(session, event);
    } else {
      int status = 0;
      if (st.exec_requested) {
        /* `ssh host 'command'` */
        status = shell_exec(st.channel, st.exec_cmd);
      } else if (st.channel_wanted_shell) {
        /* interactive iff a PTY was requested; otherwise scripted stdin */
        shell_run(st.channel, st.pty_requested, st.pty_rows);
      }
      ssh_channel_request_send_exit_status(st.channel, status);
      ssh_channel_send_eof(st.channel);
      ssh_channel_close(st.channel);
      wait_client_close(session, event);
    }
  }

  ssh_event_free(event);

done:
  ssh_disconnect(session);
  ssh_free(session);
  return NULL;
}

/* --- session socket tuning -------------------------------------------- */

/* Socket buffer size asked for on each session socket. 1 MB stays under
 * FreeBSD's default kern.ipc.maxsockbuf (2 MB, of which about 1.78 MB is
 * usable per buffer); a refused size is halved until it is taken. */
#define SESSION_SOCKBUF (1024 * 1024)
#define SESSION_SOCKBUF_MIN (128 * 1024)

static int get_sockbuf(int fd, int opt) {
  int v = -1;
  socklen_t l = sizeof(v);
  if (getsockopt(fd, SOL_SOCKET, opt, &v, &l) != 0) {
    return -1;
  }
  return v;
}

static void set_sockbuf(int fd, int opt) {
  for (int want = SESSION_SOCKBUF; want >= SESSION_SOCKBUF_MIN; want /= 2) {
    if (setsockopt(fd, SOL_SOCKET, opt, &want, sizeof(want)) == 0) {
      return;
    }
  }
}

/* Tune an accepted session socket before the key exchange:
 *   - TCP_NODELAY. libssh sets it only on its client connect path, so the
 *     server ran with Nagle on. An SFTP read reply is one full 32 KB channel
 *     packet plus a small tail packet; with Nagle the tail waits for the
 *     client's (delayed) ACK of the data before it, so a get at one request in
 *     flight spent most of each round trip idle.
 *   - Larger SO_SNDBUF/SO_RCVBUF for pipelined transfers. Setting a size turns
 *     off FreeBSD's buffer autosizing on this socket, so the values before
 *     and after go to the log to compare against.
 * Every step is best effort: a failure is logged and the session goes on. */
static void tune_session_socket(int fd) {
  if (fd < 0) {
    return;
  }
  int one = 1;
  int nodelay = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  int snd0 = get_sockbuf(fd, SO_SNDBUF);
  int rcv0 = get_sockbuf(fd, SO_RCVBUF);
  set_sockbuf(fd, SO_SNDBUF);
  set_sockbuf(fd, SO_RCVBUF);
  printf("[zsshd] session socket: nodelay %s, sndbuf %d -> %d, rcvbuf %d -> %d\n",
         nodelay == 0 ? "on" : "failed", snd0, get_sockbuf(fd, SO_SNDBUF), rcv0,
         get_sockbuf(fd, SO_RCVBUF));
}

/* --- host key --------------------------------------------------------- */

/* The host private key must be readable by its owner only. Older builds let
 * libssh's fopen() create it, which left it 0666 on the console; such a key
 * is tightened to 0600 on every start. */
static int ensure_hostkey(void) {
  (void)mkdir(ZSSHD_DIR, 0700);
  if (access(ZSSHD_HOSTKEY, F_OK) == 0) {
    if (chmod(ZSSHD_HOSTKEY, 0600) != 0) {
      printf("[zsshd] chmod 0600 %s failed: %s\n", ZSSHD_HOSTKEY,
             strerror(errno));
    }
    return 0;
  }
  /* Create the file 0600 first: libssh then writes it with fopen("wb"),
   * which truncates and keeps the mode, so the key is never world-readable. */
  int fd = open(ZSSHD_HOSTKEY, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    return -1;
  }
  (void)fchmod(fd, 0600);
  close(fd);
  ssh_key key = NULL;
  /* RSA, not ed25519: the mbedtls crypto backend is unreliable for ed25519.
   * libssh 0.12 replaced ssh_pki_generate(type, bits, ...) with a PKI context
   * that carries the RSA size. */
  ssh_pki_ctx pki = ssh_pki_ctx_new();
  if (pki == NULL) {
    unlink(ZSSHD_HOSTKEY);
    return -1;
  }
  int bits = 2048;
  (void)ssh_pki_ctx_options_set(pki, SSH_PKI_OPTION_RSA_KEY_SIZE, &bits);
  int grc = ssh_pki_generate_key(SSH_KEYTYPE_RSA, pki, &key);
  ssh_pki_ctx_free(pki);
  if (grc != SSH_OK) {
    unlink(ZSSHD_HOSTKEY);
    return -1;
  }
  int rc = ssh_pki_export_privkey_file(key, NULL, NULL, NULL, ZSSHD_HOSTKEY);
  ssh_key_free(key);
  if (rc != SSH_OK) {
    unlink(ZSSHD_HOSTKEY); /* an empty file would skip generation next start */
    return -1;
  }
  return 0;
}

/* --- public entry points --------------------------------------------- */

/* Best-effort local LAN IP: connect a UDP socket toward a public address so
 * the kernel picks the outbound interface, then read it back. No packets are
 * actually sent. */
static void local_ip(char *out, size_t n) {
  snprintf(out, n, "0.0.0.0");
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    return;
  }
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(53);
  a.sin_addr.s_addr = inet_addr("8.8.8.8");
  if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
    struct sockaddr_in local;
    socklen_t ll = sizeof(local);
    if (getsockname(s, (struct sockaddr *)&local, &ll) == 0) {
      snprintf(out, n, "%s", inet_ntoa(local.sin_addr));
    }
  }
  close(s);
}

void ssh_server_request_stop(void) {
  g_running = 0;
}

/* --- listener ---------------------------------------------------------- */

/* Rest mode can leave the SSH listener dead while this process lives on:
 * after a wake the old socket no longer takes connections, so the payload had
 * to be sent again. The accept loop below therefore re-creates the listener,
 * in this same process (so the host key stays as it is), whenever:
 *   - poll() reports POLLERR/POLLHUP/POLLNVAL on it,
 *   - accept() fails with anything but a transient error, or
 *   - a periodic self-check connect to the listener's own address and port
 *     is not accepted within ZSSHD_PROBE_DEADLINE_S (covers a listener that
 *     fails silently).
 * The re-bind pattern is ps5-payload-dev/ftpsrv's (close, wait, bind again),
 * whose port came back by itself after the same wake. */
#ifndef ZSSHD_PROBE_INTERVAL_S
#define ZSSHD_PROBE_INTERVAL_S 10
#endif
#ifndef ZSSHD_PROBE_DEADLINE_S
#define ZSSHD_PROBE_DEADLINE_S 3
#endif
#ifndef ZSSHD_REBIND_PAUSE_S
#define ZSSHD_REBIND_PAUSE_S 3
#endif

/* Listener settings, read once at start so every re-created listener gets
 * the same port, bind address and log level as the first one. */
struct listener_cfg {
  int port;
  int loglevel;
  int have_bindaddr;
  char bindaddr[64];
};

static void listener_cfg_load(struct listener_cfg *c) {
  memset(c, 0, sizeof(*c));
  /* Listen port: /data/zsshd/port overrides the compile-time default. */
  c->port = zsshd_config_int("port", ZSSHD_PORT, 1, 65535);
  /* Optional bind address: /data/zsshd/bindaddr restricts the listener to
   * one interface (e.g. a LAN or Tailscale IP) instead of all interfaces.
   * Recommended when running passwordless root. Unset = listen on 0.0.0.0. */
  c->have_bindaddr =
      zsshd_config_str("bindaddr", c->bindaddr, sizeof(c->bindaddr));
  /* libssh log verbosity: /data/zsshd/loglevel 0..4 (none..functions);
   * default 0 (quiet). Raise for connection/auth debugging. */
  c->loglevel = zsshd_config_int("loglevel", 0, 0, 4);
}

static double mono_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Sleep up to `seconds`, returning early once a stop is requested. */
static void pause_while_running(int seconds) {
  for (int i = 0; g_running && i < seconds * 10; i++) {
    usleep(100000);
  }
}

static ssh_bind listener_open(const struct listener_cfg *c) {
  ssh_bind b = ssh_bind_new();
  if (!b) {
    printf("[zsshd] ssh_bind_new failed\n");
    return NULL;
  }
  int port = c->port;
  ssh_bind_options_set(b, SSH_BIND_OPTIONS_BINDPORT, &port);
  if (c->have_bindaddr) {
    ssh_bind_options_set(b, SSH_BIND_OPTIONS_BINDADDR, c->bindaddr);
  }
  {
    int loglevel = c->loglevel;
    ssh_bind_options_set(b, SSH_BIND_OPTIONS_LOG_VERBOSITY, &loglevel);
  }
  ssh_bind_options_set(b, SSH_BIND_OPTIONS_HOSTKEY, ZSSHD_HOSTKEY);
  /* Prefer hardware-accelerated AES-GCM (PS5 CPU has AES-NI) for transfer
   * throughput, then AES-CTR, then software chacha20-poly1305. */
  {
    const char *ciphers = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
                          "aes256-ctr,aes128-ctr,"
                          "chacha20-poly1305@openssh.com";
    ssh_bind_options_set(b, SSH_BIND_OPTIONS_CIPHERS_C_S, ciphers);
    ssh_bind_options_set(b, SSH_BIND_OPTIONS_CIPHERS_S_C, ciphers);
  }
  if (ssh_bind_listen(b) != SSH_OK) {
    printf("[zsshd] bind/listen failed: %s\n", ssh_get_error(b));
    ssh_bind_free(b);
    return NULL;
  }
  return b;
}

/* Self-check probe: a non-blocking connect to the listener's own address (the
 * configured bindaddr, else loopback) that the accept loop expects to see come
 * in on the listener. */
struct probe {
  int fd;
  in_addr_t addr;       /* address probed, network byte order */
  in_port_t local_port; /* network byte order */
  double sent;
  double next;
};

static void probe_close(struct probe *p) {
  if (p->fd >= 0) {
    close(p->fd);
  }
  p->fd = -1;
  p->local_port = 0;
}

/* The address the listener is bound to, for the probe to connect to: the
 * bindaddr when it is an IPv4 address, else loopback. A wildcard bindaddr is
 * reached through loopback too. Probing loopback with a non-loopback bindaddr
 * would be refused, and the healthy listener re-created over and over.
 * Returns 0 when there is no IPv4 address to probe (an IPv6 or host name
 * bindaddr): the self-check is then skipped, and only poll() and accept()
 * errors re-create the listener. */
static int probe_target(const struct listener_cfg *c, in_addr_t *out) {
  struct in_addr in;
  if (!c->have_bindaddr) {
    *out = htonl(INADDR_LOOPBACK);
    return 1;
  }
  if (inet_pton(AF_INET, c->bindaddr, &in) != 1) {
    return 0;
  }
  *out = in.s_addr == htonl(INADDR_ANY) ? htonl(INADDR_LOOPBACK) : in.s_addr;
  return 1;
}

/* Returns 0 when the probe is in flight, -1 when the connect was refused
 * outright (listener gone). Any other local failure skips this round. */
static int probe_send(struct probe *p, const struct listener_cfg *c,
                      double now) {
  p->next = now + ZSSHD_PROBE_INTERVAL_S;
  in_addr_t target;
  if (!probe_target(c, &target)) {
    return 0;
  }
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    return 0;
  }
  int fl = fcntl(s, F_GETFL, 0);
  if (fl < 0 || fcntl(s, F_SETFL, fl | O_NONBLOCK) < 0) {
    close(s);
    return 0;
  }
  struct sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t)c->port);
  a.sin_addr.s_addr = target;
  if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0 &&
      errno != EINPROGRESS) {
    int e = errno;
    close(s);
    return e == ECONNREFUSED ? -1 : 0;
  }
  struct sockaddr_in local;
  socklen_t ll = sizeof(local);
  if (getsockname(s, (struct sockaddr *)&local, &ll) != 0) {
    close(s);
    return 0;
  }
  p->fd = s;
  p->addr = a.sin_addr.s_addr;
  p->local_port = local.sin_port;
  p->sent = now;
  return 0;
}

static int is_probe(const struct probe *p, const struct sockaddr_in *peer) {
  return p->fd >= 0 && peer->sin_family == AF_INET &&
         peer->sin_addr.s_addr == p->addr &&
         peer->sin_port == p->local_port;
}

static void start_session(int fd) {
  ssh_session session = ssh_new();
  if (!session) {
    close(fd);
    return;
  }
  if (ssh_bind_accept_fd(g_bind, session, fd) != SSH_OK) {
    /* libssh owns the fd only once it reached the session socket; close it
     * ourselves otherwise, so it is closed exactly once. */
    if (ssh_get_fd(session) != fd) {
      close(fd);
    }
    ssh_free(session);
    return;
  }

  pthread_t t;
  pthread_attr_t attr;
  int have_attr = (pthread_attr_init(&attr) == 0);
  if (have_attr) {
    (void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    /* libssh's handshake plus the shell's recursive cp/rm need more than the
     * small default thread stack; a too-small stack segfaults the whole
     * payload, since every connection shares this process. */
    (void)pthread_attr_setstacksize(&attr, 1024 * 1024);
  }
  if (pthread_create(&t, have_attr ? &attr : NULL, handle_session,
                     session) != 0) {
    ssh_disconnect(session);
    ssh_free(session);
  }
  if (have_attr) {
    (void)pthread_attr_destroy(&attr);
  }
}

int ssh_server_run(void) {
  if (ssh_init() != SSH_OK) {
    return -1;
  }
  if (ensure_hostkey() != 0) {
    printf("[zsshd] could not create host key\n");
    return -1;
  }

  struct listener_cfg cfg;
  listener_cfg_load(&cfg);
  /* Password login: /data/zsshd/passwordauth 0 turns it off; default 1. */
  g_password_auth = zsshd_config_int("passwordauth", 1, 0, 1);
  int port = cfg.port;

  /* First-run: make sure there is a usable credential before we accept
   * connections -- generates a random root password (shown on the TV) when
   * nothing is configured. */
  char autopw[64];
  int show_pw = firstrun_password(autopw, sizeof(autopw));

  /* The first bind must succeed (the port may belong to something else);
   * later re-binds retry until they do. */
  g_bind = listener_open(&cfg);
  if (!g_bind) {
    return -1;
  }

  g_running = 1;
  printf("[zsshd] SSH listening on port %d\n", port);
  int have_credential = password_auth_configured() || pubkey_auth_configured();
  if (!have_credential) {
    printf("[zsshd] no %s%s: all logins refused\n",
           g_password_auth ? ZSSHD_PASSWORD " or " : "", ZSSHD_AUTHKEYS);
  }

  {
    char ip[64];
    local_ip(ip, sizeof(ip));
    char toast[256];
    if (show_pw) {
      snprintf(toast, sizeof(toast),
               "zSSHd [ver.%s] by JinxCase Started\n%s:%d\nroot password: %s",
               ZSSHD_VERSION, ip, port, autopw);
    } else {
      snprintf(toast, sizeof(toast),
               "zSSHd [ver.%s] by JinxCase Started\n%s:%d%s", ZSSHD_VERSION,
               ip, port,
               have_credential ? "" : "\nNo login set up: all refused");
    }
    pal_notification_send(toast);
  }

  struct probe probe = {-1, 0, 0, 0.0, mono_now() + ZSSHD_PROBE_INTERVAL_S};
  int bind_fd = ssh_bind_get_fd(g_bind);
  const char *why = NULL; /* set: drop and re-create the listener */

  while (g_running) {
    if (why) {
      printf("[zsshd] SSH listener on port %d is dead (%s); re-creating\n",
             port, why);
      why = NULL;
      probe_close(&probe);
      ssh_bind_free(g_bind);
      g_bind = NULL;
      while (g_running && !g_bind) {
        pause_while_running(ZSSHD_REBIND_PAUSE_S);
        if (g_running) {
          g_bind = listener_open(&cfg);
        }
      }
      if (!g_bind) {
        break;
      }
      bind_fd = ssh_bind_get_fd(g_bind);
      probe.next = mono_now() + ZSSHD_PROBE_INTERVAL_S;
      printf("[zsshd] SSH listening on port %d again\n", port);
      continue;
    }

    struct pollfd pfd;
    pfd.fd = bind_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int pr = poll(&pfd, 1, 500);
    double now = mono_now();

    if (pr < 0 && errno != EINTR) {
      why = "poll failed";
      continue;
    }
    if (pr > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
      why = (pfd.revents & POLLNVAL) ? "POLLNVAL" : "POLLERR/POLLHUP";
      continue;
    }
    if (pr > 0 && (pfd.revents & POLLIN)) {
      struct sockaddr_in peer;
      socklen_t pl = sizeof(peer);
      memset(&peer, 0, sizeof(peer));
      int fd = accept(bind_fd, (struct sockaddr *)&peer, &pl);
      if (fd < 0) {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK &&
            errno != ECONNABORTED) {
          why = "accept failed";
        }
        continue;
      }
      if (is_probe(&probe, &peer)) {
        close(fd); /* the listener took our own self-check: healthy */
        probe_close(&probe);
        continue;
      }
      start_session(fd);
      continue;
    }
    tune_session_socket((int)ssh_get_fd(session));

    /* Idle: run the self-check. */
    if (probe.fd >= 0) {
      if (now - probe.sent >= ZSSHD_PROBE_DEADLINE_S) {
        why = "self-check connect not accepted";
      }
    } else if (now >= probe.next) {
      if (probe_send(&probe, &cfg, now) != 0) {
        why = "self-check connect refused";
      }
    }
  }

  probe_close(&probe);
  ssh_bind_free(g_bind);
  g_bind = NULL;
  ssh_finalize();
  return 0;
}

#else /* !PLATFORM_PS5 */

void ssh_server_request_stop(void) {}
int ssh_server_run(void) { return -1; }

#endif
