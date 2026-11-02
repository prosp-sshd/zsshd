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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
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
  ssh_channel channel;
};

/* --- optional-auth helpers -------------------------------------------- */

static int password_auth_configured(void) {
  return access(ZSSHD_PASSWORD, F_OK) == 0;
}
static int pubkey_auth_configured(void) {
  return access(ZSSHD_AUTHKEYS, F_OK) == 0;
}
/* Passwordless root is the default, but only while the operator has not opted
 * into a real method by dropping in a password or authorized_keys file. */
static int none_auth_allowed(void) {
  return !password_auth_configured() && !pubkey_auth_configured();
}

/* --- auth callbacks --------------------------------------------------- */

static int auth_none_cb(ssh_session session, const char *user, void *userdata) {
  (void)session;
  (void)user;
  struct session_state *st = (struct session_state *)userdata;
  if (!none_auth_allowed()) {
    return SSH_AUTH_DENIED;
  }
  st->authenticated = 1;
  return SSH_AUTH_SUCCESS;
}

static int auth_password_cb(ssh_session session, const char *user,
                            const char *password, void *userdata) {
  (void)session;
  (void)user;
  struct session_state *st = (struct session_state *)userdata;

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
     * just the base64 blob with its type prefix. */
    char *type = strtok(line, " \t");
    char *b64 = type ? strtok(NULL, " \t") : NULL;
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
  /* Route subsequent channel data to the default SFTP handler. Its userdata
   * must be the sftp_session pointer, so this is a separate callback struct
   * from our control callbacks (which carry session_state). */
  memset(&st->sftp_data_cb, 0, sizeof(st->sftp_data_cb));
  st->sftp_data_cb.userdata = &st->sftp;
  st->sftp_data_cb.channel_data_function = sftp_channel_default_data_callback;
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

static void *handle_session(void *arg) {
  ssh_session session = (ssh_session)arg;
  struct session_state st;
  memset(&st, 0, sizeof(st));

  if (ssh_handle_key_exchange(session) != SSH_OK) {
    printf("[zsshd] key exchange failed: %s\n", ssh_get_error(session));
    goto done;
  }

  struct ssh_server_callbacks_struct server_cb;
  memset(&server_cb, 0, sizeof(server_cb));
  server_cb.userdata = &st;
  server_cb.auth_none_function = auth_none_cb;
  server_cb.auth_password_function = auth_password_cb;
  server_cb.auth_pubkey_function = auth_pubkey_cb;
  server_cb.channel_open_request_session_function = channel_open_cb;
  ssh_callbacks_init(&server_cb);
  ssh_set_server_callbacks(session, &server_cb);

  int methods = SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY;
  if (none_auth_allowed()) {
    methods |= SSH_AUTH_METHOD_NONE;
  }
  ssh_set_auth_methods(session, methods);

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
      /* SFTP: libssh's default callbacks drive the protocol off incoming
       * channel data, so just pump the event loop until the client is done. */
      while (g_running && ssh_channel_is_open(st.channel) &&
             !ssh_channel_is_eof(st.channel)) {
        if (ssh_event_dopoll(event, 500) == SSH_ERROR) {
          break;
        }
      }
      if (st.sftp) {
        sftp_free(st.sftp);
        st.sftp = NULL;
      }
      ssh_channel_send_eof(st.channel);
      ssh_channel_close(st.channel);
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
    }
  }

  ssh_event_free(event);

done:
  ssh_disconnect(session);
  ssh_free(session);
  return NULL;
}

/* --- host key --------------------------------------------------------- */

static int ensure_hostkey(void) {
  (void)mkdir(ZSSHD_DIR, 0700);
  if (access(ZSSHD_HOSTKEY, F_OK) == 0) {
    return 0;
  }
  ssh_key key = NULL;
  /* RSA, not ed25519: the mbedtls crypto backend is unreliable for ed25519.
   * libssh 0.12 replaced ssh_pki_generate(type, bits, ...) with a PKI context
   * that carries the RSA size. */
  ssh_pki_ctx pki = ssh_pki_ctx_new();
  if (pki == NULL) {
    return -1;
  }
  int bits = 2048;
  (void)ssh_pki_ctx_options_set(pki, SSH_PKI_OPTION_RSA_KEY_SIZE, &bits);
  int grc = ssh_pki_generate_key(SSH_KEYTYPE_RSA, pki, &key);
  ssh_pki_ctx_free(pki);
  if (grc != SSH_OK) {
    return -1;
  }
  int rc = ssh_pki_export_privkey_file(key, NULL, NULL, NULL, ZSSHD_HOSTKEY);
  ssh_key_free(key);
  return (rc == SSH_OK) ? 0 : -1;
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
  int port = cfg.port;
  /* The first bind must succeed (the port may belong to something else);
   * later re-binds retry until they do. */
  g_bind = listener_open(&cfg);
  if (!g_bind) {
    return -1;
  }

  g_running = 1;
  printf("[zsshd] SSH listening on port %d\n", port);

  {
    char ip[64];
    local_ip(ip, sizeof(ip));
    char toast[192];
    snprintf(toast, sizeof(toast),
             "zSSHd [ver.%s] by JinxCase Started\n%s:%d", ZSSHD_VERSION, ip,
             port);
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
