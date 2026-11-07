#include "cmdline.h"

#include <stdio.h>
#include <string.h>

#define NOFILE "error: syntax error: expected filename after redirection"
#define BADFD "error: syntax error: bad file descriptor number"

static int fails = 0;
static int cases = 0;

static void put(char *out, size_t cap, const char *s) {
  size_t n = strlen(out);
  snprintf(out + n, cap - n, "%s", s);
}

/* Render one redirection as " <f", " >f" or " >>f", with the descriptor in
 * front when it is not the operator's default (" 2>f"), or as " N>&M" for a
 * dup (written either way, "N>&M" or "N<&M"). */
static void put_redir(char *out, size_t cap, const struct cmdline_redir_op *o) {
  char buf[16];
  if (o->kind == CMDLINE_DUP) {
    snprintf(buf, sizeof(buf), " %d>&%d", o->fd, o->dup_fd);
    put(out, cap, buf);
    return;
  }
  int dflt = o->kind == CMDLINE_IN ? 0 : 1;
  const char *sym = o->kind == CMDLINE_IN    ? "<"
                    : o->kind == CMDLINE_OUT ? ">"
                                             : ">>";
  if (o->fd != dflt) {
    snprintf(buf, sizeof(buf), " %d%s", o->fd, sym);
  } else {
    snprintf(buf, sizeof(buf), " %s", sym);
  }
  put(out, cap, buf);
  put(out, cap, o->path);
}

/* Run `in` through the same steps the shell takes (cut at ';' / newline, then
 * at '|', then cmdline_parse() on each command) and render the result: each
 * word as [word], then each redirection in order (see put_redir()); commands
 * joined by " | " and " ; ". An error renders as "error: <message>". */
static void render(const char *in, int max, char *out, size_t cap) {
  char work[512];
  snprintf(work, sizeof(work), "%s", in);
  out[0] = '\0';
  char *seg = work;
  for (int si = 0;; si++) {
    char *sp = cmdline_find_sep(seg, ";\n");
    char send = *sp;
    *sp = '\0';
    if (si > 0) {
      put(out, cap, " ; ");
    }
    char *cmd = seg;
    for (int ci = 0;; ci++) {
      char *cp = cmdline_find_sep(cmd, "|");
      char cend = *cp;
      *cp = '\0';
      if (ci > 0) {
        put(out, cap, " | ");
      }
      char *argv[8];
      struct cmdline_redir r;
      const char *err = NULL;
      int argc = cmdline_parse(cmd, argv, max, &r, &err);
      if (argc < 0) {
        snprintf(out, cap, "error: %s", err ? err : "(null)");
        return;
      }
      for (int i = 0; i < argc; i++) {
        put(out, cap, "[");
        put(out, cap, argv[i]);
        put(out, cap, "]");
      }
      for (int i = 0; i < r.n; i++) {
        put_redir(out, cap, &r.op[i]);
      }
      if (cend == '\0') {
        break;
      }
      cmd = cp + 1;
    }
    if (send == '\0') {
      break;
    }
    seg = sp + 1;
  }
}

static void checkm(const char *in, int max, const char *want) {
  char got[512];
  render(in, max, got, sizeof(got));
  cases++;
  if (strcmp(got, want) != 0) {
    printf("FAIL: %s\n  got:  %s\n  want: %s\n", in, got, want);
    fails++;
  }
}

static void check(const char *in, const char *want) { checkm(in, 8, want); }

/* Parse one command, route its redirections and render where descriptors
 * 0-2 end up: "0:X 1:X 2:X", X being a file name, &k for the descriptor k the
 * command started with (in the shell: the terminal, or the pipe for a stage
 * before '|'), or - for closed. */
static void checkr(const char *in, const char *want) {
  char work[512], got[512];
  snprintf(work, sizeof(work), "%s", in);
  char *argv[8];
  struct cmdline_redir r;
  struct cmdline_fd fds[CMDLINE_NFD];
  const char *err = NULL;
  got[0] = '\0';
  if (cmdline_parse(work, argv, 8, &r, &err) < 0 ||
      cmdline_route(&r, fds, &err) < 0) {
    snprintf(got, sizeof(got), "error: %s", err ? err : "(null)");
  } else {
    for (int fd = 0; fd <= 2; fd++) {
      char buf[16];
      snprintf(buf, sizeof(buf), "%s%d:", fd ? " " : "", fd);
      put(got, sizeof(got), buf);
      if (fds[fd].file >= 0) {
        put(got, sizeof(got), r.op[fds[fd].file].path);
      } else if (fds[fd].orig >= 0) {
        snprintf(buf, sizeof(buf), "&%d", fds[fd].orig);
        put(got, sizeof(got), buf);
      } else {
        put(got, sizeof(got), "-");
      }
    }
  }
  cases++;
  if (strcmp(got, want) != 0) {
    printf("FAIL: route %s\n  got:  %s\n  want: %s\n", in, got, want);
    fails++;
  }
}

int main(void) {
  /* plain words, as before quoting */
  check("", "");
  check("   \t ", "");
  check("ls", "[ls]");
  check("  ls   -l\t/data  ", "[ls][-l][/data]");

  /* double quotes */
  check("cd \"my dir\"", "[cd][my dir]");
  check("echo \"a  b\"", "[echo][a  b]");
  check("echo \"it's\"", "[echo][it's]");
  check("echo \"a\\\"b\"", "[echo][a\"b]");
  check("echo \"a\\\\b\"", "[echo][a\\b]");
  check("echo \"a\\$b\"", "[echo][a$b]");
  check("echo \"a\\nb\"", "[echo][a\\nb]"); /* other escapes stay literal */

  /* single quotes: no escapes inside */
  check("echo 'my dir'", "[echo][my dir]");
  check("echo 'say \"hi\"'", "[echo][say \"hi\"]");
  check("echo 'a\\b'", "[echo][a\\b]");

  /* backslash outside quotes */
  check("echo a\\ b", "[echo][a b]");
  check("echo \\\"x\\\"", "[echo][\"x\"]");
  check("echo \\'", "[echo][']");
  check("echo a\\\\b", "[echo][a\\b]");
  check("echo a\\", "[echo][a\\]"); /* trailing backslash is literal */

  /* adjacent pieces join; empty quotes are an empty word */
  check("echo \"a\"'b'c", "[echo][abc]");
  check("echo pre\"mid dle\"post", "[echo][premid dlepost]");
  check("echo \"\" ''", "[echo][][]");

  /* output redirection */
  check("echo \"a b\" > f", "[echo][a b] >f");
  check("echo hi >f", "[echo][hi] >f");
  check("echo hi>f", "[echo][hi] >f");
  check("echo hi >> log", "[echo][hi] >>log");
  check("echo hi>>log", "[echo][hi] >>log");
  check("echo hi > \"out file\"", "[echo][hi] >out file");
  check("echo hi > a > b", "[echo][hi] >a >b"); /* both opened; b wins */
  check("> f", " >f");

  /* input redirection */
  check("cat < \"my file\"", "[cat] <my file");
  check("cat <f", "[cat] <f");
  check("grep x < in > out", "[grep][x] <in >out");

  /* quoted or escaped operators are literal */
  check("echo \">\" f", "[echo][>][f]");
  check("echo '>>' '<'", "[echo][>>][<]");
  check("echo a\\>b", "[echo][a>b]");
  check("echo \"a>b\"", "[echo][a>b]");

  /* pipes */
  check("ps | grep zsshd", "[ps] | [grep][zsshd]");
  check("echo 'x|y' | grep x", "[echo][x|y] | [grep][x]");
  check("echo \"x|y\"", "[echo][x|y]");
  check("echo x\\|y", "[echo][x|y]");
  check("cat < in | grep \"a b\" > out", "[cat] <in | [grep][a b] >out");

  /* ';' and newline */
  check("cd /data; ls", "[cd][/data] ; [ls]");
  check("echo 'a;b'; echo c", "[echo][a;b] ; [echo][c]");
  check("echo a\\;b", "[echo][a;b]");
  check("echo \"a\nb\"", "[echo][a\nb]"); /* newline inside quotes */
  check("echo a\necho b", "[echo][a] ; [echo][b]");

  /* errors */
  check("echo \"abc", "error: syntax error: unterminated quote");
  check("echo 'abc", "error: syntax error: unterminated quote");
  check("echo 'a|b", "error: syntax error: unterminated quote");
  check("echo 'a;b", "error: syntax error: unterminated quote");
  check("echo \"a\\\"", "error: syntax error: unterminated quote");
  check("cat < \"f", "error: syntax error: unterminated quote");
  check("echo hi >", NOFILE);
  check("echo hi > ", NOFILE);
  check("echo hi > \"\"", NOFILE);
  check("echo hi > < f", NOFILE);
  check("cat <", NOFILE);
  check("echo hi 2>", NOFILE);
  check("echo hi 2>&", BADFD);
  check("echo hi 2>&x", BADFD);
  check("echo hi 2>&12", BADFD);
  check("echo hi >&-", BADFD);
  check("echo hi 12>f", BADFD);
  check("a 1>a 2>b 3>c 4>d 5>e 6>f 7>g 8>h 9>i",
        "error: syntax error: too many redirections");

  /* descriptor redirection: N>f, N>>f, N<f, N>&M */
  check("echo hi 2>err", "[echo][hi] 2>err");
  check("echo hi 2> err", "[echo][hi] 2>err");
  check("echo hi 2>>log", "[echo][hi] 2>>log");
  check("echo hi 2>\"my err\"", "[echo][hi] 2>my err");
  check("echo hi 1>f", "[echo][hi] >f");
  check("echo hi 1>>f", "[echo][hi] >>f");
  check("cat 0<f", "[cat] <f");
  check("cat 3<f", "[cat] 3<f");
  check("echo 2>f hi", "[echo][hi] 2>f");
  check("echo hi 2>&1", "[echo][hi] 2>&1");
  check("echo hi 2>& 1", "[echo][hi] 2>&1");
  check("echo hi 2>&\"1\"", "[echo][hi] 2>&1");
  check("echo hi >&2", "[echo][hi] 1>&2");
  check("cat <&3", "[cat] 0>&3");
  check("ls x >f 2>&1", "[ls][x] >f 2>&1");
  check("ls x 2>&1 >f", "[ls][x] 2>&1 >f");
  check("ls x 2>&1>f", "[ls][x] 2>&1 >f");
  check("ls x 2>e>f", "[ls][x] 2>e >f");
  check("ls x 2>&1 | grep x", "[ls][x] 2>&1 | [grep][x]");
  check("ls x 2>err | wc", "[ls][x] 2>err | [wc]");
  check("ls x 2>>err | wc > out", "[ls][x] 2>>err | [wc] >out");
  /* not a descriptor: quoted, escaped, not all digits, or not glued */
  check("echo hi '2'>f", "[echo][hi][2] >f");
  check("echo hi \"2\">f", "[echo][hi][2] >f");
  check("echo hi \\2>f", "[echo][hi][2] >f");
  check("echo hi 2 >f", "[echo][hi][2] >f");
  check("echo hi a2>f", "[echo][hi][a2] >f");
  check("echo hi 2a>f", "[echo][hi][2a] >f");
  check("echo '2>f'", "[echo][2>f]");

  /* where each descriptor ends up, applied left to right as in sh */
  checkr("ls", "0:&0 1:&1 2:&2");
  checkr("ls >f", "0:&0 1:f 2:&2");
  checkr("ls 2>err", "0:&0 1:&1 2:err");
  checkr("ls 2>>err", "0:&0 1:&1 2:err");
  checkr("cat <in", "0:in 1:&1 2:&2");
  checkr("ls >f 2>&1", "0:&0 1:f 2:f");
  checkr("ls 2>&1 >f", "0:&0 1:f 2:&1");
  checkr("ls 2>&1", "0:&0 1:&1 2:&1");
  checkr("ls >&2", "0:&0 1:&2 2:&2");
  checkr("ls 2>e >f", "0:&0 1:f 2:e");
  checkr("ls 2>e 2>&1", "0:&0 1:&1 2:&1");
  checkr("ls > a > b", "0:&0 1:b 2:&2");
  checkr("ls 2>&1 1>&2", "0:&0 1:&1 2:&1");
  checkr("ls 3>f 1>&3", "0:&0 1:f 2:&2");
  checkr("ls 3>f 2>&3 3>g", "0:&0 1:&1 2:f");
  checkr("ls 1>&5", "error: redirection: bad file descriptor");
  checkr("ls 2>&2", "0:&0 1:&1 2:&2");

  /* words beyond max are dropped; redirections after them still apply */
  checkm("a b c d e", 3, "[a][b][c]");
  checkm("a b c d > f", 2, "[a][b] >f");

  if (fails) {
    printf("cmdline: %d of %d cases FAILED\n", fails, cases);
    return 1;
  }
  printf("cmdline: all %d cases passed\n", cases);
  return 0;
}
