#include "cmdline.h"

#include <stdio.h>
#include <string.h>

#define NOFILE "error: syntax error: expected filename after redirection"

static int fails = 0;
static int cases = 0;

static void put(char *out, size_t cap, const char *s) {
  size_t n = strlen(out);
  snprintf(out + n, cap - n, "%s", s);
}

/* Run `in` through the same steps the shell takes (cut at ';' / newline, then
 * at '|', then cmdline_parse() on each command) and render the result: each
 * word as [word], then <in, >out or >>out; commands joined by " | " and
 * " ; ". An error renders as "error: <message>". */
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
      if (r.in_path) {
        put(out, cap, " <");
        put(out, cap, r.in_path);
      }
      if (r.out_path) {
        put(out, cap, r.append ? " >>" : " >");
        put(out, cap, r.out_path);
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
  check("echo hi > a > b", "[echo][hi] >b"); /* last one wins */
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
  check("echo hi 2>f",
        "error: syntax error: file descriptor redirection is not supported");
  check("echo hi '2'>f", "[echo][hi][2] >f");
  check("echo hi 2 >f", "[echo][hi][2] >f");
  check("echo hi 12>f",
        "error: syntax error: file descriptor redirection is not supported");
  check("cat 0<f",
        "error: syntax error: file descriptor redirection is not supported");
  check("echo hi a2>f", "[echo][hi][a2] >f");

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
