#ifndef ZSSHD_CMDLINE_H
#define ZSSHD_CMDLINE_H

/* Command-line splitting with shell quoting. Pure string code (no I/O, no PS5
 * calls), so it also builds and is unit-tested on the host.
 *
 * Quoting rules (a subset of POSIX sh):
 *   '...'  everything up to the next ' is literal (no escapes inside).
 *   "..."  literal, except \" \\ \$ \` which give the second character.
 *   \c     outside quotes: the character c, literally (\  is a space that
 *          does not split, \| \; \> are not operators). A trailing \ at the
 *          end of the line is kept as a literal backslash.
 * Quoted and unquoted text that touch form one word ("a"'b'c -> abc), and ""
 * or '' alone is an empty word. Quote characters themselves are removed. */

/* Return a pointer to the first character of `s` that is in `seps` and is not
 * inside quotes or escaped by a backslash, or to the terminating NUL if there
 * is none. Used to cut a line at ';' / newline and a command at '|'. An
 * unterminated quote runs to the end of the string (cmdline_parse() then
 * reports it). */
char *cmdline_find_sep(char *s, const char *seps);

/* One redirection, in the order written. `fd` is the descriptor it changes
 * (0 for '<', 1 for '>' unless a number is given, as in "2>f"). */
enum cmdline_redir_kind {
  CMDLINE_IN,     /* N<file   (N defaults to 0) */
  CMDLINE_OUT,    /* N>file   (N defaults to 1) */
  CMDLINE_APPEND, /* N>>file  (N defaults to 1) */
  CMDLINE_DUP,    /* N>&M or N<&M: N becomes a copy of M */
  CMDLINE_CLOSE,  /* N>&- or N<&-: N is closed */
  CMDLINE_RW      /* N<>file  (N defaults to 0; created if missing) */
};

#define CMDLINE_MAX_REDIR 8 /* redirections per command */
#define CMDLINE_NFD 10      /* descriptors 0-9 may be named */

struct cmdline_redir_op {
  enum cmdline_redir_kind kind;
  int fd;
  const char *path; /* the file (points into the line); NULL for a dup or close */
  int dup_fd;       /* M for CMDLINE_DUP */
};

struct cmdline_redir {
  int n;
  struct cmdline_redir_op op[CMDLINE_MAX_REDIR];
};

/* Split one command (no unquoted '|' or ';') into words, removing quotes and
 * escapes, and strip its redirections into *r in the order written:
 *   [N]<file  [N]>file  [N]>>file  [N]<>file  [N]>&M  [N]<&M  [N]>&-  [N]<&-
 * An unquoted '>' or '<' is an operator wherever it appears ("a>f", "a >f"
 * and "a > f" are the same); a quoted or escaped one is a literal part of a
 * word. The file name is the next word and may be quoted. N is a single digit
 * glued to the operator ("2>f"; "2 >f" passes "2" as an argument and "'2'>f"
 * too, as in sh); M is a single digit, glued or not ("2>&1", "2>& 1").
 *
 * `line` is modified in place (words are compacted and NUL-terminated);
 * argv[i] and the paths point into it. At most `max` words are stored; any
 * beyond are dropped. Returns the word count (0 is allowed: an empty line, or
 * "> f" alone), or -1 with *err set to a static message: an unterminated
 * quote, an operator with no file name, a descriptor number that is not a
 * single digit or "-", an '&' after ">>" or "<>", or more than
 * CMDLINE_MAX_REDIR redirections. */
int cmdline_parse(char *line, char **argv, int max, struct cmdline_redir *r,
                  const char **err);

/* Where one descriptor ends up once a command's redirections are applied:
 * the file opened by r->op[file], or (file < 0) the descriptor `orig` that
 * the command started with (0-2), or nothing: closed (file < 0 and orig < 0). */
struct cmdline_fd {
  int file;
  int orig;
};

/* Apply r's redirections left to right, as sh does, to a table in which
 * descriptors 0-2 start as themselves and 3-9 start closed, and store the
 * result for every descriptor in fds[0..CMDLINE_NFD-1]. So ">f 2>&1" sends
 * both 1 and 2 to f, while "2>&1 >f" sends 2 to the original 1 and 1 to f.
 * ">&-" leaves its descriptor closed. Returns 0, or -1 with *err set when a
 * dup names a closed descriptor ("1>&5" with no "5>..." before it, or
 * "1>&- 2>&1"). */
int cmdline_route(const struct cmdline_redir *r, struct cmdline_fd *fds,
                  const char **err);

#endif /* ZSSHD_CMDLINE_H */
