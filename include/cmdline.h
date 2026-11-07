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

/* Redirections found by cmdline_parse(). Paths point into its line; NULL
 * when absent. */
struct cmdline_redir {
  const char *out_path; /* "> file" or ">> file" */
  int append;           /* 1 for ">>", 0 for ">" */
  const char *in_path;  /* "< file" */
};

/* Split one command (no unquoted '|' or ';') into words, removing quotes and
 * escapes, and strip the redirections "> file", ">> file" and "< file" into
 * *r. An unquoted '>' or '<' is an operator wherever it appears ("a>f",
 * "a >f" and "a > f" are the same); a quoted or escaped one is a literal part
 * of a word. The file name is the next word and may be quoted. If an operator
 * repeats, the last one wins.
 *
 * `line` is modified in place (words are compacted and NUL-terminated);
 * argv[i] points into it. At most `max` words are stored; any beyond are
 * dropped. Returns the word count (0 is allowed: an empty line, or "> f"
 * alone), or -1 with *err set to a static message: an unterminated quote, an
 * operator with no file name, or a file-descriptor form such as "2>f" (an
 * unquoted all-digit word glued to an operator), which is not supported. */
int cmdline_parse(char *line, char **argv, int max, struct cmdline_redir *r,
                  const char **err);

#endif /* ZSSHD_CMDLINE_H */
