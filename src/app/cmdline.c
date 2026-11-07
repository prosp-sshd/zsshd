#include "cmdline.h"

#include <stddef.h>
#include <string.h>

static int is_blank(char c) { return c == ' ' || c == '\t'; }

static int is_redir(char c) { return c == '<' || c == '>'; }

static int is_number(const char *s) {
  if (*s == '\0') {
    return 0;
  }
  for (; *s; s++) {
    if (*s < '0' || *s > '9') {
      return 0;
    }
  }
  return 1;
}

/* Characters a backslash escapes inside double quotes (POSIX). */
static int dq_escapable(char c) {
  return c == '"' || c == '\\' || c == '$' || c == '`';
}

char *cmdline_find_sep(char *s, const char *seps) {
  char quote = '\0';
  for (; *s; s++) {
    if (quote == '\'') {
      if (*s == '\'') {
        quote = '\0';
      }
    } else if (quote == '"') {
      if (*s == '\\' && s[1] != '\0') {
        s++;
      } else if (*s == '"') {
        quote = '\0';
      }
    } else if (*s == '\\') {
      if (s[1] != '\0') {
        s++;
      }
    } else if (*s == '\'' || *s == '"') {
      quote = *s;
    } else if (strchr(seps, *s)) {
      return s;
    }
  }
  return s;
}

/* In-place word scanner. Words are compacted towards the start of the line
 * (w never passes r). A word ends at an unquoted blank, '<', '>' or the end
 * of the line. The delimiter is consumed (the word's NUL may land on it), so
 * an operator delimiter is remembered in `pend` for the caller. */
struct scan {
  char *r;
  char *w;
  char pend; /* operator that ended the last word, or 0 */
};

/* Read one word at s->r. Returns its start, or NULL on an unterminated
 * quote. *quoted is set if any quote or escape was seen. */
static char *scan_word(struct scan *s, int *quoted, const char **err) {
  char *word = s->w;
  char quote = '\0';
  *quoted = 0;
  while (*s->r != '\0') {
    char c = *s->r;
    if (quote == '\'') {
      if (c == '\'') {
        quote = '\0';
      } else {
        *s->w++ = c;
      }
    } else if (quote == '"') {
      if (c == '"') {
        quote = '\0';
      } else if (c == '\\' && dq_escapable(s->r[1])) {
        *s->w++ = *++s->r;
      } else {
        *s->w++ = c;
      }
    } else if (c == '\\') {
      if (s->r[1] != '\0') {
        *s->w++ = *++s->r;
        *quoted = 1;
      } else {
        *s->w++ = c; /* trailing backslash: literal */
      }
    } else if (c == '\'' || c == '"') {
      quote = c;
      *quoted = 1;
    } else if (is_blank(c) || is_redir(c)) {
      break;
    } else {
      *s->w++ = c;
    }
    s->r++;
  }
  if (quote != '\0') {
    *err = "syntax error: unterminated quote";
    return NULL;
  }
  char d = *s->r;
  if (d != '\0') {
    s->r++; /* step past the delimiter before the NUL may overwrite it */
  }
  *s->w++ = '\0';
  s->pend = is_redir(d) ? d : '\0';
  return word;
}

int cmdline_parse(char *line, char **argv, int max, struct cmdline_redir *r,
                  const char **err) {
  struct scan s = {line, line, '\0'};
  int argc = 0;
  r->out_path = NULL;
  r->append = 0;
  r->in_path = NULL;
  for (;;) {
    char op = s.pend;
    s.pend = '\0';
    if (op == '\0') {
      while (is_blank(*s.r)) {
        s.r++;
      }
      if (*s.r == '\0') {
        break;
      }
      if (is_redir(*s.r)) {
        op = *s.r++;
      }
    }
    int quoted;
    if (op != '\0') {
      int append = 0;
      if (op == '>' && *s.r == '>') {
        append = 1;
        s.r++;
      }
      while (is_blank(*s.r)) {
        s.r++;
      }
      if (*s.r == '\0' || is_redir(*s.r)) {
        *err = "syntax error: expected filename after redirection";
        return -1;
      }
      char *path = scan_word(&s, &quoted, err);
      if (path == NULL) {
        return -1;
      }
      if (*path == '\0') {
        *err = "syntax error: expected filename after redirection";
        return -1;
      }
      if (op == '<') {
        r->in_path = path;
      } else {
        r->out_path = path;
        r->append = append;
      }
      continue;
    }
    char *word = scan_word(&s, &quoted, err);
    if (word == NULL) {
      return -1;
    }
    /* "2>f": an unquoted all-digit word glued to an operator names a file
     * descriptor in a full shell. Not supported; refuse rather than silently
     * pass "2" as an argument. */
    if (!quoted && s.pend != '\0' && is_number(word)) {
      *err = "syntax error: file descriptor redirection is not supported";
      return -1;
    }
    if (argc < max) {
      argv[argc++] = word;
    }
  }
  return argc;
}
