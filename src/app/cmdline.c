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

#define NO_FILE "syntax error: expected filename after redirection"
#define BAD_FD "syntax error: bad file descriptor number"

/* The single-digit descriptor in `w`, or -1. */
static int fd_number(const char *w) {
  return is_number(w) && w[1] == '\0' ? w[0] - '0' : -1;
}

/* Read the rest of a redirection whose operator character `op` ('<' or '>')
 * was just consumed: an optional second '>' or '&', then the file name or
 * descriptor. `fd` is the number glued before the operator, or -1. */
static int scan_redir(struct scan *s, char op, int fd, struct cmdline_redir *r,
                      const char **err) {
  struct cmdline_redir_op o;
  o.kind = op == '<' ? CMDLINE_IN : CMDLINE_OUT;
  o.fd = fd >= 0 ? fd : (op == '<' ? 0 : 1);
  o.path = NULL;
  o.dup_fd = -1;
  if (op == '>' && *s->r == '>') {
    o.kind = CMDLINE_APPEND;
    s->r++;
  } else if (*s->r == '&') {
    o.kind = CMDLINE_DUP;
    s->r++;
  }
  while (is_blank(*s->r)) {
    s->r++;
  }
  if (*s->r == '\0' || is_redir(*s->r)) {
    *err = o.kind == CMDLINE_DUP ? BAD_FD : NO_FILE;
    return -1;
  }
  int quoted;
  char *word = scan_word(s, &quoted, err);
  if (word == NULL) {
    return -1;
  }
  if (o.kind == CMDLINE_DUP) {
    o.dup_fd = fd_number(word);
    if (o.dup_fd < 0) {
      *err = BAD_FD;
      return -1;
    }
  } else if (*word == '\0') {
    *err = NO_FILE;
    return -1;
  } else {
    o.path = word;
  }
  if (r->n >= CMDLINE_MAX_REDIR) {
    *err = "syntax error: too many redirections";
    return -1;
  }
  r->op[r->n++] = o;
  return 0;
}

int cmdline_parse(char *line, char **argv, int max, struct cmdline_redir *r,
                  const char **err) {
  struct scan s = {line, line, '\0'};
  int argc = 0;
  int fd = -1; /* descriptor number glued to the pending operator */
  r->n = 0;
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
    if (op != '\0') {
      if (scan_redir(&s, op, fd, r, err) != 0) {
        return -1;
      }
      fd = -1;
      continue;
    }
    int quoted;
    char *word = scan_word(&s, &quoted, err);
    if (word == NULL) {
      return -1;
    }
    /* "2>f": an unquoted all-digit word glued to an operator names the
     * descriptor the operator redirects. */
    if (!quoted && s.pend != '\0' && is_number(word)) {
      fd = fd_number(word);
      if (fd < 0) {
        *err = BAD_FD;
        return -1;
      }
      s.w = word; /* not a word: drop it from the compacted line */
      continue;
    }
    if (argc < max) {
      argv[argc++] = word;
    }
  }
  return argc;
}

int cmdline_route(const struct cmdline_redir *r, struct cmdline_fd *fds,
                  const char **err) {
  for (int i = 0; i < CMDLINE_NFD; i++) {
    fds[i].file = -1;
    fds[i].orig = i <= 2 ? i : -1;
  }
  for (int i = 0; i < r->n; i++) {
    const struct cmdline_redir_op *o = &r->op[i];
    if (o->kind == CMDLINE_DUP) {
      struct cmdline_fd src = fds[o->dup_fd];
      if (src.file < 0 && src.orig < 0) {
        *err = "redirection: bad file descriptor";
        return -1;
      }
      fds[o->fd] = src;
    } else {
      fds[o->fd].file = i;
      fds[o->fd].orig = -1;
    }
  }
  return 0;
}
