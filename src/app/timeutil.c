#include "timeutil.h"

#include <stdio.h>
#include <string.h>

void uptime_format(long long seconds, char *buf, size_t n) {
  if (n == 0) {
    return;
  }
  if (seconds < 0) {
    seconds = 0;
  }
  long long mins = seconds / 60;
  long long days = mins / (24 * 60);
  long long hours = (mins / 60) % 24;
  long long rem = mins % 60;

  if (days > 0) {
    snprintf(buf, n, "up %lld day%s, %lld:%02lld", days, days == 1 ? "" : "s",
             hours, rem);
  } else if (hours > 0) {
    snprintf(buf, n, "up %lld:%02lld", hours, rem);
  } else {
    snprintf(buf, n, "up %lld min", rem);
  }
}

enum uptime_mode uptime_parse(int argc, char **argv) {
  if (argc <= 1) {
    return UPTIME_MODE_UPTIME;
  }
  if (argc == 2 && argv[1] != NULL) {
    if (strcmp(argv[1], "-s") == 0) {
      return UPTIME_MODE_SINCE;
    }
    if (strcmp(argv[1], "-v") == 0) {
      return UPTIME_MODE_VERBOSE;
    }
  }
  return UPTIME_MODE_USAGE;
}

enum date_mode date_parse(int argc, char **argv) {
  if (argc <= 1) {
    return DATE_MODE_LOCAL;
  }
  if (argc == 2 && argv[1] != NULL && strcmp(argv[1], "-u") == 0) {
    return DATE_MODE_UTC;
  }
  return DATE_MODE_USAGE;
}

/* Days from 1970-01-01 to the given civil date (proleptic Gregorian),
 * Howard Hinnant's days_from_civil. */
static long long days_from_civil(long long y, unsigned m, unsigned d) {
  y -= m <= 2;
  long long era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400);
  unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + (long long)doe - 719468;
}

long tm_utc_offset(const struct tm *local, long long t) {
  long long days = days_from_civil((long long)local->tm_year + 1900,
                                   (unsigned)local->tm_mon + 1,
                                   (unsigned)local->tm_mday);
  long long as_utc = days * 86400 + local->tm_hour * 3600LL +
                     local->tm_min * 60LL + local->tm_sec;
  return (long)(as_utc - t);
}

void utc_offset_format(long offset, char *buf, size_t n) {
  if (n == 0) return;
  char sign = offset < 0 ? '-' : '+';
  long a = offset < 0 ? -offset : offset;
  long mins = (a + 30) / 60; /* round to the minute */
  snprintf(buf, n, "%c%02ld%02ld", sign, mins / 60, mins % 60);
}
