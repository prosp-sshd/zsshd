#ifndef ZSSHD_TIMEUTIL_H
#define ZSSHD_TIMEUTIL_H

#include <stddef.h>
#include <time.h>

/* Pure helpers for the `uptime` and `date` builtins (no I/O, no PS5 calls), split
 * out so they can be unit-tested on the host, where shell.c does not build. */

/* Format an elapsed time in seconds into buf (size n, truncated if too small):
 *   under an hour : "up 12 min"
 *   under a day   : "up 4:12"          (hours:minutes)
 *   one day       : "up 1 day, 0:05"
 *   several days  : "up 3 days, 4:12"
 * A negative value is treated as 0. */
void uptime_format(long long seconds, char *buf, size_t n);

enum uptime_mode {
  UPTIME_MODE_UPTIME,  /* no args: print how long the console has been up */
  UPTIME_MODE_SINCE,   /* -s: print the boot time */
  UPTIME_MODE_VERBOSE, /* -v: print both time sources raw */
  UPTIME_MODE_USAGE,   /* anything else: print usage and fail */
};

/* Classify argv (argv[0] is the command name) for `uptime`. */
enum uptime_mode uptime_parse(int argc, char **argv);

enum date_mode {
  DATE_MODE_LOCAL, /* no args: local time */
  DATE_MODE_UTC,   /* -u: UTC */
  DATE_MODE_USAGE, /* anything else: print usage and fail */
};

/* Classify argv (argv[0] is the command name) for `date`. */
enum date_mode date_parse(int argc, char **argv);

/* Offset of local time from UTC, in seconds east (e.g. -25200 for UTC-7), for
 * the instant t, given local = localtime_r(t). Reads only the nine standard
 * struct tm fields (tm_year .. tm_sec), never tm_gmtoff or tm_zone: a libc may
 * leave those unset, as the PS5's does. */
long tm_utc_offset(const struct tm *local, long long t);

/* Format an offset in seconds east of UTC as "+HHMM" / "-HHMM" into buf. */
void utc_offset_format(long offset, char *buf, size_t n);

#endif /* ZSSHD_TIMEUTIL_H */
