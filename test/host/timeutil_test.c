#include "timeutil.h"

#include <stdio.h>
#include <time.h>
#include <string.h>

static int fails = 0;
static int cases = 0;

static void fmt(const char *name, long long secs, const char *want) {
  char buf[64];
  cases++;
  uptime_format(secs, buf, sizeof(buf));
  if (strcmp(buf, want) != 0) {
    printf("FAIL: %s: got \"%s\", want \"%s\"\n", name, buf, want);
    fails++;
  }
}

static void up(const char *name, int argc, char **argv, enum uptime_mode want) {
  cases++;
  enum uptime_mode got = uptime_parse(argc, argv);
  if (got != want) {
    printf("FAIL: %s: got %d, want %d\n", name, (int)got, (int)want);
    fails++;
  }
}

static void dt(const char *name, int argc, char **argv, enum date_mode want) {
  cases++;
  enum date_mode got = date_parse(argc, argv);
  if (got != want) {
    printf("FAIL: %s: got %d, want %d\n", name, (int)got, (int)want);
    fails++;
  }
}

static void off(const char *name, int y, int mo, int d, int h, int mi, int s,
                long long t, long want) {
  struct tm tmv;
  memset(&tmv, 0, sizeof(tmv));
  tmv.tm_year = y; tmv.tm_mon = mo; tmv.tm_mday = d;
  tmv.tm_hour = h; tmv.tm_min = mi; tmv.tm_sec = s;
  long got = tm_utc_offset(&tmv, t);
  cases++;
  if (got != want) {
    printf("FAIL %s: tm_utc_offset = %ld, want %ld\n", name, got, want);
    fails++;
  }
}

static void offfmt(long offset, const char *want) {
  char buf[16];
  utc_offset_format(offset, buf, sizeof(buf));
  cases++;
  if (strcmp(buf, want) != 0) {
    printf("FAIL utc_offset_format(%ld) = '%s', want '%s'\n", offset, buf, want);
    fails++;
  }
}

int main(void) {
  fmt("0 s", 0, "up 0 min");
  fmt("59 s", 59, "up 0 min");
  fmt("60 s", 60, "up 1 min");
  fmt("12 min", 12 * 60 + 30, "up 12 min");
  fmt("59 min", 59 * 60 + 59, "up 59 min");
  fmt("1 h", 3600, "up 1:00");
  fmt("4h12", 4 * 3600 + 12 * 60, "up 4:12");
  fmt("23h59", 23 * 3600 + 59 * 60 + 59, "up 23:59");
  fmt("1 day", 86400, "up 1 day, 0:00");
  fmt("1 day 5 min", 86400 + 5 * 60, "up 1 day, 0:05");
  fmt("3 days", 3 * 86400 + 4 * 3600 + 12 * 60, "up 3 days, 4:12");
  fmt("100 days", 100LL * 86400, "up 100 days, 0:00");
  fmt("negative", -5, "up 0 min");
  {
    char tiny[8];
    cases++;
    uptime_format(3 * 86400, tiny, sizeof(tiny));
    if (strlen(tiny) != sizeof(tiny) - 1) {
      printf("FAIL: truncation: got \"%s\"\n", tiny);
      fails++;
    }
  }

  char *u_none[] = {"uptime"};
  char *u_s[] = {"uptime", "-s"};
  char *u_v[] = {"uptime", "-v"};
  char *u_bad[] = {"uptime", "-x"};
  char *u_long[] = {"uptime", "--since"};
  char *u_two[] = {"uptime", "-s", "-v"};
  char *u_word[] = {"uptime", "now"};
  up("uptime", 1, u_none, UPTIME_MODE_UPTIME);
  up("uptime -s", 2, u_s, UPTIME_MODE_SINCE);
  up("uptime -v", 2, u_v, UPTIME_MODE_VERBOSE);
  up("uptime -x", 2, u_bad, UPTIME_MODE_USAGE);
  up("uptime --since", 2, u_long, UPTIME_MODE_USAGE);
  up("uptime -s -v", 3, u_two, UPTIME_MODE_USAGE);
  up("uptime now", 2, u_word, UPTIME_MODE_USAGE);

  char *d_none[] = {"date"};
  char *d_u[] = {"date", "-u"};
  char *d_bad[] = {"date", "-x"};
  char *d_fmt[] = {"date", "+%s"};
  char *d_two[] = {"date", "-u", "-u"};
  dt("date", 1, d_none, DATE_MODE_LOCAL);
  dt("date -u", 2, d_u, DATE_MODE_UTC);
  dt("date -x", 2, d_bad, DATE_MODE_USAGE);
  dt("date +%s", 2, d_fmt, DATE_MODE_USAGE);
  dt("date -u -u", 3, d_two, DATE_MODE_USAGE);

  off("UTC", 126, 10, 1, 7, 37, 8, 1793518628LL, 0L);
  off("PDT across midnight", 126, 10, 1, 0, 37, 8, 1793518628LL, -25200L);
  off("IST +0530", 126, 10, 1, 13, 7, 8, 1793518628LL, 19800L);
  off("leap day UTC-0800", 100, 1, 28, 17, 0, 0, 951786000LL, -28800L);
  off("epoch", 70, 0, 1, 0, 0, 0, 0LL, 0L);
  off("NZDT +1300", 124, 0, 1, 13, 0, 0, 1704067200LL, 46800L);
  offfmt(0, "+0000");
  offfmt(-25200, "-0700");
  offfmt(19800, "+0530");
  offfmt(46800, "+1300");
  offfmt(-34200, "-0930");

  if (fails == 0) {
    printf("PASS: timeutil (%d cases)\n", cases);
    return 0;
  }
  return 1;
}
