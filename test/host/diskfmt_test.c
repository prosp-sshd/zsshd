#include "diskfmt.h"

#include <stdio.h>
#include <string.h>

static int fails = 0;
static int cases = 0;

static void human(uint64_t v, const char *want) {
  char b[32];
  diskfmt_human(v, b, sizeof(b));
  cases++;
  if (strcmp(b, want) != 0) {
    printf("FAIL: human(%llu): got '%s', want '%s'\n", (unsigned long long)v, b,
           want);
    fails++;
  }
}

static void ieq(const char *name, long long got, long long want) {
  cases++;
  if (got != want) {
    printf("FAIL: %s: got %lld, want %lld\n", name, got, want);
    fails++;
  }
}

static void seq(const char *name, const char *got, const char *want) {
  cases++;
  if (strcmp(got, want) != 0) {
    printf("FAIL: %s:\n  got  '%s'\n  want '%s'\n", name, got, want);
    fails++;
  }
}

int main(void) {
  human(0, "0");
  human(1, "1");
  human(512, "512");
  human(1023, "1023");
  human(1024, "1.0K");
  human(1025, "1.1K");
  human(1536, "1.5K");
  human(10239, "10K");
  human(10240, "10K");
  human(23ULL << 20, "23M");
  human((1ULL << 20) - 1, "1.0M");
  human(1ULL << 20, "1.0M");
  human(1288490189ULL, "1.3G"); /* just over 1.2 GiB, rounds up */
  human(1ULL << 30, "1.0G");
  human(3ULL * (1ULL << 40) + (1ULL << 40) * 4 / 10, "3.4T");
  human(1ULL << 50, "1.0P");
  human(1ULL << 60, "1.0E");
  human(UINT64_MAX, "16E");

  char small[4];
  diskfmt_human(1536, small, sizeof(small));
  ieq("truncate len", (long long)strlen(small), 3);

  ieq("kblocks 0", (long long)diskfmt_kblocks(0, 4096), 0);
  ieq("kblocks 4096", (long long)diskfmt_kblocks(10, 4096), 40);
  ieq("kblocks 512", (long long)diskfmt_kblocks(10, 512), 5);
  ieq("kblocks 1024", (long long)diskfmt_kblocks(7, 1024), 7);
  ieq("kblocks 16K", (long long)diskfmt_kblocks(3, 16384), 48);
  ieq("kblocks sat", diskfmt_kblocks(UINT64_MAX, 4096) == UINT64_MAX, 1);

  ieq("pct 0/0", diskfmt_use_pct(0, 0), -1);
  ieq("pct 0 used", diskfmt_use_pct(0, 100), 0);
  ieq("pct full", diskfmt_use_pct(100, 0), 100);
  ieq("pct half", diskfmt_use_pct(50, 50), 50);
  ieq("pct round up", diskfmt_use_pct(1, 999), 1);
  ieq("pct 1/3", diskfmt_use_pct(1, 2), 34);
  ieq("pct huge", diskfmt_use_pct(UINT64_MAX / 2, UINT64_MAX / 2), 50);
  ieq("pct overflow total", diskfmt_use_pct(UINT64_MAX, 5), -1);

  ieq("sandbox mount", diskfmt_is_sandbox_mount("/mnt/sandbox/NPXS40087_000/app0"), 1);
  ieq("sandbox dir itself", diskfmt_is_sandbox_mount("/mnt/sandbox"), 0);
  ieq("sandbox lookalike", diskfmt_is_sandbox_mount("/mnt/sandboxed/x"), 0);
  ieq("not sandbox", diskfmt_is_sandbox_mount("/data"), 0);
  ieq("sandbox null", diskfmt_is_sandbox_mount(NULL), 0);

  char row[256];
  diskfmt_df_header(row, sizeof(row), 10);
  seq("df header", row,
      "Filesystem       Size       Used      Avail  Use% Mounted on");
  diskfmt_df_row(row, sizeof(row), 10, "/dev/ssd0", "/data", 100, 40, 60, 4096,
                 0);
  seq("df row 1K", row, "/dev/ssd0         400        240        240   50% /data");
  diskfmt_df_row(row, sizeof(row), 10, "/dev/ssd0", "/user", 1000000, 1000,
                 500, 4096, 1);
  seq("df row -h", row, "/dev/ssd0        3.9G       3.9G       2.0M  100% /user");
  diskfmt_df_row(row, sizeof(row), 12, "/dev/lvd2", "/", 0, 0, 0, 4096, 0);
  seq("df row empty", row, "/dev/lvd2             0          0          0     - /");
  diskfmt_df_row(row, sizeof(row), 10, "x", "/y", 10, 0, -5, 1024, 0);
  seq("df row negative avail", row, "x                  10         10          0  100% /y");
  diskfmt_df_row(row, sizeof(row), 10, "/dev/ssd0", "/data", 100, 40, 60, 4096,
                 0);
  diskfmt_df_row(row, 8, 10, "/dev/ssd0", "/data", 100, 40, 60, 4096, 0);
  ieq("df row truncates", (long long)strlen(row), 7);

  if (fails == 0) {
    printf("PASS: diskfmt (%d cases)\n", cases);
    return 0;
  }
  printf("%d of %d cases failed\n", fails, cases);
  return 1;
}
