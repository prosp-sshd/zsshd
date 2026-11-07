#include "diskfmt.h"

#include <stdio.h>
#include <string.h>

void diskfmt_human(uint64_t bytes, char *buf, size_t buflen) {
  static const char units[] = "KMGTPE";
  if (buflen == 0) {
    return;
  }
  if (bytes < 1024) {
    snprintf(buf, buflen, "%llu", (unsigned long long)bytes);
    return;
  }
  int u = 1; /* unit is 1024^u */
  while (u < 6 && (bytes >> (10 * (u + 1))) != 0) {
    u++;
  }
  uint64_t unit = (uint64_t)1 << (10 * u);
  uint64_t q = bytes / unit;
  uint64_t rem = bytes % unit;
  /* value in tenths of the unit, rounded up (rem * 10 < 2^64 for u <= 6) */
  uint64_t tenths = q * 10 + (rem * 10 + unit - 1) / unit;
  if (tenths < 100) {
    snprintf(buf, buflen, "%llu.%llu%c", (unsigned long long)(tenths / 10),
             (unsigned long long)(tenths % 10), units[u - 1]);
    return;
  }
  uint64_t whole = q + (rem ? 1 : 0);
  if (whole >= 1024 && u < 6) {
    snprintf(buf, buflen, "1.0%c", units[u]);
    return;
  }
  snprintf(buf, buflen, "%llu%c", (unsigned long long)whole, units[u - 1]);
}

uint64_t diskfmt_kblocks(uint64_t blocks, uint64_t block_size) {
  if (block_size >= 1024) {
    uint64_t per = block_size / 1024;
    if (blocks != 0 && per > UINT64_MAX / blocks) {
      return UINT64_MAX;
    }
    return blocks * per;
  }
  if (blocks != 0 && block_size > UINT64_MAX / blocks) {
    return UINT64_MAX;
  }
  return blocks * block_size / 1024;
}

int diskfmt_use_pct(uint64_t used, uint64_t avail) {
  uint64_t total = used + avail;
  if (total == 0 || total < used) {
    return -1;
  }
  /* 128-bit intermediate: used * 100 can exceed 64 bits */
  unsigned __int128 n = (unsigned __int128)used * 100 + total - 1;
  return (int)(n / total);
}

int diskfmt_is_sandbox_mount(const char *mount_point) {
  static const char prefix[] = "/mnt/sandbox/";
  return mount_point != NULL &&
         strncmp(mount_point, prefix, sizeof(prefix) - 1) == 0;
}

static void df_fmt(char *out, size_t n, uint64_t kb, int human) {
  if (human) {
    diskfmt_human(kb > UINT64_MAX / 1024 ? UINT64_MAX : kb * 1024, out, n);
  } else {
    snprintf(out, n, "%llu", (unsigned long long)kb);
  }
}

void diskfmt_df_row(char *out, size_t n, int w, const char *from,
                    const char *on, uint64_t blocks, uint64_t bfree,
                    int64_t bavail, uint64_t bsize, int human) {
  uint64_t total = diskfmt_kblocks(blocks, bsize);
  uint64_t used = diskfmt_kblocks(blocks > bfree ? blocks - bfree : 0, bsize);
  uint64_t avail = diskfmt_kblocks(bavail > 0 ? (uint64_t)bavail : 0, bsize);
  char sz[32], us[32], av[32], pc[8];
  df_fmt(sz, sizeof(sz), total, human);
  df_fmt(us, sizeof(us), used, human);
  df_fmt(av, sizeof(av), avail, human);
  int pct = diskfmt_use_pct(used, avail);
  if (pct < 0) {
    snprintf(pc, sizeof(pc), "-");
  } else {
    snprintf(pc, sizeof(pc), "%d%%", pct);
  }
  snprintf(out, n, "%-*s %10s %10s %10s %5s %s", w, from, sz, us, av, pc, on);
}

void diskfmt_df_header(char *out, size_t n, int w) {
  snprintf(out, n, "%-*s %10s %10s %10s %5s %s", w, "Filesystem", "Size",
           "Used", "Avail", "Use%", "Mounted on");
}
