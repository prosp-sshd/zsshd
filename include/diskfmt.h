#ifndef ZSSHD_DISKFMT_H
#define ZSSHD_DISKFMT_H

#include <stddef.h>
#include <stdint.h>

/* Pure size-formatting helpers for the `df` and `du` builtins, split out (no
 * I/O, no PS5 calls) so they can be unit-tested on the host. */

/* Format a byte count in `df -h` style: plain digits below 1024 ("512"), then
 * K/M/G/T/P/E with one decimal below 10 ("1.5K") and none from 10 up ("23M"),
 * always rounding up like BSD humanize. Writes a NUL-terminated string to buf
 * (at least 8 bytes recommended); truncates safely if buf is smaller. */
void diskfmt_human(uint64_t bytes, char *buf, size_t buflen);

/* Convert `blocks` units of `block_size` bytes to a count of 1K blocks,
 * rounding down, saturating at UINT64_MAX instead of overflowing. */
uint64_t diskfmt_kblocks(uint64_t blocks, uint64_t block_size);

/* `Use%` as df computes it: used / (used + avail) rounded up, as an integer
 * percentage. Returns -1 when used + avail is 0 or overflows (callers print
 * "-"). */
int diskfmt_use_pct(uint64_t used, uint64_t avail);

/* 1 if `mount_point` is a per-application sandbox mount (under
 * "/mnt/sandbox/"), which `df` hides unless `-a`: the console mounts a
 * hundred or more of them per running app, each repeating its source's sizes. */
int diskfmt_is_sandbox_mount(const char *mount_point);

/* Format one `df` row (no trailing newline) into out: from, the five size
 * columns, then on. `blocks`, `bfree`, `bavail` and `bsize` are the statfs
 * f_blocks, f_bfree, f_bavail and f_bsize fields (bavail may be negative when
 * root has used reserved space; it counts as 0). `human` selects -h units over
 * 1K blocks. `w` is the width of the Filesystem column. Truncates safely. */
void diskfmt_df_row(char *out, size_t n, int w, const char *from,
                    const char *on, uint64_t blocks, uint64_t bfree,
                    int64_t bavail, uint64_t bsize, int human);

/* The matching `df` header line (no trailing newline), same column width. */
void diskfmt_df_header(char *out, size_t n, int w);

#endif /* ZSSHD_DISKFMT_H */
