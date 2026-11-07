#!/bin/sh
# Host test for the df/du size-formatting helpers (src/app/diskfmt.c). They are
# pure (no I/O, no PS5 calls), so they build and run on the host. Needs only a
# C compiler.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cc -Wall -Werror -I"$root/include" -o "$W/diskfmt-test" \
  "$here/diskfmt_test.c" "$root/src/app/diskfmt.c"
"$W/diskfmt-test"
