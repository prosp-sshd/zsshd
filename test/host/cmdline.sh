#!/bin/sh
# Host unit test for src/app/cmdline.c, the shell's quote-aware command-line
# splitter. Pure string code (no I/O, no PS5 calls), so it builds and runs on
# the host with any C compiler: sh test/host/cmdline.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cc -Wall -Wextra -Werror -I"$root/include" -o "$W/cmdline-test" \
  "$here/cmdline_test.c" "$root/src/app/cmdline.c"
"$W/cmdline-test"
