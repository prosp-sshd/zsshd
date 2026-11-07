#!/bin/sh
# Host test for the `uptime` / `date` builtins' pure helpers (src/app/timeutil.c):
# uptime_format() and the flag parsers do no I/O and make no PS5 calls, so they
# build and run on the host even though shell.c does not. Needs only a C compiler.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cc -Wall -Werror -I"$root/include" -o "$W/timeutil-test" \
  "$here/timeutil_test.c" "$root/src/app/timeutil.c"
"$W/timeutil-test"
