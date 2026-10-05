#!/bin/sh
# Runs every compiled test binary, including tests ignored by default such as
# the corpus test. Fails if any binary fails.
set -u

status=0
for binary in /tests/*; do
    echo "== $(basename "$binary")"
    "$binary" --include-ignored "$@" || status=1
done
exit "$status"
