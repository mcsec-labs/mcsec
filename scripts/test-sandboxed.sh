#!/bin/sh
# Runs every test suite, the ground truth corpus included, inside the test
# container with the same restrictions as a scan.
#
# Usage: scripts/test-sandboxed.sh [test binary options]
#
# Download the corpus first with scripts/fetch-corpus.py and compile the
# variants with scripts/build-variants.py. Both are mounted read-only.
set -eu
. "$(dirname "$0")/sandbox.sh"

docker build --quiet --tag mcsec-test \
    --file "$(host_path "$REPO_ROOT/docker/test.Dockerfile")" "$(host_path "$REPO_ROOT")" >/dev/null

# shellcheck disable=SC2086
exec docker run $SANDBOX_FLAGS \
    --mount "type=bind,src=$(host_path "$REPO_ROOT/corpus/cache"),dst=/src/corpus/cache,readonly" \
    --mount "type=bind,src=$(host_path "$REPO_ROOT/corpus/variants/build"),dst=/src/corpus/variants/build,readonly" \
    mcsec-test "$@"
