#!/bin/sh
# Runs every test suite, the ground truth corpus included, inside the test
# container with the same restrictions as a scan.
#
# Usage: scripts/test-sandboxed.sh [test binary options]
#
# Download the corpus first with scripts/fetch-corpus.py, the benchmark with
# scripts/fetch-corpus.py benchmark/manifest.json, and compile the variants
# with scripts/build-variants.py. All of them are mounted read-only. Set
# MCSEC_BENCHMARK_EXTENDED=1 to also run the extended benchmark tier, after
# downloading it with scripts/fetch-corpus.py benchmark/extended/manifest.json.
set -eu
. "$(dirname "$0")/sandbox.sh"

docker build --quiet --tag mcsec-test \
    --file "$(host_path "$REPO_ROOT/docker/test.Dockerfile")" "$(host_path "$REPO_ROOT")" >/dev/null

# Bind mounts need their source folders, which an unfetched cache lacks.
mkdir -p "$REPO_ROOT/corpus/cache" "$REPO_ROOT/corpus/variants/build" \
    "$REPO_ROOT/benchmark/cache" "$REPO_ROOT/benchmark/extended/cache"

extended=""
if [ -n "${MCSEC_BENCHMARK_EXTENDED:-}" ]; then
    extended="--env MCSEC_BENCHMARK_EXTENDED=1"
fi

# shellcheck disable=SC2086
exec docker run $SANDBOX_FLAGS $extended \
    --mount "type=bind,src=$(host_path "$REPO_ROOT/corpus/cache"),dst=/src/corpus/cache,readonly" \
    --mount "type=bind,src=$(host_path "$REPO_ROOT/corpus/variants/build"),dst=/src/corpus/variants/build,readonly" \
    --mount "type=bind,src=$(host_path "$REPO_ROOT/benchmark/cache"),dst=/src/benchmark/cache,readonly" \
    --mount "type=bind,src=$(host_path "$REPO_ROOT/benchmark/extended/cache"),dst=/src/benchmark/extended/cache,readonly" \
    mcsec-test "$@"
