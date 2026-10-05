#!/bin/sh
# Scans one jar inside the scan container and prints the JSON report.
#
# Usage: scripts/scan-sandboxed.sh <jar> [mcsec scan options]
#
# The jar's folder is mounted read-only. The image is rebuilt from the
# current source first, which takes a moment only when the source changed.
set -eu
. "$(dirname "$0")/sandbox.sh"

if [ $# -lt 1 ]; then
    echo "usage: $0 <jar> [mcsec scan options]" >&2
    exit 2
fi
jar=$1
shift
folder=$(cd "$(dirname "$jar")" && pwd)
name=$(basename "$jar")

docker build --quiet --tag mcsec-scan \
    --file "$(host_path "$REPO_ROOT/docker/scan.Dockerfile")" "$(host_path "$REPO_ROOT")" >/dev/null

# shellcheck disable=SC2086
exec docker run $SANDBOX_FLAGS \
    --mount "type=bind,src=$(host_path "$folder"),dst=/input,readonly" \
    mcsec-scan scan "/input/$name" "$@"
