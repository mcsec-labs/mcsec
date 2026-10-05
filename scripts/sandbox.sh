#!/bin/sh
# Shared runtime restrictions for the scan and test containers. Sourced by
# scan-sandboxed.sh and test-sandboxed.sh.
#
# - No network, so nothing in a jar can reach out
# - Read-only root, with a small scratch space that cannot hold executables
# - Unprivileged user, every capability dropped, no privilege escalation
# - Memory, process, and CPU caps, so a zip bomb or a hang only kills the container
SANDBOX_FLAGS="--rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges
    --memory 2g --memory-swap 2g --pids-limit 64 --cpus 1"

# Git Bash on Windows rewrites arguments that look like Unix paths, which
# would break paths inside the container, and Docker Desktop needs Windows
# paths for mounts.
export MSYS_NO_PATHCONV=1
host_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        printf '%s\n' "$1"
    fi
}

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
