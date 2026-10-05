# Runs the test suites, ground truth corpus included, inside the same
# restrictions as the scan container. Tests are compiled at build time, the
# only step with network access, and the image keeps only the test binaries.
# Run it through scripts/test-sandboxed.sh.

# Base images are pinned by digest so a changed upstream image cannot slip
# into a build. To update, look up the new digest with
# `docker buildx imagetools inspect <image>` and replace it here.
FROM rust:1-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo test --release --locked --workspace --no-run --message-format=json \
        | grep -o '"executable":"[^"]*"' | cut -d '"' -f 4 > /tmp/test-binaries \
    && mkdir /tests \
    && xargs -I '{}' cp '{}' /tests/ < /tmp/test-binaries

FROM alpine:3@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
# The corpus test finds the manifest relative to the crate directory it was
# compiled in, so that path has to exist here too.
RUN mkdir -p /src/crates/mcsec-core /src/corpus/cache
COPY --from=build /tests /tests
COPY corpus/manifest.json /src/corpus/manifest.json
COPY docker/run-tests.sh /run-tests.sh
USER 65534:65534
ENTRYPOINT ["/bin/sh", "/run-tests.sh"]
