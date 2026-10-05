# The scan container. Builds mcsec as a static binary and ships it alone in an
# empty image, with no shell, no JVM, and no other tools, so a jar has nothing
# to run in even if it got past the scanner. Run it through
# scripts/scan-sandboxed.sh, which applies the runtime restrictions.

# Base images are pinned by digest so a changed upstream image cannot slip
# into a build. To update, look up the new digest with
# `docker buildx imagetools inspect <image>` and replace it here.
FROM rust:1-alpine@sha256:0cce0a5e0e8ba67b455257a3a02a1d99005f382748789d6464460028810f1627 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p mcsec-cli

FROM scratch
COPY --from=build /src/target/release/mcsec /mcsec
USER 65534:65534
ENTRYPOINT ["/mcsec"]
