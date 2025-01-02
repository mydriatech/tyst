FROM docker.io/library/rust:alpine as builder
WORKDIR /work
COPY . .
RUN \
    apk add musl-dev curl xz && \
    cargo update && \
    cargo build --target=x86_64-unknown-linux-musl --release || \
    cargo build --target=aarch64-unknown-linux-musl --release && \
    cp /work/target/x86_64-unknown-linux-musl/release/tyst /work/target/tyst || \
    cp /work/target/aarch64-unknown-linux-musl/release/tyst /work/target/tyst && \
    # UPX cuts the container size by 2/3rds, but might get flagged by AV scanners
    # Fedora uses "LicenseRef-GPL-2.0-or-later-WITH-UPX" as SPDX expression.
    # -> Skip this for now.
    #apk add upx && \
    #upx -9 /work/target/${TARGET}/release/tyst -o/work/target/tyst && \
    ls -l /work/target/ && \
    ./bin/extract-third-party-licenses.sh && \
    tar cJf licenses.tar.xz licenses/

FROM scratch

LABEL org.opencontainers.image.source="https://github.com/mydriatech/tyst"
LABEL org.opencontainers.image.description="TYST Cryptographic Provider REST API"
LABEL org.opencontainers.image.licenses="Apache-2.0 WITH FWM-Exception-1.0.0 AND Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT AND Unicode-3.0"
LABEL org.opencontainers.image.vendor="MydriaTech AB"

COPY --from=builder --chown=10001:0 /work/target/tyst /tyst
COPY --from=builder --chown=10001:0 --chmod=770 /work/licenses.tar.xz /licenses.tar.xz

WORKDIR /

USER 10001:0

EXPOSE 8084

ENV LOG_LEVEL "INFO"

ENV TYST_API_ADDRESS "0.0.0.0"
ENV TYST_API_PORT    "8084"

CMD ["/tyst"]
