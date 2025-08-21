FROM docker.io/library/rust:1.89.0-alpine as builder
WORKDIR /work
COPY . .
RUN \
    apk add musl-dev curl xz && \
    cargo update && \
    cargo build --target=x86_64-unknown-linux-musl --release && \
    xz -k -6 target/x86_64-unknown-linux-musl/release/tyst-api-rest && \
    mv target/x86_64-unknown-linux-musl/release/tyst-api-rest.xz tyst-api-rest.xz && \
    ./bin/extract-third-party-licenses.sh && \
    tar cJf licenses.tar.xz licenses/

FROM ghcr.io/mydriatech/the-ground-up:1.0.0 as tgu

FROM scratch

LABEL org.opencontainers.image.source="https://github.com/mydriatech/tyst"
LABEL org.opencontainers.image.description="TYST Cryptographic Provider REST API"
LABEL org.opencontainers.image.licenses="Apache-2.0 WITH FWM-Exception-1.0.0 AND Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT AND Unicode-3.0"
LABEL org.opencontainers.image.vendor="MydriaTech AB"

COPY --from=tgu     --chown=10001:0 /licenses-tgu.tar.xz   /licenses-tgu.tar.xz
COPY --from=tgu     --chown=10001:0 /the-ground-up         /tyst-api-rest
COPY --from=tgu     --chown=10001:0 /the-ground-up-bin     /tyst-api-rest-bin
COPY --from=builder --chown=10001:0 /work/tyst-api-rest.xz /tyst-api-rest.xz
COPY --from=builder --chown=10001:0 /work/licenses.tar.xz  /licenses.tar.xz

WORKDIR /

USER 10001:0

EXPOSE 8084

ENV LOG_LEVEL "INFO"

ENV TYST_API_ADDRESS "0.0.0.0"
ENV TYST_API_PORT    "8084"

CMD ["/tyst-api-rest"]
