FROM docker.io/library/rust:alpine as builder
WORKDIR /work
COPY . .
RUN \
    apk add musl-dev curl xz && \
    cargo update && \
    cargo build --target=x86_64-unknown-linux-musl --release && \
    xz -k -6 target/x86_64-unknown-linux-musl/release/tyst && \
    mv target/x86_64-unknown-linux-musl/release/tyst.xz app.xz && \
    ./bin/extract-third-party-licenses.sh && \
    tar cJf licenses.tar.xz licenses/

FROM ghcr.io/mydriatech/the-ground-up:latest as runner

FROM scratch

LABEL org.opencontainers.image.source="https://github.com/mydriatech/tyst"
LABEL org.opencontainers.image.description="TYST Cryptographic Provider REST API"
LABEL org.opencontainers.image.licenses="Apache-2.0 WITH FWM-Exception-1.0.0 AND Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT AND Unicode-3.0"
LABEL org.opencontainers.image.vendor="MydriaTech AB"

COPY --from=runner  --chown=10001:0 /the-ground-up /tyst
COPY --from=runner  --chown=10001:0 /app /app
COPY --from=runner  --chown=10001:0 /licenses-the-ground-up.tar.xz /licenses-tgu.tar.xz
COPY --from=builder --chown=10001:0 /work/app.xz /app.xz
COPY --from=builder --chown=10001:0 /work/licenses.tar.xz /licenses.tar.xz

WORKDIR /

USER 10001:0

EXPOSE 8084

ENV LOG_LEVEL "INFO"

ENV TYST_API_ADDRESS "0.0.0.0"
ENV TYST_API_PORT    "8084"

CMD ["/tyst"]
