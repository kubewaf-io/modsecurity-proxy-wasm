# syntax=docker/dockerfile:1
# Builder image: OS toolchain + `make all` (see build/build.mk).
#
# OCI artifact image (default):
#   podman build -f build/docker/Dockerfile -t modsec-wasm:latest .
#   make extract-wasm IMAGE=modsec-wasm:latest
#
# Builder stage only:
#   podman build -f build/docker/Dockerfile --target builder -t modsec-wasm-builder .
#
# Package an existing modsec.wasm (no compile):
#   podman build -f build/docker/Dockerfile.oci -t modsec-wasm:latest .

FROM debian:trixie-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl ca-certificates xz-utils python3 bash \
    autoconf automake libtool m4 pkg-config \
    clang-18 lld-18 cmake ninja-build wabt \
    && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-c"]

WORKDIR /build
COPY . /build/

ARG CRS_VERSION=v4.27.0
ENV CRS_VERSION=${CRS_VERSION}

RUN make all PREFIX=/opt MODSEC_WASM_OUT=/modsec.wasm MODSEC_WAT_OUT=/modsec.wat

# OCI distribution image (default target): wasm + default WAF JSON + Envoy example.
FROM scratch AS release

ARG CRS_VERSION=v4.27.0
ARG VERSION=0.1.0

LABEL org.opencontainers.image.title="modsec-wasm" \
      org.opencontainers.image.description="ModSecurity proxy-wasm module with embedded OWASP CRS for Envoy envoy.wasm.runtime.v8" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="modsec-wasm-plugin" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/owasp-modsecurity/ModSecurity" \
      modsec.wasm.runtime="envoy.wasm.runtime.v8" \
      owasp.crs.ref="${CRS_VERSION}"

COPY --from=builder /modsec.wasm /usr/share/modsec-wasm/modsec.wasm
COPY --from=builder /modsec.wat /usr/share/modsec-wasm/modsec.wat
COPY test/fixtures/waf-config.default.json /usr/share/modsec-wasm/waf-config.default.json
COPY test/fixtures/envoy.yaml /usr/share/modsec-wasm/examples/envoy.yaml