#!/usr/bin/env bash
# Extract modsec.wasm (and optional extras) from the OCI artifact image.
set -euo pipefail

IMAGE="${1:-modsec-wasm:latest}"
OUT_DIR="${2:-dist}"
mkdir -p "$OUT_DIR"

if [[ -z "${CTR:-}" ]]; then
  if command -v podman >/dev/null 2>&1; then
    CTR=podman
  elif command -v docker >/dev/null 2>&1; then
    CTR=docker
  else
    echo "ERROR: need podman or docker" >&2
    exit 1
  fi
fi

WASM_PATH="/usr/share/modsec-wasm/modsec.wasm"

# Release images are FROM scratch with no CMD/ENTRYPOINT. Docker refuses plain
# `create` (podman may allow it); use the wasm path as a dummy entrypoint — we
# only copy files and never start the container.
cid=""
if cid=$($CTR create "$IMAGE" 2>/dev/null); then
  :
elif cid=$($CTR create --entrypoint="$WASM_PATH" "$IMAGE" 2>/dev/null); then
  :
else
  echo "ERROR: failed to create container from $IMAGE (scratch image needs --entrypoint)" >&2
  exit 1
fi
trap '$CTR rm -f "$cid" >/dev/null 2>&1 || true' EXIT

$CTR cp "$cid:$WASM_PATH" "$OUT_DIR/modsec.wasm"
echo "Wrote $OUT_DIR/modsec.wasm"

if $CTR cp "$cid:/usr/share/modsec-wasm/waf-config.default.json" "$OUT_DIR/waf-config.default.json" 2>/dev/null; then
  echo "Wrote $OUT_DIR/waf-config.default.json"
fi

if $CTR cp "$cid:/usr/share/modsec-wasm/examples/envoy.yaml" "$OUT_DIR/envoy.example.yaml" 2>/dev/null; then
  echo "Wrote $OUT_DIR/envoy.example.yaml"
fi