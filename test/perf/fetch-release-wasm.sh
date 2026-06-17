#!/usr/bin/env bash
# Download modsecurity-proxy-wasm.wasm from a GitHub release tag.
#
# Usage:
#   ./test/perf/fetch-release-wasm.sh v0.1.0-alpha5
#   RELEASE_TAG=v0.1.0-alpha5 OUT=path/to.wasm ./test/perf/fetch-release-wasm.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="${1:-${RELEASE_TAG:-}}"
OUT="${OUT:-$SCRIPT_DIR/.releases/${TAG}/modsecurity-proxy-wasm.wasm}"
REPO="${GITHUB_REPOSITORY:-}"

if [[ -z "$TAG" ]]; then
  echo "ERROR: release tag required (arg or RELEASE_TAG)" >&2
  exit 2
fi

if [[ -z "$REPO" ]]; then
  REPO="$(git -C "$SCRIPT_DIR/../.." remote get-url origin 2>/dev/null \
    | sed -E 's#(git@|https://)github.com[:/](.+)(\.git)?#\2#')"
fi
REPO="${REPO%.git}"

BASE="https://github.com/${REPO}/releases/download/${TAG}"
WASM_URL="${BASE}/modsecurity-proxy-wasm.wasm"
SHA_URL="${BASE}/modsecurity-proxy-wasm.wasm.sha256"

mkdir -p "$(dirname "$OUT")"

if [[ -f "$OUT" ]] && [[ -f "${OUT}.sha256" ]] \
    && [[ "$(cat "${OUT}.sha256")" == "$(sha256sum "$OUT" | awk '{print $1}')" ]]; then
  echo "==> Reusing cached release wasm: $OUT"
  exit 0
fi

echo "==> Downloading ${WASM_URL}" >&2
curl -fsSL "$WASM_URL" -o "$OUT"

if curl -fsSL "$SHA_URL" -o "${OUT}.expected-sha256" 2>/dev/null; then
  echo "==> Verifying SHA256" >&2
  expected="$(tr -d '[:space:]' < "${OUT}.expected-sha256")"
  actual="$(sha256sum "$OUT" | awk '{print $1}')"
  [[ "$expected" == "$actual" ]] || {
    echo "ERROR: sha256 mismatch for $TAG (expected $expected, got $actual)" >&2
    exit 1
  }
  cp "${OUT}.expected-sha256" "${OUT}.sha256"
else
  sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
fi

echo "$OUT"