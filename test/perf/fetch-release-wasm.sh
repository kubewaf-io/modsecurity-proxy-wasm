#!/usr/bin/env bash
# Download modsecurity-proxy-wasm.wasm from a GitHub release tag.
#
# Private repos (and higher rate limits) need auth:
#   GITHUB_TOKEN or GH_TOKEN (GitHub Actions injects GITHUB_TOKEN automatically).
# When a token is set, assets are resolved via the Releases API (reliable for private repos).
# Without a token, falls back to public browser download URLs.
#
# Exit codes:
#   0 — success (path printed on stdout)
#   2 — usage / config error
#   3 — release or asset not found (404); safe for callers to skip
#   1 — other download / verify failure
#
# Usage:
#   ./test/perf/fetch-release-wasm.sh v0.1.0-alpha5
#   RELEASE_TAG=v0.1.0-alpha5 OUT=path/to.wasm ./test/perf/fetch-release-wasm.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG="${1:-${RELEASE_TAG:-}}"
OUT="${OUT:-$SCRIPT_DIR/.releases/${TAG}/modsecurity-proxy-wasm.wasm}"
REPO="${GITHUB_REPOSITORY:-}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
ASSET_NAME="${ASSET_NAME:-modsecurity-proxy-wasm.wasm}"
SHA_ASSET_NAME="${SHA_ASSET_NAME:-modsecurity-proxy-wasm.wasm.sha256}"

if [[ -z "$TAG" ]]; then
  echo "ERROR: release tag required (arg or RELEASE_TAG)" >&2
  exit 2
fi

if [[ -z "$REPO" ]]; then
  REPO="$(git -C "$SCRIPT_DIR/../.." remote get-url origin 2>/dev/null \
    | sed -E 's#(git@|https://)github.com[:/](.+)(\.git)?#\2#')"
fi
REPO="${REPO%.git}"

if [[ -z "$REPO" ]]; then
  echo "ERROR: could not determine GitHub repository (set GITHUB_REPOSITORY)" >&2
  exit 2
fi

mkdir -p "$(dirname "$OUT")"

if [[ -f "$OUT" ]] && [[ -f "${OUT}.sha256" ]] \
    && [[ "$(cat "${OUT}.sha256")" == "$(sha256sum "$OUT" | awk '{print $1}')" ]]; then
  echo "==> Reusing cached release wasm: $OUT" >&2
  echo "$OUT"
  exit 0
fi

# Shared curl headers for GitHub API / authenticated browser downloads.
curl_headers=()
if [[ -n "$TOKEN" ]]; then
  curl_headers+=(
    -H "Authorization: Bearer ${TOKEN}"
    -H "X-GitHub-Api-Version: 2022-11-28"
  )
fi

cleanup_partial() {
  rm -f "$OUT" "${OUT}.expected-sha256" "${OUT}.sha256" 2>/dev/null || true
}

not_found() {
  local msg="$1"
  echo "WARN: ${msg}" >&2
  cleanup_partial
  exit 3
}

verify_sha256() {
  local expected_file="$1"
  local expected actual
  expected="$(tr -d '[:space:]' < "$expected_file")"
  # Accept either bare hash or "hash  filename" (sha256sum style).
  expected="${expected%%[[:space:]]*}"
  actual="$(sha256sum "$OUT" | awk '{print $1}')"
  [[ "$expected" == "$actual" ]] || {
    echo "ERROR: sha256 mismatch for $TAG (expected $expected, got $actual)" >&2
    cleanup_partial
    exit 1
  }
  printf '%s\n' "$actual" > "${OUT}.sha256"
}

# curl with status code capture. Writes body to $2. Echoes HTTP code on stdout.
# Does not use -f so 404s are inspectable.
curl_to_file() {
  local url="$1"
  local dest="$2"
  shift 2
  local code
  code="$(
    curl -sS -L \
      -o "$dest" \
      -w '%{http_code}' \
      "$@" \
      "$url"
  )" || {
    echo "000"
    return 0
  }
  printf '%s' "$code"
}

download_api_asset() {
  local asset_id="$1"
  local dest="$2"
  curl_to_file \
    "https://api.github.com/repos/${REPO}/releases/assets/${asset_id}" \
    "$dest" \
    "${curl_headers[@]}" \
    -H "Accept: application/octet-stream"
}

asset_id_from_release_json() {
  local asset_name="$1"
  python3 -c '
import json, sys
name = sys.argv[1]
data = json.load(sys.stdin)
for asset in data.get("assets") or []:
    if asset.get("name") == name:
        print(asset["id"])
        raise SystemExit(0)
raise SystemExit(f"asset not found on release: {name}")
' "$asset_name"
}

if [[ -n "$TOKEN" ]]; then
  echo "==> Resolving ${ASSET_NAME} via GitHub API: ${REPO}@${TAG}" >&2
  release_tmp="$(mktemp)"
  api_code="$(
    curl_to_file \
      "https://api.github.com/repos/${REPO}/releases/tags/${TAG}" \
      "$release_tmp" \
      "${curl_headers[@]}" \
      -H "Accept: application/vnd.github+json"
  )"
  if [[ "$api_code" == "404" ]]; then
    rm -f "$release_tmp"
    not_found "release ${TAG} not found for ${REPO} (HTTP 404)"
  fi
  if [[ "$api_code" != "200" ]]; then
    echo "ERROR: failed to fetch release ${TAG} for ${REPO} (HTTP ${api_code})" >&2
    head -c 400 "$release_tmp" >&2 || true
    echo >&2
    rm -f "$release_tmp"
    exit 1
  fi

  if ! wasm_id="$(asset_id_from_release_json "$ASSET_NAME" <"$release_tmp")"; then
    rm -f "$release_tmp"
    not_found "release ${TAG} has no asset named ${ASSET_NAME}"
  fi

  echo "==> Downloading ${ASSET_NAME} (asset id ${wasm_id})" >&2
  asset_code="$(download_api_asset "$wasm_id" "$OUT")"
  if [[ "$asset_code" == "404" ]]; then
    rm -f "$release_tmp"
    not_found "asset ${ASSET_NAME} on ${TAG} returned HTTP 404"
  fi
  if [[ "$asset_code" != "200" ]]; then
    echo "ERROR: download failed for ${ASSET_NAME} on ${TAG} (HTTP ${asset_code})" >&2
    cleanup_partial
    rm -f "$release_tmp"
    exit 1
  fi

  if sha_id="$(asset_id_from_release_json "$SHA_ASSET_NAME" <"$release_tmp" 2>/dev/null)"; then
    echo "==> Verifying SHA256" >&2
    sha_code="$(download_api_asset "$sha_id" "${OUT}.expected-sha256")"
    if [[ "$sha_code" == "200" ]]; then
      verify_sha256 "${OUT}.expected-sha256"
      rm -f "${OUT}.expected-sha256"
    else
      sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
      rm -f "${OUT}.expected-sha256"
    fi
  else
    sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
  fi
  rm -f "$release_tmp"
else
  BASE="https://github.com/${REPO}/releases/download/${TAG}"
  WASM_URL="${BASE}/${ASSET_NAME}"
  SHA_URL="${BASE}/${SHA_ASSET_NAME}"

  echo "==> Downloading ${WASM_URL}" >&2
  http_code="$(curl_to_file "$WASM_URL" "$OUT")"
  if [[ "$http_code" == "404" ]]; then
    not_found "download 404 for ${WASM_URL}"
  fi
  if [[ "$http_code" != "200" ]]; then
    echo "ERROR: download failed for ${WASM_URL} (HTTP ${http_code})" >&2
    echo "hint: private repositories require GITHUB_TOKEN or GH_TOKEN" >&2
    cleanup_partial
    exit 1
  fi

  sha_code="$(curl_to_file "$SHA_URL" "${OUT}.expected-sha256" 2>/dev/null || echo "000")"
  if [[ "$sha_code" == "200" ]]; then
    echo "==> Verifying SHA256" >&2
    verify_sha256 "${OUT}.expected-sha256"
    rm -f "${OUT}.expected-sha256"
  else
    rm -f "${OUT}.expected-sha256"
    sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
  fi
fi

echo "$OUT"
