#!/usr/bin/env bash
set -euo pipefail

# Scrape Envoy admin stats for a perf run.
# Usage: ADMIN_URL=http://127.0.0.1:19901 ./test/perf/collect-stats.sh <label> <output-dir>

ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:19901}"
LABEL="${1:?label required}"
OUT_DIR="${2:?output dir required}"

mkdir -p "$OUT_DIR"

curl -sf "${ADMIN_URL}/stats" > "${OUT_DIR}/envoy-stats-${LABEL}.txt"
curl -sf "${ADMIN_URL}/stats/prometheus" > "${OUT_DIR}/envoy-prometheus-${LABEL}.txt"

grep -E '^(http\.ingress_http\.|wasm\.|modsecurity_proxy_wasm|waf_filter)' "${OUT_DIR}/envoy-stats-${LABEL}.txt" \
  > "${OUT_DIR}/envoy-stats-${LABEL}-filtered.txt" || true

grep -E '^modsecurity_proxy_wasm' "${OUT_DIR}/envoy-prometheus-${LABEL}.txt" \
  > "${OUT_DIR}/modsecurity-proxy-wasm-metrics-${LABEL}.txt" || true

grep -E '^waf_filter' "${OUT_DIR}/envoy-prometheus-${LABEL}.txt" \
  > "${OUT_DIR}/coraza-wasm-metrics-${LABEL}.txt" || true

echo "==> Saved Envoy stats (${LABEL}) to ${OUT_DIR}"