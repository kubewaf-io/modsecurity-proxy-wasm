#!/usr/bin/env bash
# Build release-notes.md with embedded perf chart links for GitHub Releases.
set -euo pipefail

OUT="${1:-release-notes.md}"
CHARTS_DIR="${2:-test/perf/release-charts}"
REPO="${GITHUB_REPOSITORY:-owner/repo}"
TAG="${GITHUB_REF_NAME:-v0.0.0}"
BASE="https://github.com/${REPO}/releases/download/${TAG}"

chart_url() {
  local file="$1"
  echo "${BASE}/${file}"
}

emit_section() {
  local title="$1"
  local file="$2"
  if [[ -f "${CHARTS_DIR}/${file}" ]]; then
    printf '### %s\n\n' "$title"
    printf '![%s](%s)\n\n' "$title" "$(chart_url "$file")"
  fi
}

{
  echo "## modsec-wasm ${TAG}"
  echo ""
  echo "Artifacts: \`modsec.wasm\` (Envoy proxy-wasm / V8) and SHA256 checksum."
  echo ""
  echo "## Performance benchmarks"
  echo ""
  echo "k6 smoke through Envoy (\`envoyproxy/envoy:v1.38-latest\`): baseline, minimal Wasm, full CRS."
  echo "Compare charts are directional (modsec CRS v4.27 vs coraza embedded v4.14)."
  echo ""
  emit_section "modsec-full — benign GET" "perf-modsec-full-benign-get.png"
  emit_section "baseline — benign GET" "perf-baseline-benign-get.png"
  emit_section "modsec-full vs coraza-full — benign GET" "perf-compare-modsec-full-vs-coraza-full-benign-get.png"
  emit_section "modsec-full vs coraza-full — benign POST 1k" "perf-compare-modsec-full-vs-coraza-full-benign-post-1k.png"
  emit_section "wasm-minimal vs coraza-minimal — benign GET" "perf-compare-wasm-minimal-vs-coraza-minimal-benign-get.png"
} >"$OUT"

echo "==> Wrote $OUT"