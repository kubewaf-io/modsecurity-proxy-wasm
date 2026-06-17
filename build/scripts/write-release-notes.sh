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
  echo "## OCI image"
  echo ""
  echo "Container image: \`ghcr.io/${REPO}:${TAG}\` (also \`:${TAG#v}\` without the \`v\` prefix)."
  echo ""
  echo "Built from [\`build/docker/Dockerfile\`](https://github.com/${REPO}/blob/${TAG}/build/docker/Dockerfile) (default \`release\` stage: wasm + default WAF JSON + Envoy example)."
  echo "Repackage an existing wasm only: [\`build/docker/Dockerfile.oci\`](https://github.com/${REPO}/blob/${TAG}/build/docker/Dockerfile.oci)."
  echo ""
  echo '```bash'
  echo "make image IMAGE=ghcr.io/${REPO}:${TAG} VERSION=${TAG#v}"
  echo "make extract-wasm IMAGE=ghcr.io/${REPO}:${TAG}"
  echo '```'
  echo ""
  echo "## Performance benchmarks"
  echo ""
  echo "k6 smoke through Envoy (\`envoyproxy/envoy:v1.38-latest\`): baseline, minimal Wasm, full CRS."
  echo "Each line is one profile/scenario; comparisons are directional (modsec CRS v4.27 vs coraza embedded v4.14)."
  echo ""
  emit_section "k6 perf — all tests" "perf-overlay.png"
} >"$OUT"

echo "==> Wrote $OUT"