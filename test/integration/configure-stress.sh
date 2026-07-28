#!/usr/bin/env bash
# Path B configure stress gate (WS1C / recovery plan M0+M1).
#
# Boots Envoy with a large gzip+base64 directives_map that mixes:
#   - many setvar score SecRules
#   - a deny chain (parent+child)
#   - @pmFromFile scanners-user-agents.data (catalog automata)
#
# Pass criteria:
#   - Envoy becomes ready (plugin did not trap as unreachable)
#   - logs contain "event":"config_applied" (not fail_closed)
#   - logs contain "event":"heap_sample" stages (WS0 instrumentation)
#   - optional: wasm_heap_bytes after configure <= CONFIGURE_HEAP_BUDGET_BYTES
#
# Usage:
#   ./test/integration/configure-stress.sh
#   WASM=dist/modsecurity-proxy-wasm.wasm SCORE_RULES=200 ./test/integration/configure-stress.sh
#   INITIAL_MEMORY=64MB make modsecurity-proxy-wasm.wasm && make test-configure-stress
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WASM="${WASM:-$ROOT_DIR/dist/modsecurity-proxy-wasm.wasm}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.38-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-modsecurity-proxy-wasm-configure-stress}"
HOST_PORT="${HOST_PORT:-18090}"
ADMIN_PORT="${ADMIN_PORT:-19910}"
SCORE_RULES="${SCORE_RULES:-120}"
# 0 = no budget check (default). Example: 134217728 for 128MiB floor.
CONFIGURE_HEAP_BUDGET_BYTES="${CONFIGURE_HEAP_BUDGET_BYTES:-0}"
KEEP_RUNNING="${KEEP_RUNNING:-0}"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/test/integration/.configure-stress}"
OUT_DIR="${OUT_DIR:-$WORK_DIR/out}"

mkdir -p "$WORK_DIR" "$OUT_DIR"
ENVOY_YAML="$WORK_DIR/envoy-configure-stress.yaml"
PLUGIN_JSON="$WORK_DIR/plugin-configure-stress.json"
ENVOY_LOG="$OUT_DIR/configure-stress-envoy.log"

if command -v docker >/dev/null 2>&1; then
  CTR=docker
elif command -v podman >/dev/null 2>&1; then
  CTR=podman
else
  echo "ERROR: need docker or podman" >&2
  exit 1
fi

cleanup() {
  if [[ "$KEEP_RUNNING" == "1" ]]; then
    echo "==> KEEP_RUNNING=1 — container ${CONTAINER_NAME} left up"
    return 0
  fi
  $CTR rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ -f "$WASM" ]] || {
  echo "ERROR: $WASM not found. Build first (make image / make modsecurity-proxy-wasm.wasm)." >&2
  exit 1
}

echo "==> Generating Path B stress config (score_rules=${SCORE_RULES})"
python3 "$SCRIPT_DIR/generate-configure-stress-config.py" \
  --score-rules "$SCORE_RULES" \
  --out-json "$PLUGIN_JSON" \
  --out-envoy "$ENVOY_YAML"

# Parse link-time linear memory for the report.
PYTHONPATH="$ROOT_DIR/test/perf" python3 - "$WASM" "$OUT_DIR" <<'PY'
import json
import sys
from pathlib import Path
from memory import parse_wasm_linear_memory

wasm = Path(sys.argv[1])
out = Path(sys.argv[2])
m = parse_wasm_linear_memory(wasm)
(out / "wasm-linear-memory.json").write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
print("wasm linear memory:", json.dumps(m))
PY

$CTR rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
echo "==> Starting Envoy ($ENVOY_IMAGE) for configure stress"
$CTR run -d --name "$CONTAINER_NAME" \
  -v "$WASM:/etc/modsecurity-proxy-wasm.wasm:ro" \
  -v "$ENVOY_YAML:/etc/envoy.yaml:ro" \
  -p "${HOST_PORT}:8080" \
  -p "${ADMIN_PORT}:9901" \
  "$ENVOY_IMAGE" \
  envoy -c /etc/envoy.yaml --log-level info

ready=0
for _ in $(seq 1 180); do
  logs=$($CTR logs "$CONTAINER_NAME" 2>&1 || true)
  printf '%s\n' "$logs" >"$ENVOY_LOG"
  # Trap-class failures only (OOM / bad_alloc under DISABLE_EXCEPTION_CATCHING).
  # Do not treat "Wasm VM failed Failed to configure" as a trap — that is fail_closed.
  if grep -E 'Uncaught RuntimeError|RuntimeError: unreachable' <<<"$logs" >/dev/null 2>&1; then
    echo "FAIL: Wasm unreachable/trap during configure (likely INITIAL_MEMORY too low)" >&2
    grep -E 'Uncaught RuntimeError|unreachable|rules_loading|heap_sample' "$ENVOY_LOG" | tail -n 40 >&2 || true
    exit 1
  fi
  if grep -E '"event"[[:space:]]*:[[:space:]]*"config_load_failed"' <<<"$logs" >/dev/null 2>&1 \
    && ! grep -E '"event"[[:space:]]*:[[:space:]]*"config_applied"' <<<"$logs" >/dev/null 2>&1; then
    echo "FAIL: plugin fail_closed during configure stress" >&2
    grep -E 'config_load_failed|configure_failed|rules_load_failed' "$ENVOY_LOG" | tail -n 20 >&2 || true
    exit 1
  fi
  if grep -E '"event"[[:space:]]*:[[:space:]]*"config_applied"' <<<"$logs" >/dev/null 2>&1; then
    if curl -s --max-time 1 --resolve "www.example.com:${HOST_PORT}:127.0.0.1" \
        "http://www.example.com:${HOST_PORT}/" >/dev/null 2>&1; then
      ready=1
      break
    fi
  fi
  sleep 0.5
done

$CTR logs "$CONTAINER_NAME" >"$ENVOY_LOG" 2>&1 || true

if [[ "$ready" != "1" ]]; then
  echo "FAIL: configure stress did not reach config_applied + HTTP ready" >&2
  tail -n 100 "$ENVOY_LOG" >&2 || true
  exit 1
fi

echo "==> config_applied observed; checking heap_sample instrumentation"
if ! grep -E '"event"[[:space:]]*:[[:space:]]*"heap_sample"' "$ENVOY_LOG" >/dev/null 2>&1; then
  echo "FAIL: no heap_sample events in Envoy logs (rebuild wasm with WS0 instrumentation?)" >&2
  tail -n 40 "$ENVOY_LOG" >&2 || true
  exit 1
fi

# Scrape prometheus for wasm heap gauge after configure.
curl -s --max-time 3 "http://127.0.0.1:${ADMIN_PORT}/stats/prometheus" \
  >"$OUT_DIR/envoy-prometheus-after.txt" || true
grep -E 'modsecurity_proxy_wasm_memory_wasm_heap' "$OUT_DIR/envoy-prometheus-after.txt" \
  >"$OUT_DIR/modsecurity-proxy-wasm-memory-after.txt" || true
# Treat post-configure scrape as before/after for finalize schema compatibility.
cp -f "$OUT_DIR/envoy-prometheus-after.txt" "$OUT_DIR/envoy-prometheus-before.txt" 2>/dev/null || true
cp -f "$OUT_DIR/modsecurity-proxy-wasm-memory-after.txt" \
  "$OUT_DIR/modsecurity-proxy-wasm-memory-before.txt" 2>/dev/null || true

chmod +x "$ROOT_DIR/test/perf/finalize-memory.sh"
PERF_WASM="$WASM" PERF_ENVOY_LOG="$ENVOY_LOG" PERF_ENVOY_CONTAINER="$CONTAINER_NAME" \
  "$ROOT_DIR/test/perf/finalize-memory.sh" "$OUT_DIR"

export CONFIGURE_HEAP_BUDGET_BYTES
python3 - "$OUT_DIR" <<'PY'
import json
import os
import sys
from pathlib import Path

out = Path(sys.argv[1])
snap = json.loads((out / "memory-snapshot.json").read_text(encoding="utf-8"))
ladder = snap.get("configure_heap_ladder") or {}
stages = ladder.get("stages") or {}
peak = ladder.get("peak_wasm_heap_bytes") or 0
after = (snap.get("modsecurity_after") or {}).get("wasm_heap_bytes") or 0
linear = snap.get("wasm_linear_memory") or {}
initial = linear.get("initial_memory_bytes") or 0

print("==> Configure stress heap ladder")
for k in sorted(stages.keys()):
    print(f"    stage={k:24s} wasm_heap_bytes={stages[k]} ({stages[k] / (1024*1024):.1f} MiB)")
if peak:
    print(f"    peak_from_logs={peak} ({peak / (1024*1024):.1f} MiB)")
else:
    print("    peak_from_logs=n/a")
if after:
    print(f"    gauge_after_configure={after} ({after / (1024*1024):.1f} MiB)")
else:
    print("    gauge_after_configure=n/a")
if initial:
    print(f"    wasm_initial_memory={initial} ({initial / (1024*1024):.1f} MiB)")
else:
    print("    wasm_initial_memory=n/a")

budget = int(os.environ.get("CONFIGURE_HEAP_BUDGET_BYTES", "0") or "0")
if budget > 0:
    observed = max(peak, after)
    if observed > budget:
        print(
            f"FAIL: wasm heap {observed} exceeds budget {budget} "
            f"({observed / (1024*1024):.1f} MiB > {budget / (1024*1024):.1f} MiB)",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"    budget_ok observed={observed} budget={budget}")

print(f"    results: {out}")
PY

status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
  --resolve "www.example.com:${HOST_PORT}:127.0.0.1" \
  "http://www.example.com:${HOST_PORT}/?q=stress-token-0" || echo 000)
echo "==> Smoke GET status=${status}"

echo "==> PASS configure-stress (logs: $ENVOY_LOG, snapshot: $OUT_DIR/memory-snapshot.json)"
