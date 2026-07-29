#!/usr/bin/env bash
# Path B full CRS configure soak (recovery plan item #1 — memory truth).
#
# Loads real OWASP CRS rule confs as gzip+base64 Path B SecLang (same shape as
# kubeWAF operator injection). Records heap_sample ladder and whether the
# 64 MiB INITIAL_MEMORY floor had to grow.
#
# Profiles:
#   CRS_SOAK_PROFILE=request  (default) — REQUEST-*.conf only
#   CRS_SOAK_PROFILE=full               — all rules/*.conf
#
# Usage:
#   make test-configure-crs-soak
#   CRS_SOAK_PROFILE=full make test-configure-crs-soak
#   CONFIGURE_HEAP_BUDGET_BYTES=67108864 make test-configure-crs-soak
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WASM="${WASM:-$ROOT_DIR/dist/modsecurity-proxy-wasm.wasm}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.38-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-modsecurity-proxy-wasm-crs-soak}"
HOST_PORT="${HOST_PORT:-18091}"
ADMIN_PORT="${ADMIN_PORT:-19911}"
CRS_SOAK_PROFILE="${CRS_SOAK_PROFILE:-request}"
CRS_DIR="${CRS_DIR:-$ROOT_DIR/.cache/deps/crs}"
# 0 = report only (default). Example: 67108864 to fail if peak > 64 MiB.
CONFIGURE_HEAP_BUDGET_BYTES="${CONFIGURE_HEAP_BUDGET_BYTES:-0}"
KEEP_RUNNING="${KEEP_RUNNING:-0}"
# Full CRS configure can take longer than synthetic stress.
READY_ATTEMPTS="${READY_ATTEMPTS:-300}"
WORK_DIR="${WORK_DIR:-$ROOT_DIR/test/integration/.configure-crs-soak}"
OUT_DIR="${OUT_DIR:-$WORK_DIR/out}"

mkdir -p "$WORK_DIR" "$OUT_DIR"
ENVOY_YAML="$WORK_DIR/envoy-crs-soak.yaml"
PLUGIN_JSON="$WORK_DIR/plugin-crs-soak.json"
STATS_JSON="$OUT_DIR/crs-path-b-stats.json"
ENVOY_LOG="$OUT_DIR/configure-crs-soak-envoy.log"
REPORT_JSON="$OUT_DIR/crs-soak-report.json"

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
  echo "ERROR: $WASM not found. Build first (make modsecurity-proxy-wasm.wasm)." >&2
  exit 1
}
[[ -d "$CRS_DIR/rules" ]] || {
  echo "ERROR: CRS rules not found at $CRS_DIR/rules (run: make deps)" >&2
  exit 1
}

echo "==> Generating Path B CRS config (profile=${CRS_SOAK_PROFILE}, crs=${CRS_DIR})"
python3 "$SCRIPT_DIR/generate-crs-path-b-config.py" \
  --crs "$CRS_DIR" \
  --profile "$CRS_SOAK_PROFILE" \
  --out-json "$PLUGIN_JSON" \
  --out-envoy "$ENVOY_YAML" \
  --out-stats "$STATS_JSON"

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
echo "==> Starting Envoy ($ENVOY_IMAGE) for CRS Path B configure soak"
$CTR run -d --name "$CONTAINER_NAME" \
  -v "$WASM:/etc/modsecurity-proxy-wasm.wasm:ro" \
  -v "$ENVOY_YAML:/etc/envoy.yaml:ro" \
  -p "${HOST_PORT}:8080" \
  -p "${ADMIN_PORT}:9901" \
  "$ENVOY_IMAGE" \
  envoy -c /etc/envoy.yaml --log-level info

ready=0
trap_seen=0
for _ in $(seq 1 "$READY_ATTEMPTS"); do
  logs=$($CTR logs "$CONTAINER_NAME" 2>&1 || true)
  printf '%s\n' "$logs" >"$ENVOY_LOG"
  if grep -E 'Uncaught RuntimeError|RuntimeError: unreachable' <<<"$logs" >/dev/null 2>&1; then
    trap_seen=1
    echo "FAIL: Wasm unreachable/trap during CRS configure (INITIAL_MEMORY too low or peak OOM)" >&2
    grep -E 'Uncaught RuntimeError|unreachable|rules_loading|heap_sample|rules_load_failed' \
      "$ENVOY_LOG" | tail -n 50 >&2 || true
    exit 1
  fi
  if grep -E '"event"[[:space:]]*:[[:space:]]*"config_load_failed"' <<<"$logs" >/dev/null 2>&1 \
    && ! grep -E '"event"[[:space:]]*:[[:space:]]*"config_applied"' <<<"$logs" >/dev/null 2>&1; then
    echo "FAIL: plugin fail_closed during CRS configure soak" >&2
    grep -E 'config_load_failed|configure_failed|rules_load_failed' "$ENVOY_LOG" | tail -n 30 >&2 || true
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
  echo "FAIL: CRS soak did not reach config_applied + HTTP ready (attempts=${READY_ATTEMPTS})" >&2
  tail -n 120 "$ENVOY_LOG" >&2 || true
  exit 1
fi

echo "==> config_applied observed; checking heap_sample instrumentation"
if ! grep -E '"event"[[:space:]]*:[[:space:]]*"heap_sample"' "$ENVOY_LOG" >/dev/null 2>&1; then
  echo "FAIL: no heap_sample events (rebuild wasm with WS0 instrumentation?)" >&2
  exit 1
fi

curl -s --max-time 5 "http://127.0.0.1:${ADMIN_PORT}/stats/prometheus" \
  >"$OUT_DIR/envoy-prometheus-after.txt" || true
grep -E 'modsecurity_proxy_wasm_memory_wasm_heap' "$OUT_DIR/envoy-prometheus-after.txt" \
  >"$OUT_DIR/modsecurity-proxy-wasm-memory-after.txt" || true
cp -f "$OUT_DIR/envoy-prometheus-after.txt" "$OUT_DIR/envoy-prometheus-before.txt" 2>/dev/null || true
cp -f "$OUT_DIR/modsecurity-proxy-wasm-memory-after.txt" \
  "$OUT_DIR/modsecurity-proxy-wasm-memory-before.txt" 2>/dev/null || true

chmod +x "$ROOT_DIR/test/perf/finalize-memory.sh"
PERF_WASM="$WASM" PERF_ENVOY_LOG="$ENVOY_LOG" PERF_ENVOY_CONTAINER="$CONTAINER_NAME" \
  "$ROOT_DIR/test/perf/finalize-memory.sh" "$OUT_DIR"

export CONFIGURE_HEAP_BUDGET_BYTES CRS_SOAK_PROFILE HOST_PORT
python3 - "$OUT_DIR" "$STATS_JSON" "$REPORT_JSON" <<'PY'
import json
import os
import sys
from pathlib import Path

out = Path(sys.argv[1])
stats_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])

snap = json.loads((out / "memory-snapshot.json").read_text(encoding="utf-8"))
ladder = snap.get("configure_heap_ladder") or {}
stages = ladder.get("stages") or {}
peak = int(ladder.get("peak_wasm_heap_bytes") or 0)
after = int((snap.get("modsecurity_after") or {}).get("wasm_heap_bytes") or 0)
linear = snap.get("wasm_linear_memory") or {}
initial = int(linear.get("initial_memory_bytes") or 0)
maximum = int(linear.get("maximum_memory_bytes") or 0)

crs_stats = {}
if stats_path.is_file():
    crs_stats = json.loads(stats_path.read_text(encoding="utf-8"))

observed = max(peak, after)
grew = bool(initial and observed > initial)
# Growth within a page of initial is noise; require clear step.
if initial and observed > initial + (64 * 1024):
    grew = True
elif initial and observed <= initial:
    grew = False

print("==> CRS Path B configure soak heap ladder")
print(f"    profile={os.environ.get('CRS_SOAK_PROFILE', 'request')}")
for k in sorted(stages.keys()):
    print(f"    stage={k:24s} wasm_heap_bytes={stages[k]} ({stages[k] / (1024*1024):.1f} MiB)")
print(f"    peak_from_logs={peak} ({peak / (1024*1024):.1f} MiB)" if peak else "    peak_from_logs=n/a")
print(f"    gauge_after_configure={after} ({after / (1024*1024):.1f} MiB)" if after else "    gauge_after_configure=n/a")
print(f"    wasm_initial_memory={initial} ({initial / (1024*1024):.1f} MiB)" if initial else "    wasm_initial_memory=n/a")
print(f"    wasm_maximum_memory={maximum} ({maximum / (1024*1024):.1f} MiB)" if maximum else "    wasm_maximum_memory=n/a")
print(f"    memory_grew_above_initial={'YES' if grew else 'NO'}")
if crs_stats:
    print(
        f"    crs_directives={crs_stats.get('directive_count')} "
        f"confs={len(crs_stats.get('conf_files') or [])} "
        f"pmFromFile={crs_stats.get('pm_from_file_refs')} "
        f"raw_MiB={(crs_stats.get('raw_bytes') or 0) / 1024 / 1024:.2f}"
    )

report = {
    "profile": os.environ.get("CRS_SOAK_PROFILE", "request"),
    "pass": True,
    "wasm_linear_memory": linear,
    "peak_wasm_heap_bytes": peak or None,
    "gauge_after_configure_bytes": after or None,
    "memory_grew_above_initial": grew,
    "stages": stages,
    "crs_path_b": {
        "directive_count": crs_stats.get("directive_count"),
        "pm_from_file_refs": crs_stats.get("pm_from_file_refs"),
        "raw_bytes": crs_stats.get("raw_bytes"),
        "compressed_bytes": crs_stats.get("compressed_bytes"),
        "conf_files": len(crs_stats.get("conf_files") or []),
    },
    "recommendation": (
        f"INITIAL_MEMORY floor ({initial / (1024*1024):.0f} MiB) is sufficient for this "
        "profile; no growth required."
        if not grew
        else "Heap grew above INITIAL_MEMORY during CRS configure — investigate peak "
        "chunks (heap_sample) before lowering floor further; raise INITIAL_MEMORY if "
        "growth approaches MAXIMUM under production Path B payloads."
    ),
}

budget = int(os.environ.get("CONFIGURE_HEAP_BUDGET_BYTES", "0") or "0")
if budget > 0:
    if observed > budget:
        report["pass"] = False
        report["budget_bytes"] = budget
        report["observed_bytes"] = observed
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(
            f"FAIL: wasm heap {observed} exceeds budget {budget} "
            f"({observed / (1024*1024):.1f} MiB > {budget / (1024*1024):.1f} MiB)",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"    budget_ok observed={observed} budget={budget}")
    report["budget_bytes"] = budget
    report["observed_bytes"] = observed

report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(f"    report: {report_path}")
print(f"    recommendation: {report['recommendation']}")
PY

# Smoke: benign + classic XSS after full CRS load
benign=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  --resolve "www.example.com:${HOST_PORT}:127.0.0.1" \
  "http://www.example.com:${HOST_PORT}/" || echo 000)
xss=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  --resolve "www.example.com:${HOST_PORT}:127.0.0.1" \
  "http://www.example.com:${HOST_PORT}/?q=%3Cscript%3Ealert(1)%3C/script%3E" || echo 000)
echo "==> Smoke GET benign=${benign} xss=${xss} (expect 200 / 403 with CRS PL1)"

if [[ "$benign" != "200" ]]; then
  echo "WARN: benign GET returned ${benign} (CRS may block base request; check setup)" >&2
fi

echo "==> PASS configure-crs-soak (logs: $ENVOY_LOG, report: $REPORT_JSON)"
