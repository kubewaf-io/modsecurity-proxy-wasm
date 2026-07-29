#!/usr/bin/env bash
# Build memory-snapshot.json from envoy prometheus + optional docker stats samples.
# Optional env:
#   PERF_WASM          path to .wasm (parses INITIAL/MAXIMUM linear memory)
#   PERF_ENVOY_LOG     path to Envoy log with heap_sample JSON lines
#   PERF_ENVOY_CONTAINER  container name for docker/podman stats
set -euo pipefail

OUT_DIR="${1:?output dir}"
CONTAINER="${PERF_ENVOY_CONTAINER:-modsecurity-proxy-wasm-perf-envoy}"
PERF_WASM="${PERF_WASM:-}"
PERF_ENVOY_LOG="${PERF_ENVOY_LOG:-}"

if command -v docker >/dev/null 2>&1; then
  CTR="docker"
elif command -v podman >/dev/null 2>&1; then
  CTR="podman"
else
  CTR=""
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH="$SCRIPT_DIR" python3 - "$OUT_DIR" "$CONTAINER" "$CTR" "$PERF_WASM" "$PERF_ENVOY_LOG" <<'PY'
import json
import sys
from pathlib import Path

from memory import (
    parse_heap_samples_from_log,
    parse_modsecurity_memory,
    parse_prometheus_memory,
    parse_wasm_linear_memory,
    peak_from_samples,
)

out_dir = Path(sys.argv[1])
container = sys.argv[2]
ctr = sys.argv[3]
wasm_path = sys.argv[4] if len(sys.argv) > 4 else ""
envoy_log = sys.argv[5] if len(sys.argv) > 5 else ""

def load_envoy(label: str) -> dict:
    path = out_dir / f"memory-envoy-{label}.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return parse_prometheus_memory(out_dir / f"envoy-prometheus-{label}.txt")

def load_modsec(label: str) -> dict:
    # Prefer filtered scrapes; fall back to full prometheus text.
    filtered = out_dir / f"modsecurity-proxy-wasm-memory-{label}.txt"
    if filtered.is_file():
        m = parse_modsecurity_memory(filtered)
        if m:
            return m
    return parse_modsecurity_memory(out_dir / f"envoy-prometheus-{label}.txt")

peak = peak_from_samples(out_dir / "memory-samples.log")
container_after = None
if ctr:
    import subprocess

    try:
        proc = subprocess.run(
            [ctr, "stats", "--no-stream", "--format", "{{.MemUsage}}", container],
            capture_output=True,
            text=True,
            check=True,
        )
        from memory import parse_docker_mem_usage

        used, limit = parse_docker_mem_usage(proc.stdout.strip())
        if used is not None:
            container_after = {
                "container_rss_bytes": used,
                "container_limit_bytes": limit,
            }
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

modsec_before = load_modsec("before")
modsec_after = load_modsec("after")
if not modsec_after:
    modsec_after = parse_modsecurity_memory(out_dir / "envoy-prometheus-after.txt")

# Linear memory from the .wasm under test (link-time INITIAL/MAXIMUM).
wasm_linear = {}
candidates = []
if wasm_path:
    candidates.append(Path(wasm_path))
candidates.append(out_dir / "modsecurity-proxy-wasm.wasm")
for parent in list(out_dir.resolve().parents)[:6]:
    guess = parent / "dist" / "modsecurity-proxy-wasm.wasm"
    if guess.is_file():
        candidates.append(guess)
        break
for c in candidates:
    wasm_linear = parse_wasm_linear_memory(c)
    if wasm_linear:
        wasm_linear["source"] = str(c)
        break

# Configure-phase heap ladder from Envoy logs (plugin event=heap_sample).
heap_ladder = {}
log_candidates = []
if envoy_log:
    log_candidates.append(Path(envoy_log))
for name in (
    "envoy-logs.txt",
    "envoy.log",
    "configure-stress-envoy.log",
    "heap-samples.log",
):
    log_candidates.append(out_dir / name)
for lp in log_candidates:
    heap_ladder = parse_heap_samples_from_log(lp)
    if heap_ladder:
        heap_ladder["source"] = str(lp)
        break

snapshot = {
    "envoy_before": load_envoy("before"),
    "envoy_after": load_envoy("after"),
    "modsecurity_before": modsec_before,
    "modsecurity_after": modsec_after,
    # Prefer explicit names used by recovery plan / release compare.
    "wasm_heap_after_configure": modsec_before.get("wasm_heap_bytes"),
    "wasm_heap_after_k6": modsec_after.get("wasm_heap_bytes"),
    "wasm_linear_memory": wasm_linear,
    "configure_heap_ladder": heap_ladder,
    "peak_container": peak,
    "container_after": container_after or {},
}
(out_dir / "memory-snapshot.json").write_text(
    json.dumps(snapshot, indent=2) + "\n",
    encoding="utf-8",
)
print(
    "memory-snapshot:",
    json.dumps(
        {
            "initial_memory_mb": (wasm_linear.get("initial_memory_bytes") or 0) / (1024 * 1024)
            if wasm_linear
            else None,
            "wasm_heap_after_configure_mb": (modsec_before.get("wasm_heap_bytes") or 0) / (1024 * 1024)
            if modsec_before.get("wasm_heap_bytes")
            else None,
            "wasm_heap_after_k6_mb": (modsec_after.get("wasm_heap_bytes") or 0) / (1024 * 1024)
            if modsec_after.get("wasm_heap_bytes")
            else None,
            "peak_configure_heap_mb": (heap_ladder.get("peak_wasm_heap_bytes") or 0) / (1024 * 1024)
            if heap_ladder.get("peak_wasm_heap_bytes")
            else None,
        }
    ),
)
PY
