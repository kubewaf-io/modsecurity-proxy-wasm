"""Envoy and container memory helpers for perf runs."""

from __future__ import annotations

import json
import re
from pathlib import Path

PROM_MEMORY_KEYS = {
    "envoy_server_memory_allocated": "allocated_bytes",
    "envoy_server_memory_heap_size": "heap_size_bytes",
    "envoy_server_memory_physical_size": "physical_size_bytes",
}

MODSECURITY_MEMORY_KEYS = {
    "modsecurity_proxy_wasm_memory_wasm_heap_bytes": "wasm_heap_bytes",
}

# Wasm page size (linear memory unit).
WASM_PAGE_BYTES = 64 * 1024


def _parse_prometheus_gauges(path: Path, key_map: dict[str, str]) -> dict[str, int]:
    out: dict[str, int] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        for prom_key, field in key_map.items():
            if line.startswith(f"{prom_key}{{") or line.startswith(f"{prom_key} "):
                try:
                    out[field] = int(float(line.rsplit(" ", 1)[-1]))
                except ValueError:
                    pass
                break
    return out


def parse_prometheus_memory(path: Path) -> dict[str, int]:
    return _parse_prometheus_gauges(path, PROM_MEMORY_KEYS)


def parse_modsecurity_memory(path: Path) -> dict[str, int]:
    return _parse_prometheus_gauges(path, MODSECURITY_MEMORY_KEYS)


def _read_leb128(data: bytes, offset: int) -> tuple[int, int]:
    """Return (value, new_offset) for an unsigned LEB128 integer."""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, offset
        shift += 7
        if shift > 35:
            break
    raise ValueError("truncated LEB128")


def parse_wasm_linear_memory(path: Path | str | None) -> dict[str, int]:
    """Parse the Memory section of a .wasm binary into byte limits.

    Returns keys:
      initial_memory_bytes, maximum_memory_bytes (0 if unbounded),
      initial_memory_pages, maximum_memory_pages
    Empty dict if path missing or unparseable.
    """
    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    data = p.read_bytes()
    if len(data) < 8 or data[:4] != b"\x00asm":
        return {}
    offset = 8  # magic + version
    try:
        while offset < len(data):
            section_id = data[offset]
            offset += 1
            section_size, offset = _read_leb128(data, offset)
            section_end = offset + section_size
            if section_id == 5:  # Memory section
                count, offset = _read_leb128(data, offset)
                if count < 1:
                    return {}
                flags = data[offset]
                offset += 1
                initial_pages, offset = _read_leb128(data, offset)
                max_pages = 0
                if flags & 0x01:
                    max_pages, offset = _read_leb128(data, offset)
                return {
                    "initial_memory_pages": initial_pages,
                    "maximum_memory_pages": max_pages,
                    "initial_memory_bytes": initial_pages * WASM_PAGE_BYTES,
                    "maximum_memory_bytes": max_pages * WASM_PAGE_BYTES if max_pages else 0,
                }
            offset = section_end
    except (ValueError, IndexError):
        return {}
    return {}


def parse_heap_samples_from_log(path: Path | str | None) -> dict:
    """Extract heap_sample / config_applied stages from Envoy plugin logs.

    Looks for JSON lines with \"event\":\"heap_sample\" or config_applied that
    carry wasm_heap_bytes. Returns peak + per-stage map.
    """
    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    stages: dict[str, int] = {}
    peak = 0
    # Match both pretty and compact JSON fragments in Envoy log lines.
    stage_re = re.compile(
        r'"event"\s*:\s*"(heap_sample|config_applied|configure_start|crs_data_ready|rules_loaded)"'
    )
    heap_re = re.compile(r'"wasm_heap_bytes"\s*:\s*(\d+)')
    stage_name_re = re.compile(r'"stage"\s*:\s*"([^"]+)"')
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if "wasm_heap_bytes" not in line:
            continue
        if not stage_re.search(line) and '"event"' not in line:
            continue
        hm = heap_re.search(line)
        if not hm:
            continue
        heap = int(hm.group(1))
        peak = max(peak, heap)
        sm = stage_name_re.search(line)
        if sm:
            stages[sm.group(1)] = heap
        else:
            em = re.search(r'"event"\s*:\s*"([^"]+)"', line)
            if em:
                stages[em.group(1)] = heap
    out: dict = {}
    if peak:
        out["peak_wasm_heap_bytes"] = peak
    if stages:
        out["stages"] = stages
    return out


def parse_docker_mem_usage(value: str) -> tuple[int | None, int | None]:
    """Parse '123.4MiB / 2GiB' into (used_bytes, limit_bytes)."""
    parts = [p.strip() for p in value.split("/")]
    if len(parts) != 2:
        return None, None
    return parse_byte_quantity(parts[0]), parse_byte_quantity(parts[1])


def parse_byte_quantity(raw: str) -> int | None:
    raw = raw.strip()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?i?B)", raw, re.IGNORECASE)
    if not match:
        return None
    amount = float(match.group(1))
    unit = match.group(2).upper()
    mult = {
        "B": 1,
        "KIB": 1024,
        "MIB": 1024**2,
        "GIB": 1024**3,
        "TIB": 1024**4,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
    }.get(unit)
    if mult is None:
        return None
    return int(amount * mult)


def peak_from_samples(path: Path) -> dict[str, int | None]:
    peak_used = 0
    peak_limit: int | None = None
    if not path.is_file():
        return {"container_rss_bytes": None, "container_limit_bytes": None}
    for line in path.read_text(encoding="utf-8").splitlines():
        used, limit = parse_docker_mem_usage(line)
        if used is not None:
            peak_used = max(peak_used, used)
        if limit is not None:
            peak_limit = limit
    return {
        "container_rss_bytes": peak_used or None,
        "container_limit_bytes": peak_limit,
    }


def load_run_memory(run_dir: Path) -> dict:
    snapshot = run_dir / "memory-snapshot.json"
    if snapshot.is_file():
        with snapshot.open(encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        after_prom = run_dir / "envoy-prometheus-after.txt"
        peak = peak_from_samples(run_dir / "memory-samples.log")
        data = {
            "envoy_after": parse_prometheus_memory(after_prom),
            "peak_container": peak,
        }

    modsec_path = run_dir / "modsecurity-proxy-wasm-memory-after.txt"
    if not modsec_path.is_file():
        modsec_path = run_dir / "envoy-prometheus-after.txt"
    modsec = parse_modsecurity_memory(modsec_path)
    if modsec:
        data["modsecurity_after"] = modsec
    return data


def memory_mb(snapshot: dict) -> dict[str, float | None]:
    envoy = snapshot.get("envoy_after") or snapshot.get("after", {}).get("envoy", {})
    modsec = snapshot.get("modsecurity_after") or snapshot.get("after", {}).get("modsecurity", {})
    modsec_before = snapshot.get("modsecurity_before") or {}
    peak = snapshot.get("peak_container") or snapshot.get("peak", {})
    linear = snapshot.get("wasm_linear_memory") or {}
    allocated = envoy.get("allocated_bytes")
    physical = envoy.get("physical_size_bytes")
    rss = peak.get("container_rss_bytes")
    wasm_heap = modsec.get("wasm_heap_bytes")
    wasm_heap_before = modsec_before.get("wasm_heap_bytes")
    initial = linear.get("initial_memory_bytes")
    return {
        "envoy_allocated_mb": allocated / (1024 * 1024) if allocated else None,
        "envoy_physical_mb": physical / (1024 * 1024) if physical else None,
        "container_peak_rss_mb": rss / (1024 * 1024) if rss else None,
        "modsecurity_wasm_heap_mb": wasm_heap / (1024 * 1024) if wasm_heap else None,
        "modsecurity_wasm_heap_before_mb": (
            wasm_heap_before / (1024 * 1024) if wasm_heap_before else None
        ),
        "wasm_initial_memory_mb": initial / (1024 * 1024) if initial else None,
    }