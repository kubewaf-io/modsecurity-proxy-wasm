#!/usr/bin/env python3
"""Render small PNG charts from k6 --summary-export JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

VALID_PROFILES = (
    "baseline",
    "wasm-minimal",
    "modsecurity-proxy-wasm-full",
    "coraza-minimal",
    "coraza-full",
)
VALID_SCENARIOS = ("benign-get", "benign-post-1k", "block-xss", "mixed")

# Preferred legend order (CI smoke first, then extras).
TEST_ORDER = [
    ("baseline", "benign-get"),
    ("wasm-minimal", "benign-get"),
    ("coraza-minimal", "benign-get"),
    ("modsecurity-proxy-wasm-full", "benign-get"),
    ("coraza-full", "benign-get"),
    ("modsecurity-proxy-wasm-full", "benign-post-1k"),
    ("coraza-full", "benign-post-1k"),
    ("modsecurity-proxy-wasm-full", "block-xss"),
    ("coraza-full", "block-xss"),
    ("modsecurity-proxy-wasm-full", "mixed"),
    ("coraza-full", "mixed"),
]

OVERLAY_METRICS = ("p50", "p90", "p95", "p99")
OVERLAY_COLORS = (
    "#8b9cb3",
    "#3d8bfd",
    "#f0883e",
    "#2ea043",
    "#a371f7",
    "#ff7b72",
    "#79c0ff",
    "#d29922",
    "#56d364",
    "#ffa657",
    "#bc8cff",
)


def load_summary(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def metric_ms(data: dict, name: str, key: str) -> float | None:
    entry = data.get("metrics", {}).get(name)
    if not entry or key not in entry:
        return None
    return float(entry[key])


def metric_rate(data: dict, name: str) -> float | None:
    entry = data.get("metrics", {}).get(name)
    if not entry:
        return None
    if "rate" in entry:
        return float(entry["rate"])
    if "count" in entry and "rate" not in entry:
        return None
    return None


def metric_count(data: dict, name: str) -> float | None:
    entry = data.get("metrics", {}).get(name)
    if not entry:
        return None
    if "count" in entry:
        return float(entry["count"])
    return None


def latency_stats(data: dict) -> dict[str, float | None]:
    dur = "http_req_duration"
    return {
        "p50": metric_ms(data, dur, "med"),
        "p90": metric_ms(data, dur, "p(90)"),
        "p95": metric_ms(data, dur, "p(95)"),
        "p99": metric_ms(data, dur, "p(99)"),
        "avg": metric_ms(data, dur, "avg"),
    }


def apply_style() -> None:
    plt.style.use("dark_background")
    plt.rcParams.update(
        {
            "figure.facecolor": "#0f1419",
            "axes.facecolor": "#1a2332",
            "axes.edgecolor": "#2d3a4f",
            "axes.labelcolor": "#8b9cb3",
            "text.color": "#e7ecf3",
            "xtick.color": "#8b9cb3",
            "ytick.color": "#8b9cb3",
            "grid.color": "#2d3a4f",
            "font.size": 10,
        }
    )


def render_single(summary: dict, title: str, output: Path) -> None:
    apply_style()
    lat = latency_stats(summary)
    labels = [k for k in ("p50", "p90", "p95", "p99") if lat[k] is not None]
    values = [lat[k] for k in labels]

    rps = metric_rate(summary, "http_reqs")
    reqs = metric_count(summary, "http_reqs")
    fail = metric_rate(summary, "http_req_failed")
    checks = summary.get("metrics", {}).get("checks", {}).get("value")

    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=120)
    bars = ax.bar(labels, values, color="#3d8bfd", edgecolor="#2d3a4f", linewidth=0.8)
    ax.set_ylabel("latency (ms)")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.grid(axis="y", alpha=0.35)
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{val:.2f}",
            ha="center",
            va="bottom",
            fontsize=8,
            color="#e7ecf3",
        )

    fail_pct = f"{fail * 100:.2f}%" if fail is not None else "n/a"
    checks_pct = f"{checks * 100:.1f}%" if checks is not None else "n/a"
    caption = (
        f"RPS {rps:,.0f}  ·  requests {reqs:,.0f}  ·  failed {fail_pct}  ·  checks {checks_pct}"
        if rps is not None and reqs is not None
        else "k6 summary"
    )
    fig.text(0.5, 0.02, caption, ha="center", fontsize=9, color="#8b9cb3")
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def render_overlay(
    series: list[tuple[str, dict]],
    title: str,
    output: Path,
) -> None:
    apply_style()
    x = list(range(len(OVERLAY_METRICS)))

    fig, ax = plt.subplots(figsize=(10, 6), dpi=120)
    plotted = 0
    for i, (name, summary) in enumerate(series):
        lat = latency_stats(summary)
        values = [lat[key] for key in OVERLAY_METRICS]
        if not any(v is not None for v in values):
            continue
        y = [float(v) if v is not None else 0.0 for v in values]
        color = OVERLAY_COLORS[i % len(OVERLAY_COLORS)]
        ax.plot(
            x,
            y,
            marker="o",
            label=name,
            color=color,
            linewidth=2,
            markersize=5,
            alpha=0.9,
        )
        plotted += 1

    if plotted == 0:
        raise ValueError("no latency data to plot")

    ax.set_xticks(x)
    ax.set_xticklabels(list(OVERLAY_METRICS))
    ax.set_ylabel("latency (ms)")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.legend(loc="upper left", fontsize=8, ncol=2, framealpha=0.85)
    ax.grid(axis="y", alpha=0.35)
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def render_compare(
    left: dict,
    right: dict,
    left_label: str,
    right_label: str,
    title: str,
    output: Path,
) -> None:
    apply_style()
    ll = latency_stats(left)
    rl = latency_stats(right)
    lrps = metric_rate(left, "http_reqs")
    rrps = metric_rate(right, "http_reqs")

    metrics = ["p50", "p90", "p95", "RPS"]
    left_vals = [ll["p50"], ll["p90"], ll["p95"], lrps]
    right_vals = [rl["p50"], rl["p90"], rl["p95"], rrps]

    x = range(len(metrics))
    width = 0.36
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=120)
    ax.bar([i - width / 2 for i in x], left_vals, width, label=left_label, color="#3d8bfd")
    ax.bar([i + width / 2 for i in x], right_vals, width, label=right_label, color="#f0883e")
    ax.set_xticks(list(x))
    ax.set_xticklabels(metrics)
    ax.set_ylabel("ms (RPS for last bar)")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=12)
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(axis="y", alpha=0.35)
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    plt.close(fig)


def parse_run_dir(path: Path) -> tuple[str, str, str] | None:
    name = path.name
    if not name.startswith("run-"):
        return None
    rest = name[4:]
    for scenario in VALID_SCENARIOS:
        suffix = f"-{scenario}"
        if not rest.endswith(suffix):
            continue
        middle = rest[: -len(suffix)]
        for profile in VALID_PROFILES:
            profile_suffix = f"-{profile}"
            if middle.endswith(profile_suffix):
                stamp = middle[: -len(profile_suffix)]
                if stamp:
                    return stamp, profile, scenario
    return None


def test_sort_key(profile: str, scenario: str) -> tuple[int, str, str]:
    key = (profile, scenario)
    try:
        return (TEST_ORDER.index(key), profile, scenario)
    except ValueError:
        return (len(TEST_ORDER), profile, scenario)


def test_label(profile: str, scenario: str) -> str:
    return f"{profile} / {scenario}"


def find_latest_run(results_root: Path, profile: str, scenario: str) -> Path | None:
    matches = []
    for child in results_root.iterdir():
        if not child.is_dir():
            continue
        parsed = parse_run_dir(child)
        if parsed and parsed[1] == profile and parsed[2] == scenario:
            matches.append(child)
    if not matches:
        return None
    return sorted(matches, key=lambda p: p.name, reverse=True)[0]


def collect_latest_summaries(results_root: Path) -> list[tuple[str, str, dict]]:
    latest: dict[tuple[str, str], tuple[str, dict]] = {}
    for child in results_root.iterdir():
        if not child.is_dir():
            continue
        parsed = parse_run_dir(child)
        if not parsed:
            continue
        stamp, profile, scenario = parsed
        summary = child / "k6-summary.json"
        if not summary.is_file():
            continue
        key = (profile, scenario)
        prev = latest.get(key)
        if prev is None or stamp > prev[0]:
            latest[key] = (stamp, load_summary(summary))

    ordered = sorted(latest, key=lambda k: test_sort_key(k[0], k[1]))
    return [(test_label(profile, scenario), latest[(profile, scenario)][1]) for profile, scenario in ordered]


def bundle(results_root: Path, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    for old in output_dir.glob("perf-*.png"):
        if old.name != "perf-overlay.png":
            old.unlink()
    series = collect_latest_summaries(results_root)
    if not series:
        print("WARN: no k6-summary.json files found under results/", file=sys.stderr)
        return []

    out = output_dir / "perf-overlay.png"
    render_overlay(series, "k6 perf — all tests", out)
    print(f"==> Wrote {out} ({len(series)} series)")
    return [out]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    single = sub.add_parser("single", help="Chart one k6-summary.json")
    single.add_argument("summary", type=Path)
    single.add_argument("-o", "--output", type=Path, required=True)
    single.add_argument("--title", default="k6 perf")

    compare = sub.add_parser("compare", help="Chart two summaries")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    compare.add_argument("-o", "--output", type=Path, required=True)
    compare.add_argument("--left-label", default="left")
    compare.add_argument("--right-label", default="right")
    compare.add_argument("--title", default="k6 compare")

    overlay_p = sub.add_parser("overlay", help="Overlay multiple k6-summary.json files")
    overlay_p.add_argument("summaries", nargs="+", type=Path)
    overlay_p.add_argument("-o", "--output", type=Path, required=True)
    overlay_p.add_argument("--title", default="k6 perf — all tests")

    bundle_p = sub.add_parser("bundle", help="Overlay chart from latest runs under results/")
    bundle_p.add_argument("results_root", type=Path)
    bundle_p.add_argument("-o", "--output", type=Path, required=True)

    args = parser.parse_args()

    if args.cmd == "single":
        render_single(load_summary(args.summary), args.title, args.output)
        print(f"==> Wrote {args.output}")
    elif args.cmd == "compare":
        render_compare(
            load_summary(args.left),
            load_summary(args.right),
            args.left_label,
            args.right_label,
            args.title,
            args.output,
        )
        print(f"==> Wrote {args.output}")
    elif args.cmd == "overlay":
        series = []
        for path in args.summaries:
            parsed = parse_run_dir(path.parent)
            label = (
                test_label(parsed[1], parsed[2])
                if parsed
                else path.parent.name.removeprefix("run-")
            )
            series.append((label, load_summary(path)))
        render_overlay(series, args.title, args.output)
        print(f"==> Wrote {args.output}")
    else:
        bundle(args.results_root, args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())