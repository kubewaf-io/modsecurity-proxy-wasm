#!/usr/bin/env python3
"""Render small PNG charts from k6 --summary-export JSON."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RUN_DIR_RE = re.compile(r"^run-(?P<stamp>[0-9TZ]+)-(?P<profile>.+)-(?P<scenario>.+)$")

COMPARE_PAIRS = (
    ("wasm-minimal", "coraza-minimal", "benign-get"),
    ("modsec-full", "coraza-full", "benign-get"),
    ("modsec-full", "coraza-full", "benign-post-1k"),
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
    m = RUN_DIR_RE.match(path.name)
    if not m:
        return None
    return m.group("stamp"), m.group("profile"), m.group("scenario")


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


def bundle(results_root: Path, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    seen: set[tuple[str, str]] = set()
    for child in sorted(results_root.iterdir(), key=lambda p: p.name, reverse=True):
        if not child.is_dir():
            continue
        parsed = parse_run_dir(child)
        if not parsed:
            continue
        _, profile, scenario = parsed
        key = (profile, scenario)
        if key in seen:
            continue
        summary = child / "k6-summary.json"
        if not summary.is_file():
            continue
        seen.add(key)
        out = output_dir / f"perf-{profile}-{scenario}.png"
        render_single(load_summary(summary), f"{profile} / {scenario}", out)
        written.append(out)
        print(f"==> Wrote {out}")

    for left_p, right_p, scenario in COMPARE_PAIRS:
        left_dir = find_latest_run(results_root, left_p, scenario)
        right_dir = find_latest_run(results_root, right_p, scenario)
        if not left_dir or not right_dir:
            continue
        left_summary = left_dir / "k6-summary.json"
        right_summary = right_dir / "k6-summary.json"
        if not left_summary.is_file() or not right_summary.is_file():
            continue
        out = output_dir / f"perf-compare-{left_p}-vs-{right_p}-{scenario}.png"
        render_compare(
            load_summary(left_summary),
            load_summary(right_summary),
            left_p,
            right_p,
            f"{left_p} vs {right_p} ({scenario})",
            out,
        )
        written.append(out)
        print(f"==> Wrote {out}")

    return written


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

    bundle_p = sub.add_parser("bundle", help="Chart latest runs under results/")
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
    else:
        bundle(args.results_root, args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())