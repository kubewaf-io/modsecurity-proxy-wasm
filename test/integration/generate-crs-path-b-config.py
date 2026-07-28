#!/usr/bin/env python3
"""Build a Path B (inline SecLang) plugin config from a local OWASP CRS tree.

Emits the same shape kubeWAF uses in production:
  Include @kubewaf-defaults + CRS setup marker + flattened rule confs
  (gzip+base64 by default). CRS rule confs are NOT embedded in the wasm;
  @pmFromFile basenames resolve via the path-b catalog.

Profiles
--------
  request  REQUEST-*.conf only (default) — request-path CRS like most edge WAFs
  full     all rules/*.conf including RESPONSE-*

Usage
-----
  python3 test/integration/generate-crs-path-b-config.py \\
    --crs .cache/deps/crs \\
    --profile request \\
    --out-json /tmp/crs-path-b.json \\
    --out-envoy /tmp/crs-path-b-envoy.yaml
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import re
import sys
from pathlib import Path

# CRS numerical setup version for v4.27.0 (see crs-setup.conf.example).
CRS_SETUP_VERSION = 4270

# Directives that need a real filesystem or are unsupported in wasm.
_SKIP_PREFIXES = (
    "SecUnicodeMapFile",
    "SecGeoLookupDb",
    "SecAuditLog ",
    "SecAuditLogStorageDir",
    "SecDebugLog ",
    "SecTmpDir ",  # set by @kubewaf-defaults
    "SecDataDir ",
)


def flatten_seclang(text: str) -> list[str]:
    """Join backslash-continued CRS lines into single physical directives."""
    out: list[str] = []
    buf: list[str] = []
    for raw in text.splitlines():
        s = raw.rstrip()
        stripped = s.strip()
        if not buf:
            if not stripped or stripped.startswith("#"):
                continue
        if s.endswith("\\"):
            buf.append(s[:-1].rstrip())
            continue
        buf.append(s)
        # Collapse internal whitespace runs from indent continuations.
        joined = " ".join(part.strip() for part in buf if part.strip())
        # Normalize "id:123,\ phase" spacing left by CRS multi-line actions.
        joined = re.sub(r",\s+", ",", joined)
        out.append(joined)
        buf = []
    if buf:
        joined = " ".join(part.strip() for part in buf if part.strip())
        joined = re.sub(r",\s+", ",", joined)
        out.append(joined)
    return out


def should_skip_line(line: str) -> bool:
    s = line.strip()
    if not s or s.startswith("#"):
        return True
    for p in _SKIP_PREFIXES:
        if s.startswith(p) or s.startswith(p.strip()):
            return True
    if "@rxFromFile" in s:
        return True
    if s.startswith("Include "):
        # Path B: operator supplies rules; nested Includes are not resolved.
        return True
    return False


def load_conf_directives(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [ln for ln in flatten_seclang(text) if not should_skip_line(ln)]


def crs_setup_directives() -> list[str]:
    """Minimal setup so REQUEST-901 does not 500 on missing crs_setup_version."""
    return [
        # Marker required by REQUEST-901-INITIALIZATION (rule 901001).
        (
            'SecAction "id:900990,phase:1,pass,nolog,t:none,'
            f'setvar:tx.crs_setup_version={CRS_SETUP_VERSION}"'
        ),
        # Explicit PL1 + thresholds (901 also defaults these if unset).
        (
            'SecAction "id:900000,phase:1,pass,nolog,t:none,'
            "setvar:tx.blocking_paranoia_level=1,"
            "setvar:tx.detection_paranoia_level=1,"
            "setvar:tx.inbound_anomaly_score_threshold=5,"
            'setvar:tx.outbound_anomaly_score_threshold=4"'
        ),
        'SecDefaultAction "phase:1,log,auditlog,pass"',
        'SecDefaultAction "phase:2,log,auditlog,pass"',
        'SecDefaultAction "phase:3,log,auditlog,pass"',
        'SecDefaultAction "phase:4,log,auditlog,pass"',
        'SecDefaultAction "phase:5,log,auditlog,pass"',
    ]


def select_conf_files(rules_dir: Path, profile: str) -> list[Path]:
    confs = sorted(
        p
        for p in rules_dir.glob("*.conf")
        if p.is_file() and ".example" not in p.name
    )
    if profile == "full":
        return confs
    if profile == "request":
        return [p for p in confs if p.name.startswith("REQUEST-")]
    raise ValueError(f"unknown profile: {profile}")


def build_directives(crs: Path, profile: str, preset: str = "default") -> tuple[list[str], dict]:
    rules_dir = crs / "rules"
    if not rules_dir.is_dir():
        raise FileNotFoundError(f"missing CRS rules dir: {rules_dir}")

    confs = select_conf_files(rules_dir, profile)
    if not confs:
        raise FileNotFoundError(f"no rule confs for profile={profile} under {rules_dir}")

    if preset == "ftw":
        # Engine-local go-ftw: catalog helpers + PL4 DetectionOnly marker + full CRS.
        directives: list[str] = [
            "Include @demo-conf",
            "Include @ftw-conf",
            "SecRuleEngine On",
        ]
    elif preset == "default":
        directives = [
            "Include @kubewaf-defaults",
            "SecRuleEngine On",
            "SecDebugLogLevel 0",
        ]
    else:
        raise ValueError(f"unknown preset: {preset}")

    directives.extend(crs_setup_directives())

    stats: dict = {
        "profile": profile,
        "preset": preset,
        "conf_files": [],
        "pm_from_file_refs": 0,
        "directive_count": 0,
    }
    for path in confs:
        lines = load_conf_directives(path)
        pm = sum(1 for ln in lines if "@pmFromFile" in ln)
        stats["conf_files"].append(
            {"name": path.name, "directives": len(lines), "pm_from_file": pm}
        )
        stats["pm_from_file_refs"] += pm
        directives.append(f"# --- CRS {path.name} ---")
        directives.extend(lines)

    stats["directive_count"] = len(
        [d for d in directives if d.strip() and not d.strip().startswith("#")]
    )
    stats["total_lines"] = len(directives)
    return directives, stats


def _indent_block(text: str, spaces: int) -> str:
    """Indent every line of text for a YAML | block scalar (must exceed key indent)."""
    pad = " " * spaces
    return "\n".join(pad + (line if line else "") for line in text.splitlines())


def write_envoy_yaml(plugin_json: str, out: Path, vm_id: str, layout: str = "soak") -> None:
    """Write Envoy YAML with plugin_json embedded under the Wasm filter config."""
    if layout == "ftw":
        # value: | sits at 26 spaces; content must be deeper (28+).
        indented = _indent_block(plugin_json, 28)
        # Matches test/regression/ftw/envoy.yaml topology (albedo upstream, HTTP/1.0).
        yaml = f"""# Generated by generate-crs-path-b-config.py — Path B CRS for go-ftw.
# Do not edit by hand; regenerated by test/regression/run-ftw.sh.
static_resources:
  listeners:
    - address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                codec_type: AUTO
                http_protocol_options:
                  accept_http_10: true
                route_config:
                  virtual_hosts:
                    - name: local_route
                      domains:
                        - "*"
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: local_server
                http_filters:
                  - name: envoy.filters.http.wasm
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
                      config:
                        name: "modsecurity_proxy_wasm"
                        vm_config:
                          vm_id: "{vm_id}"
                          runtime: "envoy.wasm.runtime.v8"
                          code:
                            local:
                              filename: "/etc/modsecurity-proxy-wasm.wasm"
                        configuration:
                          "@type": "type.googleapis.com/google.protobuf.StringValue"
                          value: |
{indented}
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: local_server
      connect_timeout: 6000s
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: local_server
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: albedo
                      port_value: 8080

admin:
  access_log_path: /dev/null
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 9901
"""
    elif layout == "soak":
        # value: | sits at 18 spaces in soak template; content at 20.
        indented = _indent_block(plugin_json, 20)
        yaml = f"""# Generated by generate-crs-path-b-config.py — do not edit by hand.
# Path B CRS configure soak (gzip directives + @pmFromFile from catalog).
stats_config:
  stats_tags:
    - tag_name: phase
      regex: "(_phase=(http_request_headers|http_request_body|http_response_headers|http_response_body|http_logging|unknown))"
    - tag_name: owner
      regex: "(_owner=([0-9a-z.:_-]+?))(?:_|$)"
    - tag_name: identifier
      regex: "(_identifier=([0-9a-z.:_-]+))"

static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8080
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          codec_type: AUTO
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: local_backend
          http_filters:
          - name: envoy.filters.http.wasm
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
              config:
                name: "modsecurity_proxy_wasm"
                vm_config:
                  vm_id: "{vm_id}"
                  runtime: "envoy.wasm.runtime.v8"
                  code:
                    local:
                      filename: "/etc/modsecurity-proxy-wasm.wasm"
                configuration:
                  "@type": "type.googleapis.com/google.protobuf.StringValue"
                  value: |
{indented}
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  - name: backend_listener
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 19000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: backend_http
          codec_type: AUTO
          route_config:
            name: backend_route
            virtual_hosts:
            - name: backend
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                direct_response:
                  status: 200
                  body:
                    inline_string: "ok\\n"
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: local_backend
    connect_timeout: 1s
    type: STATIC
    load_assignment:
      cluster_name: local_backend
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 19000

admin:
  access_log_path: /dev/null
  address:
    socket_address:
      address: 0.0.0.0
      port_value: 9901
"""
    else:
        raise ValueError(f"unknown envoy layout: {layout}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--crs",
        type=Path,
        default=None,
        help="CRS checkout (default: <repo>/.cache/deps/crs)",
    )
    ap.add_argument(
        "--profile",
        choices=("request", "full"),
        default="request",
        help="request = REQUEST-*.conf only; full = all rules/*.conf",
    )
    ap.add_argument(
        "--preset",
        choices=("default", "ftw"),
        default="default",
        help="default = @kubewaf-defaults; ftw = @demo-conf + @ftw-conf (go-ftw)",
    )
    ap.add_argument("--out-json", type=Path, help="Plugin configuration JSON path")
    ap.add_argument("--out-envoy", type=Path, help="Envoy YAML path embedding the plugin JSON")
    ap.add_argument(
        "--envoy-layout",
        choices=("soak", "ftw"),
        default="soak",
        help="Envoy topology: soak (loopback backend) or ftw (albedo upstream)",
    )
    ap.add_argument(
        "--out-stats",
        type=Path,
        help="JSON stats about conf sizes / @pmFromFile counts",
    )
    ap.add_argument(
        "--plain",
        action="store_true",
        help="Emit plain JSON array (huge; debug only — prefer gzip)",
    )
    ap.add_argument(
        "--vm-id",
        default="modsecurity_proxy_wasm_crs_soak",
        help="Envoy wasm vm_id",
    )
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[2]
    crs = args.crs or (repo / ".cache" / "deps" / "crs")
    if not crs.is_dir():
        print(
            f"ERROR: CRS not found at {crs}. Build deps first (make deps) "
            "or pass --crs /path/to/coreruleset",
            file=sys.stderr,
        )
        return 1

    # FTW needs RESPONSE rules for many suites; default full when preset=ftw unless overridden.
    profile = args.profile
    if args.preset == "ftw" and args.profile == "request":
        # Explicit request still allowed; go-ftw typically wants full.
        pass

    try:
        directives, stats = build_directives(crs, profile, preset=args.preset)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    joined = "\n".join(directives) + "\n"
    if args.plain:
        plugin = {
            "directives_map": {"default": directives},
            "default_directives": "default",
            "metric_labels": {
                "owner": "modsecurity-proxy-wasm",
                "identifier": f"crs-soak-{args.profile}",
            },
            "metrics": {
                "enabled": True,
                "per_rule_id": False,
                "rule_tags": False,
                "dual_prefix": False,
            },
            "directives_stats": {
                "raw_bytes": len(joined),
                "compressed_bytes": len(joined),
                "profile": args.profile,
                "directive_count": stats["directive_count"],
            },
        }
    else:
        compressed = gzip.compress(joined.encode("utf-8"), mtime=0)
        b64 = base64.b64encode(compressed).decode("ascii")
        plugin = {
            "directives_encoding": "gzip+base64",
            "directives_map": {"default": b64},
            "default_directives": "default",
            "directives_stats": {
                "raw_bytes": len(joined),
                "compressed_bytes": len(compressed),
                "profile": args.profile,
                "directive_count": stats["directive_count"],
                "pm_from_file_refs": stats["pm_from_file_refs"],
                "conf_files": len(stats["conf_files"]),
            },
            "metric_labels": {
                "owner": "modsecurity-proxy-wasm",
                "identifier": f"crs-soak-{args.profile}",
            },
            "metrics": {
                "enabled": True,
                "per_rule_id": False,
                "rule_tags": False,
                "dual_prefix": False,
            },
        }

    plugin_json = json.dumps(plugin, indent=2)
    stats["raw_bytes"] = len(joined)
    if not args.plain:
        stats["compressed_bytes"] = plugin["directives_stats"]["compressed_bytes"]
    else:
        stats["compressed_bytes"] = len(joined)

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(plugin_json + "\n", encoding="utf-8")
        print(
            f"Wrote plugin JSON ({len(plugin_json)} bytes, "
            f"{stats['directive_count']} directives, "
            f"raw={stats['raw_bytes']} compressed={stats.get('compressed_bytes', '?')}) "
            f"-> {args.out_json}",
            file=sys.stderr,
        )
    if args.out_envoy:
        write_envoy_yaml(plugin_json, args.out_envoy, args.vm_id, layout=args.envoy_layout)
        print(f"Wrote Envoy YAML (layout={args.envoy_layout}) -> {args.out_envoy}", file=sys.stderr)
    if args.out_stats:
        args.out_stats.parent.mkdir(parents=True, exist_ok=True)
        args.out_stats.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote stats -> {args.out_stats}", file=sys.stderr)

    if not args.out_json and not args.out_envoy:
        print(plugin_json)

    print(
        f"CRS Path B profile={args.profile} confs={len(stats['conf_files'])} "
        f"directives={stats['directive_count']} pmFromFile={stats['pm_from_file_refs']} "
        f"raw_MiB={stats['raw_bytes'] / 1024 / 1024:.2f}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
