# Performance tests (k6)

Load-test modsec-wasm-plugin through Envoy with [Grafana k6](https://k6.io/), with **[coraza-proxy-wasm](https://github.com/corazawaf/coraza-proxy-wasm)** as a reference WAF on the same Envoy stack.

## Prerequisites

- `docker` or `podman` (+ compose)
- `dist/modsec.wasm` (`make image` then `make extract-wasm`, or `make modsec.wasm`)
- `curl`, `unzip`, `sha256sum` (to fetch coraza wasm on first compare run)
- Ports `18080` (HTTP) and `19901` (admin) free

Coraza wasm is downloaded automatically to `test/perf/.coraza/main.wasm` (pinned in `test/perf/versions.env`).

## Quick start

```bash
# modsec full CRS only
make test-perf-k6

# Side-by-side: modsec-full vs coraza-full (same scenario)
make test-perf-k6-compare

# coraza only
PERF_PROFILE=coraza-full make test-perf-k6

# Floor (no Wasm)
PERF_PROFILE=baseline make test-perf-k6
```

## Profiles

| Profile | WAF | Config | Pairs with |
|---------|-----|--------|------------|
| `baseline` | none | Envoy router only | — |
| `wasm-minimal` | modsec-wasm | `SecRuleEngine Off` | `coraza-minimal` |
| `modsec-full` | modsec-wasm | Full CRS, debug off | `coraza-full` |
| `coraza-minimal` | coraza-proxy-wasm | `SecRuleEngine Off` | `wasm-minimal` |
| `coraza-full` | coraza-proxy-wasm | Embedded CRS v4.14, debug off | `modsec-full` |

Configs: `test/perf/profiles/`.

**Note:** CRS versions differ (modsec pins v4.27 at build time; coraza 0.6.0 embeds v4.14). Treat comparisons as directional, not byte-identical.

## Compare modsec vs coraza

```bash
# Default pair: modsec-full vs coraza-full, benign GET
make test-perf-k6-compare

# Minimal Wasm ABI tax comparison
PERF_PROFILE=wasm-minimal make test-perf-k6-compare

# POST bodies
PERF_SCENARIO=benign-post-1k make test-perf-k6-compare

# Blocking path
PERF_SCENARIO=block-xss make test-perf-k6-compare
```

`--compare` runs both profiles back-to-back and prints a latency/RPS table via `compare-summaries.py`.

## CI smoke

```bash
make test-perf-k6-ci
```

Runs on every PR/push via GitHub Actions job `perf` in [`.github/workflows/test.yml`](../../.github/workflows/test.yml). Results are uploaded as the `perf-results` artifact.

CI settings (`PERF_CI=1`): 30s measured, 10s warmup, 16 VUs, p99 threshold 500ms (relaxed for shared 2-vCPU runners).

Smoke sequence:

1. `baseline` / `benign-get`
2. `wasm-minimal` vs `coraza-minimal` / `benign-get`
3. `modsec-full` vs `coraza-full` / `benign-get`
4. `modsec-full` vs `coraza-full` / `benign-post-1k`

## Scenarios

| Scenario | Traffic |
|----------|---------|
| `benign-get` | `GET /` → 200 |
| `benign-post-1k` | `POST /api/user` 1 KB JSON → 200 |
| `block-xss` | `GET /?q=<script>…` → 403 |
| `mixed` | 95% allow / 5% block |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PERF_PROFILE` | `modsec-full` | Envoy profile |
| `PERF_SCENARIO` | `benign-get` | k6 script name |
| `PERF_VUS` | `32` | Virtual users |
| `PERF_DURATION` | `60s` | Measured run |
| `PERF_WARMUP` | `15s` | Warmup (`0` to skip) |
| `PERF_P99_MS` | `200` | k6 p99 threshold |
| `PERF_HOST_PORT` | `18080` | HTTP port |
| `PERF_ADMIN_PORT` | `19901` | Admin port |
| `ENVOY_IMAGE` | `envoyproxy/envoy:v1.38-latest` | Envoy pin |

Coraza pin: `test/perf/versions.env` (`CORAZA_VERSION`, `CORAZA_ZIP_SHA256`).

## Output

Each run: `test/perf/results/run-<timestamp>-<profile>-<scenario>/`

- `k6-summary.json`, `k6-stdout.txt`, **`k6-report.html`** (small self-contained HTML)
- `k6-compare.html` (after `--compare` / CI smoke pairs)
- `envoy-stats-*.txt`, `envoy-prometheus-*.txt`
- `modsec-wasm-metrics-*.txt` (modsec profiles)
- `coraza-wasm-metrics-*.txt` (coraza profiles — `waf_filter_tx_*`)

Open a report locally:

```bash
xdg-open test/perf/results/run-*/k6-report.html
xdg-open test/perf/release-charts/perf-modsec-full-benign-get.png
```

## PNG charts (release)

```bash
pip install -r test/perf/requirements-charts.txt
make test-perf-charts          # bundle PNGs into test/perf/release-charts/
make test-perf-release         # smoke perf + chart bundle
```

**Release publish:** pushing a `v*` tag runs [`.github/workflows/release.yml`](../../.github/workflows/release.yml), which:

1. Builds and attaches `modsec.wasm` + SHA256
2. Runs k6 perf smoke and renders PNG charts
3. Publishes charts to the GitHub Release (embedded in release notes)

## Fetch coraza wasm manually

```bash
./test/perf/fetch-coraza-wasm.sh
```