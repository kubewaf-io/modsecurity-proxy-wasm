# Tests

| Directory | Purpose |
|-----------|---------|
| [fixtures/](fixtures/) | Envoy YAML and default WAF JSON configs |
| [integration/](integration/) | Bats smoke, getentropy/V8 checks, **configure-stress** heap gate |
| [regression/](regression/) | CRS go-ftw regression (`run-ftw.sh`, `ftw/`) |
| [unit/](unit/) | Native gtest for `waf_config` |
| [fuzz/](fuzz/) | libFuzzer smoke on config parsing |
| [perf/](perf/) | k6 load tests, memory-snapshot, chart rendering |

Run from repo root:

```bash
make test-unit
make test-bats
make test-configure-stress   # Path B gzip + chains + @pmFromFile; prints heap_sample ladder
make test-regression                         # Path B CRS go-ftw (generates gzip SecLang)
FTW_INCLUDE='^941.*' make test-regression    # XSS suite subset (CI)

# Speed knobs (defaults already CI-tuned):
#   FTW_RATE_LIMIT=100ms FTW_MAX_MARKER_RETRIES=20 FTW_MARKER_SETTLE=2
# Raise retries if markers flake; lower rate only if logs are proven fast.
```


### Configure stress / memory ladder (WS0–M1)

Default link floor is **32 MiB** (`INITIAL_MEMORY`, growth to 512 MiB).
Plugin logs emit `"event":"heap_sample"` with `stage` + `wasm_heap_bytes` during
`onConfigure`. Re-run the gate before changing the floor:

```bash
make modsecurity-proxy-wasm.wasm
make test-configure-stress
# Harder: SCORE_RULES=300 CONFIGURE_HEAP_BUDGET_BYTES=33554432 make test-configure-stress
# Raise floor if production Path B OOMs:
#   INITIAL_MEMORY=64MB make modsecurity-proxy-wasm.wasm
```

Results: `test/integration/.configure-stress/out/memory-snapshot.json` and
`configure-stress-envoy.log`.

### Path B CRS configure soak (memory truth)

Loads **real** OWASP CRS rule confs as gzip Path B SecLang (operator shape),
under Envoy V8, and records the `heap_sample` ladder vs `INITIAL_MEMORY`:

```bash
make deps   # ensures .cache/deps/crs
make modsecurity-proxy-wasm.wasm
make test-configure-crs-soak                    # REQUEST-*.conf (default)
CRS_SOAK_PROFILE=full make test-configure-crs-soak
CONFIGURE_HEAP_BUDGET_BYTES=33554432 make test-configure-crs-soak
```

Report: `test/integration/.configure-crs-soak/out/crs-soak-report.json`
(`memory_grew_above_initial`, peak heap, CRS directive counts).

### Latency knobs (plugin JSON)

```json
{
  "transforms": { "fullwidth_normalize": true },
  "metrics": {
    "enabled": true,
    "per_rule_id": false,
    "rule_tags": false,
    "dual_prefix": false
  }
}
```

- **fullwidth_normalize** (default **true**): fold fullwidth Unicode / `%EF%BC` in path, headers, bodies for CRS XSS. Set `false` on latency-only profiles.
- **metrics**: slim defaults (`per_rule_id` / `rule_tags` / `dual_prefix` off). kubeWAF identity auto-enables `dual_prefix` unless set explicitly to `false`.