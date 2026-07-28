# modsecurity-proxy-wasm

ModSecurity [Proxy-Wasm](https://github.com/proxy-wasm/spec) filter for Envoy (`envoy.wasm.runtime.v8`) with embedded **OWASP CRS v4.27.0**.

**Full documentation (kubeWAF docs site):** [modsecurity-proxy-wasm](https://kubewaf.io/engines/modsecurity-proxy-wasm/) · [pow-proxy-wasm](https://kubewaf.io/engines/pow-proxy-wasm/) · [operator docs](https://kubewaf.io/docs/home/)

## Quick start

```bash
make image && make extract-wasm
make test-bats
```

```bash
podman run --rm \
  -v "$(pwd)/dist/modsecurity-proxy-wasm.wasm:/etc/modsecurity-proxy-wasm.wasm:ro" \
  -v "$(pwd)/test/fixtures/envoy.yaml:/etc/envoy.yaml:ro" \
  -p 8080:8080 envoyproxy/envoy:v1.38-latest envoy -c /etc/envoy.yaml
```

```bash
curl http://localhost:8080/                                      # 200
curl 'http://localhost:8080/?q=<script>alert(1)</script>'       # 403
```

## Features

**Envoy filter** — Emscripten wasm on the HTTP filter chain (`envoy.wasm.runtime.v8` only):

```yaml
http_filters:
- name: envoy.filters.http.wasm
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
    config:
      vm_config:
        runtime: envoy.wasm.runtime.v8
        code: { local: { filename: /etc/modsecurity-proxy-wasm.wasm } }
```

**WAF config** — JSON `directives_map` / `default_directives` profiles.
When driven by **kubeWAF**, the operator also sets `mode`, `config_id`, identity
`metric_labels`, nested `metrics`, and `block` (see
[`schemas/waf-plugin-config.json`](../schemas/waf-plugin-config.json)).

Large Path B SecLang lists are sent compressed:

```json
{
  "directives_encoding": "gzip+base64",
  "default_directives": "default",
  "directives_map": {
    "default": "<base64(gzip(joined SecLang lines))>"
  },
  "directives_stats": { "raw_bytes": 1200000, "compressed_bytes": 90000 }
}
```

The filter base64-decodes and gunzips on configure (32 MiB inflated cap), then loads
lines the same way as a plain string array. Small configs stay uncompressed arrays.

```json
{
  "mode": "kubewaf",
  "config_id": "kubewaf/shop/shop-waf",
  "allow_fallback": false,
  "directives_map": {
    "default": [
      "Include @kubewaf-defaults",
      "SecRuleEngine On",
      "SecRequestBodyAccess On"
    ]
  },
  "default_directives": "default",
  "metric_labels": {
    "waf_namespace": "shop",
    "waf_name": "shop-waf",
    "engine": "modsecurity",
    "owner": "modsecurity-proxy-wasm"
  },
  "metrics": { "enabled": true, "per_rule_id": false, "rule_tags": false, "dual_prefix": true },
  "transforms": { "fullwidth_normalize": true },
  "block": { "message": "blocked by kubeWAF" }
}
```

**Rules catalog (build-time embed)** — **path-b only**. The wasm ships helpers + CRS phrase lists; CRS *rule confs* are never embedded. kubeWAF loads structured SecRule CRs as inline SecLang. Phrase files stay embedded so `@pmFromFile scanners-user-agents.data` etc. resolve without a real filesystem.

| Virtual include | Embedded |
|-----------------|----------|
| `@kubewaf-defaults` | yes |
| `@demo-conf` / `@ftw-conf` | yes |
| `@crs-data/*.data` | yes (`@pmFromFile`) |
| `@crs-setup-conf` | no |
| `@owasp_crs/*.conf` | no |

```bash
make modsecurity-proxy-wasm.wasm
```

Path B plugin config (operator / tests) looks like:

```json
{
  "directives_map": {
    "default": [
      "Include @kubewaf-defaults",
      "SecRuleEngine On",
      "SecAction \"id:900000,...\"",
      "SecRule ... \"id:913100,...@pmFromFile scanners-user-agents.data...\""
    ]
  }
}
```

**Metrics** — Envoy stats with name-embedded labels (`metric_labels`). Core series are dual-emitted as `modsecurity_proxy_wasm.*` and `kubewaf_waf.*`. All counters include the label suffix (including `tx.total` / `tx.allowed`).

```bash
curl -s http://127.0.0.1:9901/stats/prometheus | grep -E 'modsecurity_proxy_wasm|kubewaf_waf'
```

**Security logs** — plugin log lines are JSON objects (no text prefix). Lifecycle events use `"event":"version"|"configure_start"|"config_applied"|…`; security events use `"event":"rule_match"` / `"tx_interrupt"`. Rule IDs are emitted as `"id"` (go-ftw JSON parser) and `"rule_id"`. Rule-match lines also append a classic ModSecurity fragment (`[id "N"] [msg "…"]`) so go-ftw `match_regex` tests (e.g. CRS 922130) succeed. Multipart/body processor errors are logged as raw engine text for the same reason.

```text
{"component":"modsecurity-proxy-wasm","event":"rule_match","engine":"modsecurity","id":942100,"rule_id":942100,"phase":2,"severity":2,"disruptive":false,"msg":"..."} [id "942100"] [msg "..."]
{"component":"modsecurity-proxy-wasm","event":"tx_interrupt","engine":"modsecurity","config_id":"kubewaf/shop/shop-waf","id":949110,"rule_id":949110,"disruptive":true,"phase_name":"request_body"}
{"component":"modsecurity-proxy-wasm","event":"config_applied","config_id":"kubewaf/shop/shop-waf","mode":"kubewaf","metric_labels":3,"per_rule_id":false,"stats":true}
```

**OCI artifact** — wasm, default WAF JSON, and an Envoy example in one image:

```bash
make image
make extract-wasm    # → dist/modsecurity-proxy-wasm.wasm
```

**Fail-closed** — invalid config aborts plugin startup (no silent CRS fallback unless `allow_fallback: true`).

**Tests**

```bash
make test-bats         # Envoy smoke
make test-regression   # CRS go-ftw (Path B gzip CRS; FTW_INCLUDE='^941.*' for subset)
make test-unit         # waf_config
```

## License

Apache-2.0 (same as SDK and ModSecurity).