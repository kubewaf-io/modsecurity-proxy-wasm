# modsecurity-proxy-wasm

ModSecurity [Proxy-Wasm](https://github.com/proxy-wasm/spec) filter for Envoy (`envoy.wasm.runtime.v8`) with embedded **OWASP CRS v4.27.0**.

## Quick start

```bash
make image && make extract-wasm
make test-bats
```

```bash
podman run --rm \
  -v "$(pwd)/dist/modsec.wasm:/etc/modsec.wasm:ro" \
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
        code: { local: { filename: /etc/modsec.wasm } }
```

**WAF config** — JSON `directives_map` / `default_directives` profiles:

```json
{
  "directives_map": {
    "default": ["SecRuleEngine On", "SecRequestBodyAccess On"]
  },
  "default_directives": "default"
}
```

**Embedded CRS** — OWASP CRS v4.27.0 and phrase lists are baked in at build; load with virtual includes (no runtime filesystem):

```json
{
  "directives_map": {
    "crs": [
      "Include @demo-conf",
      "SecRuleEngine On",
      "Include @crs-setup-conf",
      "Include @owasp_crs/*.conf"
    ]
  },
  "default_directives": "crs"
}
```

**Metrics** — Prometheus counters via `metric_labels` and Envoy `stats_config` (see `test/fixtures/envoy.yaml`):

```json
{ "metric_labels": { "owner": "modsecurity-proxy-wasm", "identifier": "prod" } }
```

```bash
curl -s http://127.0.0.1:9901/stats/prometheus | grep modsec_wasm.tx
```

**OCI artifact** — wasm, default WAF JSON, and an Envoy example in one image:

```bash
make image
make extract-wasm    # → dist/modsec.wasm
```

**Fail-closed** — invalid config aborts plugin startup (no silent CRS fallback unless `allow_fallback: true`).

**Tests**

```bash
make test-bats         # Envoy smoke
make test-regression   # CRS go-ftw
make test-unit         # waf_config
```

## License

Apache-2.0 (same as SDK and ModSecurity).