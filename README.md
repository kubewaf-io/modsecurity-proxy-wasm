# modsec-wasm-plugin

ModSecurity proxy-wasm module for Envoy (`envoy.wasm.runtime.v8`) with embedded **OWASP CRS v4.27.0**.

- libModSecurity v3 + PCRE2, built with Emscripten and the [proxy-wasm-cpp-sdk](https://github.com/proxy-wasm/proxy-wasm-cpp-sdk)
- CRS rules and phrase lists embedded at build time (no runtime filesystem)
- JSON `directives_map` / `default_directives` WAF configuration

## Quick start

```bash
make image                    # build wasm + OCI artifact
make extract-wasm             # writes dist/modsec.wasm
make test-bats                # Envoy integration smoke tests
```

Run Envoy with the example config:

```bash
podman run --rm \
  -v "$(pwd)/dist/modsec.wasm:/etc/modsec.wasm:ro" \
  -v "$(pwd)/test/fixtures/envoy.yaml:/etc/envoy.yaml:ro" \
  -p 8080:8080 \
  envoyproxy/envoy:v1.38-latest \
  envoy -c /etc/envoy.yaml
```

```bash
curl -v http://localhost:8080/                                    # 200
curl -v 'http://localhost:8080/?q=<script>alert(1)</script>'       # 403
```

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/BUILD.md](docs/BUILD.md) | Toolchain, Docker/OCI images, dependency pins, CRS embedding |
| [docs/TESTING.md](docs/TESTING.md) | Integration (bats), CRS regression (go-ftw), unit/fuzz, perf (k6) |
| [docs/METRICS.md](docs/METRICS.md) | Prometheus counters via Envoy `/stats` |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model and supply-chain notes |
| [docs/TODO.md](docs/TODO.md) | Production-readiness backlog |

## Layout

```
src/          plugin C++ sources
build/        build.mk, scripts, rules templates, docker/
test/         fixtures, integration, regression, unit, fuzz, perf
dist/         modsec.wasm (gitignored; produced by make)
.cache/       dependency clones (gitignored)
docs/         detailed guides
```

## Moved paths (2026-06)

| Old | New |
|-----|-----|
| `modsec.wasm` (root) | `dist/modsec.wasm` |
| `build.mk`, `Dockerfile` | `build/build.mk`, `build/docker/Dockerfile` |
| `test/envoy.yaml` | `test/fixtures/envoy.yaml` |
| `rules/`, `scripts/` | `build/rules/`, `build/scripts/` |
| `SECURITY.md`, `TODO.md` | `docs/SECURITY.md`, `docs/TODO.md` |

## License

Apache-2.0 (same as SDK and ModSecurity).