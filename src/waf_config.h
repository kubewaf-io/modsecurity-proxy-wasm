#ifndef MODSECURITY_PROXY_WASM_WAF_CONFIG_H_
#define MODSECURITY_PROXY_WASM_WAF_CONFIG_H_

#include <cstddef>
#include <string>

#include "metrics.h"

// Expand Envoy plugin configuration into ModSecurity rules text.
// Supports:
//   1) JSON WAF config (directives_map / default_directives + Include @virtual paths)
//   2) Compressed directives: directives_encoding=gzip+base64 and
//      directives_map.default as base64(gzip(SecLang lines joined by "\n"))
//   3) Legacy plain-text SecLanguage (passed through unchanged)
//
// Virtual includes recognized:
//   @kubewaf-defaults  — production body-access / tmp baseline (kubeWAF)
//   @demo-conf         — demo overlay
//   @ftw-conf          — go-ftw harness
//   @crs-data/*.data   — CRS phrase lists for @pmFromFile (always embedded)
// Catalog is path-b only: CRS rule confs are NOT embedded. Use structured SecRule
// CRs / inline SecLang. Include @crs-setup-conf / @owasp_crs* fail closed with a hint.
const char* defaultWafJsonConfig();
bool expandWafConfiguration(const std::string& config, std::string& rules_out, std::string& error);

// Load rules in chunks (one virtual include at a time) to avoid huge single parse on WASM.
using RuleChunkLoader = bool (*)(const char* label, const char* data, std::size_t size, void* user,
                                 std::string& error);
bool applyWafConfiguration(const std::string& config, RuleChunkLoader loader, void* user, std::string& error);

// Local-reply options for interventions.
// Client-visible strings/headers stay product-neutral by default (no vendor names).
struct WafBlockOptions {
  std::string message{"Forbidden"};
  // 0 = use ModSecurity intervention status (typically 403).
  int status{0};
  // Marker header on deny local-replies. Empty disables the header entirely.
  // Generic default intentionally avoids product names.
  std::string blocked_header{"x-blocked"};
  bool add_rule_id_header{false};
  std::string rule_id_header{"x-blocked-rule-id"};
  // When true, echo the correlated request id on the deny local-reply.
  bool add_request_id_header{false};
  std::string request_id_header{"x-request-id"};
};

// Full plugin configuration parsed from Envoy Wasm plugin config JSON.
struct WafPluginOptions {
  WafMetricOptions metrics;
  WafBlockOptions block;
  // "kubewaf" when driven by the kubeWAF operator; empty for standalone demos.
  std::string mode;
  // Stable id, e.g. "kubewaf/shop/shop-waf" (ECDS resource name).
  std::string config_id;
  bool allow_fallback{false};
  // Pre-fold fullwidth Unicode / %EF%BC in path, headers, and request bodies so
  // CRS XSS (941110-7/8) sees ASCII. Off for pure-latency profiles; on by default.
  bool fullwidth_normalize{true};
};

// Parse metric_labels + metrics{}/flat toggles from JSON plugin configuration.
bool parseWafMetricOptions(const std::string& config, WafMetricOptions& out);

// Parse full plugin options (metrics, block, mode, config_id, allow_fallback).
bool parseWafPluginOptions(const std::string& config, WafPluginOptions& out);

// Dev-only escape hatch: when true, onConfigure may load minimal built-in rules if CRS/config fails.
// Always false when mode is "kubewaf" or metric_labels contain waf_name (operator-driven).
bool wafConfigAllowsFallback(const std::string& config);

// Built-in @kubewaf-defaults content (also shipped via rules catalog when rebuilt).
const char* kubeWafDefaultsConf();

#endif
