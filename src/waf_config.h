#ifndef MODSECURITY_PROXY_WASM_WAF_CONFIG_H_
#define MODSECURITY_PROXY_WASM_WAF_CONFIG_H_

#include <cstddef>
#include <string>

#include "metrics.h"

// Expand Envoy plugin configuration into ModSecurity rules text.
// Supports:
//   1) JSON WAF config (directives_map / default_directives + Include @virtual paths)
//   2) Legacy plain-text SecLanguage (passed through unchanged)
const char* defaultWafJsonConfig();
bool expandWafConfiguration(const std::string& config, std::string& rules_out, std::string& error);

// Load rules in chunks (one virtual include at a time) to avoid huge single parse on WASM.
using RuleChunkLoader = bool (*)(const char* label, const char* data, std::size_t size, void* user,
                                 std::string& error);
bool applyWafConfiguration(const std::string& config, RuleChunkLoader loader, void* user, std::string& error);

// Dev-only escape hatch: when true, onConfigure may load minimal built-in rules if CRS/config fails.
bool wafConfigAllowsFallback(const std::string& config);

// Parse optional metrics settings from JSON plugin configuration.
bool parseWafMetricOptions(const std::string& config, WafMetricOptions& out);

#endif