#include "metrics.h"

#include <cctype>

#include "proxy_wasm_intrinsics.h"

void ModSecMetrics::configure(const WafMetricOptions& options) {
  options_ = options;
  metric_ids_.clear();
  distinct_rule_metrics_ = 0;
  distinct_tag_metrics_ = 0;
}

std::string ModSecMetrics::labelSuffix() const {
  std::string suffix;
  for (const auto& kv : options_.labels) {
    suffix.push_back('_');
    suffix.append(kv.first);
    suffix.push_back('=');
    suffix.append(kv.second);
  }
  return suffix;
}

const char* ModSecMetrics::phaseNameFromRule(int rule_phase) {
  switch (rule_phase) {
    case 0:
      return modsecurity_proxy_wasm_metric_phase::kRequestHeaders;
    case 1:
      return modsecurity_proxy_wasm_metric_phase::kRequestBody;
    case 2:
      return modsecurity_proxy_wasm_metric_phase::kResponseHeaders;
    case 3:
      return modsecurity_proxy_wasm_metric_phase::kResponseBody;
    case 4:
      return modsecurity_proxy_wasm_metric_phase::kLogging;
    default:
      return "unknown";
  }
}

bool ModSecMetrics::isInterestingRuleTag(std::string_view tag) {
  if (tag.empty()) {
    return false;
  }
  if (tag.rfind("attack-", 0) == 0) {
    return true;
  }
  if (tag.rfind("OWASP_CRS", 0) == 0) {
    return true;
  }
  if (tag.rfind("paranoia-level", 0) == 0) {
    return true;
  }
  return false;
}

std::string ModSecMetrics::sanitizeTagForMetric(std::string_view tag) {
  std::string out;
  out.reserve(tag.size());
  for (char c : tag) {
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.') {
      out.push_back(c);
    } else if (c == '/') {
      out.push_back('-');
    }
  }
  if (out.empty()) {
    out = "unknown";
  }
  return out;
}

void ModSecMetrics::incrementCounter(const std::string& name) {
  auto it = metric_ids_.find(name);
  if (it == metric_ids_.end()) {
    uint32_t id = 0;
    if (defineMetric(MetricType::Counter, name, &id) != WasmResult::Ok) {
      return;
    }
    metric_ids_[name] = id;
    it = metric_ids_.find(name);
  }
  incrementMetric(it->second, 1);
}

bool ModSecMetrics::trackDistinct(std::string& name, size_t& distinct_count, size_t max_distinct) {
  if (metric_ids_.find(name) != metric_ids_.end()) {
    return true;
  }
  if (distinct_count >= max_distinct) {
    return false;
  }
  ++distinct_count;
  return true;
}

void ModSecMetrics::countTxTotal() {
  incrementCounter("modsecurity_proxy_wasm.tx.total");
}

void ModSecMetrics::countTxAllowed() {
  incrementCounter("modsecurity_proxy_wasm.tx.allowed");
}

void ModSecMetrics::countTxInterruption(const char* phase, int64_t rule_id) {
  if (phase == nullptr || phase[0] == '\0') {
    phase = "unknown";
  }

  incrementCounter(std::string("modsecurity_proxy_wasm.tx.interruptions_phase=") + phase + labelSuffix());

  if (!options_.per_rule_id || rule_id <= 0) {
    return;
  }

  std::string name = std::string("modsecurity_proxy_wasm.tx.interruptions_ruleid=") + std::to_string(rule_id) +
                     "_phase=" + phase + labelSuffix();
  if (!trackDistinct(name, distinct_rule_metrics_, kMaxDistinctRuleMetrics)) {
    return;
  }
  incrementCounter(name);
}

void ModSecMetrics::countRuleMatch(int rule_phase, int severity, bool disruptive, int64_t rule_id,
                                   const std::list<std::string>& tags) {
  const char* phase = phaseNameFromRule(rule_phase);
  const std::string suffix = labelSuffix();

  incrementCounter("modsecurity_proxy_wasm.rule.matches");
  incrementCounter(std::string("modsecurity_proxy_wasm.rule.matches_phase=") + phase + "_severity=" +
                   std::to_string(severity) + suffix);

  if (disruptive) {
    incrementCounter("modsecurity_proxy_wasm.rule.matches_disruptive");
    incrementCounter(std::string("modsecurity_proxy_wasm.rule.matches_disruptive_phase=") + phase +
                     "_severity=" + std::to_string(severity) + suffix);
  }

  if (options_.per_rule_id && rule_id > 0) {
    std::string rule_name = std::string("modsecurity_proxy_wasm.rule.matches_ruleid=") + std::to_string(rule_id) +
                           "_phase=" + phase + suffix;
    if (trackDistinct(rule_name, distinct_rule_metrics_, kMaxDistinctRuleMetrics)) {
      incrementCounter(rule_name);
    }
  }

  if (!options_.rule_tags) {
    return;
  }

  for (const auto& tag : tags) {
    if (!isInterestingRuleTag(tag)) {
      continue;
    }
    std::string tag_name = std::string("modsecurity_proxy_wasm.rule.matches_tag=") + sanitizeTagForMetric(tag) +
                           "_phase=" + phase + suffix;
    if (!trackDistinct(tag_name, distinct_tag_metrics_, kMaxDistinctTagMetrics)) {
      continue;
    }
    incrementCounter(tag_name);
  }
}

void ModSecMetrics::countResponseBodySanitized() {
  incrementCounter("modsecurity_proxy_wasm.response_body.sanitized");
}

void ModSecMetrics::countConfigureFallbackRules() {
  incrementCounter("modsecurity_proxy_wasm.configure.fallback_rules");
}