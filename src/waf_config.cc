#include "waf_config.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "generated/rules_catalog.h"

namespace {

std::string trim(const std::string& s) {
  size_t b = 0;
  while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
  size_t e = s.size();
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
  return s.substr(b, e - b);
}

bool looksLikeJson(const std::string& s) {
  auto t = trim(s);
  return !t.empty() && t.front() == '{';
}

bool extractMetricLabels(const std::string& json, std::vector<std::pair<std::string, std::string>>& out) {
  out.clear();
  const std::string map_key = "\"metric_labels\"";
  size_t map_pos = json.find(map_key);
  if (map_pos == std::string::npos) {
    return true;
  }

  size_t obj_start = json.find('{', map_pos);
  if (obj_start == std::string::npos) {
    return false;
  }

  size_t i = obj_start + 1;
  while (i < json.size()) {
    size_t key_quote = json.find('"', i);
    if (key_quote == std::string::npos) {
      break;
    }
    size_t key_end = json.find('"', key_quote + 1);
    if (key_end == std::string::npos) {
      break;
    }
    std::string label_key = json.substr(key_quote + 1, key_end - key_quote - 1);

    size_t colon = json.find(':', key_end);
    if (colon == std::string::npos) {
      break;
    }
    size_t val_quote = json.find('"', colon);
    if (val_quote == std::string::npos) {
      break;
    }
    size_t val_end = json.find('"', val_quote + 1);
    if (val_end == std::string::npos) {
      break;
    }
    std::string label_value = json.substr(val_quote + 1, val_end - val_quote - 1);
    if (!label_key.empty()) {
      out.emplace_back(label_key, label_value);
    }

    i = val_end + 1;
    size_t obj_end = json.find('}', obj_start);
    if (obj_end != std::string::npos && i >= obj_end) {
      break;
    }
    size_t next = json.find_first_not_of(" \t\n\r,", i);
    if (next == std::string::npos) {
      break;
    }
    if (json[next] == '}') {
      break;
    }
    i = next;
  }
  return true;
}

bool extractJsonBoolValue(const std::string& json, const std::string& key, bool default_value) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) {
    return default_value;
  }
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) {
    return default_value;
  }
  const std::string tail = trim(json.substr(pos + 1));
  if (tail.rfind("true", 0) == 0) {
    return true;
  }
  if (tail.rfind("false", 0) == 0) {
    return false;
  }
  return default_value;
}

std::string extractJsonStringValue(const std::string& json, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) return "";
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) return "";
  pos = json.find('"', pos);
  if (pos == std::string::npos) return "";
  ++pos;
  std::string out;
  bool escape = false;
  for (; pos < json.size(); ++pos) {
    char c = json[pos];
    if (escape) {
      if (c == 'n') out.push_back('\n');
      else if (c == 'r') out.push_back('\r');
      else if (c == 't') out.push_back('\t');
      else if (c == '"') out.push_back('"');
      else if (c == '\\') out.push_back('\\');
      else out.push_back(c);
      escape = false;
      continue;
    }
    if (c == '\\') {
      escape = true;
      continue;
    }
    if (c == '"') break;
    out.push_back(c);
  }
  return out;
}

size_t findJsonArrayEnd(const std::string& json, size_t arr_start) {
  if (arr_start >= json.size() || json[arr_start] != '[') {
    return std::string::npos;
  }
  int depth = 0;
  bool in_string = false;
  bool escape = false;
  for (size_t i = arr_start; i < json.size(); ++i) {
    char c = json[i];
    if (in_string) {
      if (escape) {
        escape = false;
        continue;
      }
      if (c == '\\') {
        escape = true;
        continue;
      }
      if (c == '"') {
        in_string = false;
      }
      continue;
    }
    if (c == '"') {
      in_string = true;
      continue;
    }
    if (c == '[') {
      ++depth;
    } else if (c == ']') {
      --depth;
      if (depth == 0) {
        return i;
      }
    }
  }
  return std::string::npos;
}

std::vector<std::string> extractDirectiveArray(const std::string& json, const std::string& profile) {
  std::vector<std::string> out;
  const std::string map_key = "\"directives_map\"";
  size_t map_pos = json.find(map_key);
  if (map_pos == std::string::npos) return out;

  const std::string profile_key = "\"" + profile + "\"";
  size_t prof_pos = json.find(profile_key, map_pos);
  if (prof_pos == std::string::npos) return out;

  size_t arr_start = json.find('[', prof_pos);
  if (arr_start == std::string::npos) return out;

  size_t arr_end = findJsonArrayEnd(json, arr_start);
  if (arr_end == std::string::npos) return out;

  size_t i = arr_start + 1;
  while (i < arr_end) {
    size_t q = json.find('"', i);
    if (q == std::string::npos || q >= arr_end) break;

    ++q;
    std::string item;
    bool escape = false;
    for (; q < json.size(); ++q) {
      char c = json[q];
      if (escape) {
        if (c == 'n') item.push_back('\n');
        else if (c == 'r') item.push_back('\r');
        else if (c == 't') item.push_back('\t');
        else if (c == '"') item.push_back('"');
        else if (c == '\\') item.push_back('\\');
        else item.push_back(c);
        escape = false;
        continue;
      }
      if (c == '\\') {
        escape = true;
        continue;
      }
      if (c == '"') break;
      item.push_back(c);
    }
    if (!item.empty()) out.push_back(item);
    i = q + 1;
    size_t next = json.find_first_not_of(" \t\n\r,", i);
    if (next == std::string::npos || next >= arr_end) break;
    if (json[next] == ']') break;
    i = next;
  }
  return out;
}

bool loadChunk(RuleChunkLoader loader, void* user, const char* label, const char* data, std::size_t size,
               std::string& error) {
  if (loader == nullptr || data == nullptr || size == 0) {
    return true;
  }
  return loader(label, data, size, user, error);
}

bool loadAsset(RuleChunkLoader loader, void* user, const modsec_wasm_rules::RuleAsset& asset,
               std::set<std::string>& seen, std::string& error) {
  if (seen.count(asset.path)) {
    return true;
  }
  seen.insert(asset.path);
  return loadChunk(loader, user, asset.path, asset.data, asset.size, error);
}

struct LoadCtx {
  RuleChunkLoader loader;
  void* user;
  std::set<std::string>* seen;
  std::string* error;
};

bool loadOwaspCrsGlob(const modsec_wasm_rules::RuleAsset& asset, void* user) {
  auto* ctx = static_cast<LoadCtx*>(user);
  if (std::strcmp(asset.path, "@owasp_crs/_all.conf") == 0) {
    return true;
  }
  return loadAsset(ctx->loader, ctx->user, asset, *ctx->seen, *ctx->error);
}

bool resolveIncludeLoad(const std::string& target, RuleChunkLoader loader, void* user,
                        std::set<std::string>& seen, std::string& error) {
  if (target == "@demo-conf" || target == "@crs-setup-conf" || target == "@ftw-conf") {
    const auto* asset = modsec_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = "unknown virtual include: " + target;
      return false;
    }
    return loadAsset(loader, user, *asset, seen, error);
  }

  if (target == "@owasp_crs/*.conf") {
    LoadCtx ctx{loader, user, &seen, &error};
    modsec_wasm_rules::foreach_owasp_crs(loadOwaspCrsGlob, &ctx);
    return error.empty();
  }

  if (target.rfind("@owasp_crs/", 0) == 0) {
    const auto* asset = modsec_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = "unknown virtual include: " + target;
      return false;
    }
    return loadAsset(loader, user, *asset, seen, error);
  }

  error = "unsupported Include target: " + target;
  return false;
}

bool applyJsonConfig(const std::string& json, RuleChunkLoader loader, void* user, std::string& error) {
  std::string profile = extractJsonStringValue(json, "default_directives");
  if (profile.empty()) profile = "default";

  std::vector<std::string> directives = extractDirectiveArray(json, profile);
  if (directives.empty()) {
    error = "directives_map profile not found or empty: " + profile;
    return false;
  }

  std::set<std::string> seen;
  std::string inline_batch;
  inline_batch.reserve(8192);

  auto flushInline = [&]() -> bool {
    if (inline_batch.empty()) {
      return true;
    }
    if (!loadChunk(loader, user, "inline-directives", inline_batch.data(), inline_batch.size(), error)) {
      return false;
    }
    inline_batch.clear();
    return true;
  };

  for (const auto& raw : directives) {
    std::string line = trim(raw);
    if (line.empty() || line.rfind("#", 0) == 0) continue;

    if (line.rfind("Include ", 0) == 0) {
      if (!flushInline()) return false;
      std::string target = trim(line.substr(8));
      if (!resolveIncludeLoad(target, loader, user, seen, error)) return false;
      continue;
    }

    inline_batch.append(line);
    inline_batch.push_back('\n');
  }

  return flushInline();
}

bool resolveIncludeExpand(const std::string& target, std::string& out, std::set<std::string>& seen, std::string& error);

bool appendOwaspCrsGlobExpand(const modsec_wasm_rules::RuleAsset& asset, void* user) {
  struct Ctx {
    std::string* out;
    std::set<std::string>* seen;
    std::string* error;
  };
  auto* ctx = static_cast<Ctx*>(user);
  if (std::strcmp(asset.path, "@owasp_crs/_all.conf") == 0) {
    return true;
  }
  if (ctx->seen->count(asset.path)) {
    return true;
  }
  ctx->seen->insert(asset.path);
  ctx->out->append(asset.data, asset.size);
  ctx->out->push_back('\n');
  return true;
}

bool resolveIncludeExpand(const std::string& target, std::string& out, std::set<std::string>& seen, std::string& error) {
  if (target == "@demo-conf" || target == "@crs-setup-conf" || target == "@ftw-conf") {
    const auto* asset = modsec_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = "unknown virtual include: " + target;
      return false;
    }
    if (!seen.count(target)) {
      seen.insert(target);
      out.append(asset->data, asset->size);
      out.push_back('\n');
    }
    return true;
  }

  if (target == "@owasp_crs/*.conf") {
    struct Ctx {
      std::string* out;
      std::set<std::string>* seen;
      std::string* error;
    } ctx{&out, &seen, &error};
    modsec_wasm_rules::foreach_owasp_crs(appendOwaspCrsGlobExpand, &ctx);
    return true;
  }

  if (target.rfind("@owasp_crs/", 0) == 0) {
    const auto* asset = modsec_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = "unknown virtual include: " + target;
      return false;
    }
    if (!seen.count(target)) {
      seen.insert(target);
      out.append(asset->data, asset->size);
      out.push_back('\n');
    }
    return true;
  }

  error = "unsupported Include target: " + target;
  return false;
}

bool expandJsonConfig(const std::string& json, std::string& rules_out, std::string& error) {
  std::string profile = extractJsonStringValue(json, "default_directives");
  if (profile.empty()) profile = "default";

  std::vector<std::string> directives = extractDirectiveArray(json, profile);
  if (directives.empty()) {
    error = "directives_map profile not found or empty: " + profile;
    return false;
  }

  std::set<std::string> seen;
  rules_out.clear();

  for (const auto& raw : directives) {
    std::string line = trim(raw);
    if (line.empty() || line.rfind("#", 0) == 0) continue;

    if (line.rfind("Include ", 0) == 0) {
      std::string target = trim(line.substr(8));
      if (!resolveIncludeExpand(target, rules_out, seen, error)) return false;
      continue;
    }

    rules_out.append(line);
    rules_out.push_back('\n');
  }
  return !rules_out.empty();
}

}  // namespace

const char* defaultWafJsonConfig() {
  return R"({
  "directives_map": {
    "default": [
      "Include @demo-conf",
      "SecDebugLogLevel 9",
      "SecRuleEngine On",
      "Include @crs-setup-conf",
      "Include @owasp_crs/REQUEST-901-INITIALIZATION.conf",
      "Include @owasp_crs/*.conf"
    ]
  },
  "default_directives": "default"
})";
}

bool applyWafConfiguration(const std::string& config, RuleChunkLoader loader, void* user, std::string& error) {
  error.clear();
  auto trimmed = trim(config);
  if (trimmed.empty()) {
    error = "empty configuration";
    return false;
  }
  if (!looksLikeJson(trimmed)) {
    return loadChunk(loader, user, "plain-config", trimmed.data(), trimmed.size(), error);
  }
  return applyJsonConfig(trimmed, loader, user, error);
}

bool wafConfigAllowsFallback(const std::string& config) {
  if (!looksLikeJson(trim(config))) {
    return false;
  }
  return extractJsonBoolValue(config, "allow_fallback", false);
}

bool parseWafMetricOptions(const std::string& config, WafMetricOptions& out) {
  out.labels.clear();
  out.per_rule_id = true;
  out.rule_tags = true;

  if (!looksLikeJson(trim(config))) {
    return true;
  }
  if (!extractMetricLabels(config, out.labels)) {
    return false;
  }
  out.per_rule_id = extractJsonBoolValue(config, "metrics_per_rule_id", true);
  out.rule_tags = extractJsonBoolValue(config, "metrics_rule_tags", true);
  return true;
}

bool expandWafConfiguration(const std::string& config, std::string& rules_out, std::string& error) {
  error.clear();
  auto trimmed = trim(config);
  if (trimmed.empty()) {
    error = "empty configuration";
    return false;
  }
  if (!looksLikeJson(trimmed)) {
    rules_out = trimmed;
    return true;
  }
  return expandJsonConfig(trimmed, rules_out, error);
}