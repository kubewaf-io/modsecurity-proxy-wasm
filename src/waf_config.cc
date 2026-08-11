#include "waf_config.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include <zlib.h>

#include "generated/rules_catalog.h"

namespace {

// Must match internal/dataplane/config DirectivesMaxInflatedBytes.
constexpr std::size_t kMaxInflatedDirectivesBytes = 32u * 1024u * 1024u;

// Production baseline also shipped as build/rules/kubewaf-defaults.conf in the CRS catalog.
// Kept in-source so unit tests and pre-regeneration binaries always resolve Include @kubewaf-defaults.
constexpr char kKubeWafDefaultsConf[] =
    "# kubeWAF production baseline (virtual path: Include @kubewaf-defaults)\n"
    "SecTmpDir /modsecurity-proxy-wasm-rules\n"
    "SecDataDir /modsecurity-proxy-wasm-rules\n"
    "SecRequestBodyAccess On\n"
    "SecRequestBodyLimit 13107200\n"
    "SecRequestBodyLimitAction ProcessPartial\n"
    "SecRequestBodyNoFilesLimit 131072\n"
    "SecResponseBodyAccess On\n"
    "SecResponseBodyMimeType text/plain text/html text/xml application/json\n"
    "SecResponseBodyLimit 524288\n"
    "SecResponseBodyLimitAction ProcessPartial\n"
    "SecAuditEngine Off\n";

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

size_t findJsonObjectEnd(const std::string& json, size_t obj_start) {
  if (obj_start >= json.size() || json[obj_start] != '{') {
    return std::string::npos;
  }
  int depth = 0;
  bool in_string = false;
  bool escape = false;
  for (size_t i = obj_start; i < json.size(); ++i) {
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
    if (c == '{') {
      ++depth;
    } else if (c == '}') {
      --depth;
      if (depth == 0) {
        return i;
      }
    }
  }
  return std::string::npos;
}

// Extract a top-level object value for key, e.g. "metrics": { ... }.
bool extractJsonObjectSlice(const std::string& json, const std::string& key, std::string& out) {
  const std::string needle = "\"" + key + "\"";
  size_t pos = 0;
  while (pos < json.size()) {
    size_t key_pos = json.find(needle, pos);
    if (key_pos == std::string::npos) {
      return false;
    }
    // Prefer matches that look like object keys (colon after).
    size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
      return false;
    }
    size_t obj_start = json.find('{', colon);
    if (obj_start == std::string::npos) {
      return false;
    }
    // Skip if another non-whitespace token appears before '{'.
    std::string between = trim(json.substr(colon + 1, obj_start - colon - 1));
    if (!between.empty()) {
      pos = key_pos + needle.size();
      continue;
    }
    size_t obj_end = findJsonObjectEnd(json, obj_start);
    if (obj_end == std::string::npos) {
      return false;
    }
    out = json.substr(obj_start, obj_end - obj_start + 1);
    return true;
  }
  return false;
}

bool extractStringMapFromObject(const std::string& obj,
                                std::vector<std::pair<std::string, std::string>>& out) {
  out.clear();
  if (obj.empty() || obj.front() != '{') {
    return false;
  }
  size_t i = 1;
  while (i < obj.size()) {
    size_t key_quote = obj.find('"', i);
    if (key_quote == std::string::npos) {
      break;
    }
    size_t key_end = obj.find('"', key_quote + 1);
    if (key_end == std::string::npos) {
      break;
    }
    std::string label_key = obj.substr(key_quote + 1, key_end - key_quote - 1);

    size_t colon = obj.find(':', key_end);
    if (colon == std::string::npos) {
      break;
    }
    size_t val_quote = obj.find('"', colon);
    if (val_quote == std::string::npos) {
      break;
    }
    // Only accept string values for metric labels.
    std::string between = trim(obj.substr(colon + 1, val_quote - colon - 1));
    if (!between.empty()) {
      // Non-string value — skip until next comma/brace roughly.
      size_t next = obj.find_first_of(",}", colon + 1);
      if (next == std::string::npos) {
        break;
      }
      i = next + 1;
      continue;
    }
    ++val_quote;
    std::string label_value;
    bool escape = false;
    size_t p = val_quote;
    for (; p < obj.size(); ++p) {
      char c = obj[p];
      if (escape) {
        if (c == 'n') label_value.push_back('\n');
        else if (c == 'r') label_value.push_back('\r');
        else if (c == 't') label_value.push_back('\t');
        else if (c == '"') label_value.push_back('"');
        else if (c == '\\') label_value.push_back('\\');
        else label_value.push_back(c);
        escape = false;
        continue;
      }
      if (c == '\\') {
        escape = true;
        continue;
      }
      if (c == '"') break;
      label_value.push_back(c);
    }
    if (!label_key.empty()) {
      out.emplace_back(label_key, label_value);
    }
    i = p + 1;
    size_t next = obj.find_first_not_of(" \t\n\r,", i);
    if (next == std::string::npos || obj[next] == '}') {
      break;
    }
    i = next;
  }
  return true;
}

bool extractMetricLabels(const std::string& json, std::vector<std::pair<std::string, std::string>>& out) {
  out.clear();
  std::string obj;
  if (!extractJsonObjectSlice(json, "metric_labels", obj)) {
    return true;  // optional
  }
  return extractStringMapFromObject(obj, out);
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

bool extractJsonIntValue(const std::string& json, const std::string& key, int default_value) {
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
  if (tail.empty() || (!std::isdigit(static_cast<unsigned char>(tail[0])) && tail[0] != '-')) {
    return default_value;
  }
  try {
    return std::stoi(tail);
  } catch (...) {
    return default_value;
  }
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

// Locate "directives_map"."profile" value start (after colon). Returns npos on failure.
size_t findDirectivesMapProfileValue(const std::string& json, const std::string& profile) {
  const std::string map_key = "\"directives_map\"";
  size_t map_pos = json.find(map_key);
  if (map_pos == std::string::npos) return std::string::npos;

  const std::string profile_key = "\"" + profile + "\"";
  size_t prof_pos = json.find(profile_key, map_pos);
  if (prof_pos == std::string::npos) return std::string::npos;

  size_t colon = json.find(':', prof_pos + profile_key.size());
  if (colon == std::string::npos) return std::string::npos;
  size_t v = json.find_first_not_of(" \t\n\r", colon + 1);
  return v;
}

std::vector<std::string> extractDirectiveArray(const std::string& json, const std::string& profile) {
  std::vector<std::string> out;
  size_t v = findDirectivesMapProfileValue(json, profile);
  if (v == std::string::npos || json[v] != '[') return out;

  size_t arr_start = v;
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

// Extract directives_map.profile when it is a JSON string (gzip+base64 blob).
std::string extractDirectiveMapString(const std::string& json, const std::string& profile) {
  size_t v = findDirectivesMapProfileValue(json, profile);
  if (v == std::string::npos || json[v] != '"') return "";
  // Reuse string value parser from key-less position: build fake fragment.
  // extractJsonStringValue needs a key — parse manually from v.
  size_t pos = v + 1;
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

// Standard base64 decode (alphabet + URL-safe not required).
bool base64Decode(const std::string& in, std::string& out, std::string& error) {
  static const int8_t kDec[256] = {
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
      -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
      -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
  out.clear();
  out.reserve(in.size() * 3 / 4);
  int val = 0;
  int valb = -8;
  for (unsigned char c : in) {
    if (c == '=' || std::isspace(c)) continue;
    int d = kDec[c];
    if (d < 0) {
      error = "invalid base64 in compressed directives";
      return false;
    }
    val = (val << 6) + d;
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return true;
}

// Gunzip (RFC 1952 wrapper) using zlib inflateInit2 windowBits=16+MAX_WBITS.
bool gzipInflate(const std::string& compressed, std::string& plain, std::string& error) {
  if (compressed.empty()) {
    error = "empty compressed directives";
    return false;
  }
  z_stream strm{};
  // 16 + MAX_WBITS: decode gzip header
  if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
    error = "gzip inflateInit2 failed";
    return false;
  }
  strm.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data()));
  strm.avail_in = static_cast<uInt>(compressed.size());
  plain.clear();
  plain.reserve(std::min(compressed.size() * 8, static_cast<std::size_t>(256 * 1024)));
  std::vector<char> buf(64 * 1024);
  int ret = Z_OK;
  do {
    strm.next_out = reinterpret_cast<Bytef*>(buf.data());
    strm.avail_out = static_cast<uInt>(buf.size());
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END) {
      inflateEnd(&strm);
      error = "gzip inflate failed (code " + std::to_string(ret) + ")";
      return false;
    }
    std::size_t produced = buf.size() - strm.avail_out;
    if (plain.size() + produced > kMaxInflatedDirectivesBytes) {
      inflateEnd(&strm);
      error = "inflated directives exceed max size";
      return false;
    }
    plain.append(buf.data(), produced);
  } while (ret != Z_STREAM_END);
  inflateEnd(&strm);
  return true;
}

std::vector<std::string> splitDirectiveLines(const std::string& text) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < text.size()) {
    size_t nl = text.find('\n', i);
    if (nl == std::string::npos) {
      std::string line = trim(text.substr(i));
      if (!line.empty()) out.push_back(line);
      break;
    }
    std::string line = trim(text.substr(i, nl - i));
    if (!line.empty() && line.rfind("#", 0) != 0) {
      // Keep comments filtered later; push non-empty raw (comments skipped in consumer)
      out.push_back(line);
    } else if (!line.empty()) {
      out.push_back(line);
    }
    i = nl + 1;
  }
  return out;
}

// Load directive list: plain JSON array or gzip+base64 string under directives_map.
bool loadDirectiveList(const std::string& json, const std::string& profile,
                       std::vector<std::string>& directives, std::string& error) {
  directives.clear();
  std::string encoding = extractJsonStringValue(json, "directives_encoding");
  if (encoding == "gzip+base64" || encoding == "gzip") {
    std::string b64 = extractDirectiveMapString(json, profile);
    if (b64.empty()) {
      error = "directives_map profile not found or empty (compressed): " + profile;
      return false;
    }
    std::string compressed;
    if (encoding == "gzip+base64" || encoding.find("base64") != std::string::npos) {
      if (!base64Decode(b64, compressed, error)) return false;
      // Free base64 workspace before inflate peak (Path B payloads can be multi-MB).
      b64.clear();
      b64.shrink_to_fit();
    } else {
      compressed = std::move(b64);
    }
    std::string plain;
    if (!gzipInflate(compressed, plain, error)) return false;
    // Drop gzip input immediately; plain is the only buffer needed for line split.
    compressed.clear();
    compressed.shrink_to_fit();
    directives = splitDirectiveLines(plain);
    plain.clear();
    plain.shrink_to_fit();
    if (directives.empty()) {
      error = "compressed directives inflated to empty list";
      return false;
    }
    return true;
  }
  // Plain array form.
  directives = extractDirectiveArray(json, profile);
  if (directives.empty()) {
    error = "directives_map profile not found or empty: " + profile;
    return false;
  }
  return true;
}

bool loadChunk(RuleChunkLoader loader, void* user, const char* label, const char* data, std::size_t size,
               std::string& error) {
  if (loader == nullptr || data == nullptr || size == 0) {
    return true;
  }
  return loader(label, data, size, user, error);
}

bool loadAsset(RuleChunkLoader loader, void* user, const modsecurity_proxy_wasm_rules::RuleAsset& asset,
               std::set<std::string>& seen, std::string& error) {
  if (seen.count(asset.path)) {
    return true;
  }
  seen.insert(asset.path);
  return loadChunk(loader, user, asset.path, asset.data, asset.size, error);
}

bool loadKubeWafDefaults(RuleChunkLoader loader, void* user, std::set<std::string>& seen,
                         std::string& error) {
  constexpr const char* kPath = "@kubewaf-defaults";
  if (seen.count(kPath)) {
    return true;
  }
  seen.insert(kPath);
  // Prefer catalog asset when present (full wasm build); fall back to in-source constant.
  if (const auto* asset = modsecurity_proxy_wasm_rules::lookup(kPath); asset != nullptr) {
    return loadChunk(loader, user, asset->path, asset->data, asset->size, error);
  }
  return loadChunk(loader, user, kPath, kKubeWafDefaultsConf, sizeof(kKubeWafDefaultsConf) - 1, error);
}

bool appendKubeWafDefaults(std::string& out, std::set<std::string>& seen) {
  constexpr const char* kPath = "@kubewaf-defaults";
  if (seen.count(kPath)) {
    return true;
  }
  seen.insert(kPath);
  if (const auto* asset = modsecurity_proxy_wasm_rules::lookup(kPath); asset != nullptr) {
    out.append(asset->data, asset->size);
    out.push_back('\n');
    return true;
  }
  out.append(kKubeWafDefaultsConf);
  if (out.empty() || out.back() != '\n') {
    out.push_back('\n');
  }
  return true;
}

struct LoadCtx {
  RuleChunkLoader loader;
  void* user;
  std::set<std::string>* seen;
  std::string* error;
};

bool loadOwaspCrsGlob(const modsecurity_proxy_wasm_rules::RuleAsset& asset, void* user) {
  auto* ctx = static_cast<LoadCtx*>(user);
  if (std::strcmp(asset.path, "@owasp_crs/_all.conf") == 0) {
    return true;
  }
  return loadAsset(ctx->loader, ctx->user, asset, *ctx->seen, *ctx->error);
}

// Path A virtual includes are never embedded (path-b catalog only).
// Structured SecRule CRs / inline SecLang supply CRS rules from the cluster.
std::string pathACatalogHint(const std::string& target) {
  const char* mode = modsecurity_proxy_wasm_rules::catalog_mode();
  if (mode == nullptr) mode = "unknown";
  return "virtual include " + target + " not in catalog (catalog_mode=" + std::string(mode) +
         "). Path B builds omit CRS rule confs; supply rules as structured SecRule CRs "
         "(crsEnable:false) or inline SecLang in directives_map.";
}

bool resolveIncludeLoad(const std::string& target, RuleChunkLoader loader, void* user,
                        std::set<std::string>& seen, std::string& error) {
  if (target == "@kubewaf-defaults") {
    return loadKubeWafDefaults(loader, user, seen, error);
  }

  if (target == "@demo-conf" || target == "@ftw-conf") {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = "unknown virtual include: " + target;
      return false;
    }
    return loadAsset(loader, user, *asset, seen, error);
  }

  if (target == "@crs-setup-conf") {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = pathACatalogHint(target);
      return false;
    }
    return loadAsset(loader, user, *asset, seen, error);
  }

  if (target == "@owasp_crs/*.conf") {
    int count = 0;
    modsecurity_proxy_wasm_rules::foreach_owasp_crs(
        [](const modsecurity_proxy_wasm_rules::RuleAsset&, void* user) -> bool {
          *static_cast<int*>(user) += 1;
          return true;
        },
        &count);
    if (count == 0) {
      error = pathACatalogHint(target);
      return false;
    }
    LoadCtx ctx{loader, user, &seen, &error};
    modsecurity_proxy_wasm_rules::foreach_owasp_crs(loadOwaspCrsGlob, &ctx);
    return error.empty();
  }

  if (target.rfind("@owasp_crs/", 0) == 0) {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = pathACatalogHint(target);
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

  std::vector<std::string> directives;
  if (!loadDirectiveList(json, profile, directives, error)) {
    return false;
  }

  // Flatten multi-line directive strings into physical lines. Plain JSON arrays
  // may carry one ConvertToSecLangString blob per SecRule (comment + rule,
  // parent+child chain, rule+SecMarker). Without flattening:
  //  - comment-prefixed blobs are skipped entirely (leading '#')
  //  - multi-line chains leave pending_chain stuck true (',chain"' still in blob)
  // Gzip payloads are already line-split in loadDirectiveList; re-splitting is
  // idempotent for single-line entries.
  std::vector<std::string> lines;
  lines.reserve(directives.size() * 2);
  for (auto& raw : directives) {
    std::vector<std::string> parts = splitDirectiveLines(raw);
    for (auto& p : parts) {
      lines.push_back(std::move(p));
    }
    // Release each source string as soon as it is flattened (helps gzip Path B peaks).
    raw.clear();
    raw.shrink_to_fit();
  }
  directives.clear();
  directives.shrink_to_fit();

  std::set<std::string> seen;
  std::string inline_batch;
  // Keep each loadRules chunk modest. Large Path B SecLang batches have trapped
  // Envoy V8 as "Uncaught RuntimeError: unreachable" during msc_rules_add.
  constexpr std::size_t kMaxInlineChunkBytes = 4096;
  inline_batch.reserve(kMaxInlineChunkBytes);

  auto flushInline = [&]() -> bool {
    if (inline_batch.empty()) {
      return true;
    }
    if (!loadChunk(loader, user, "inline-directives", inline_batch.data(), inline_batch.size(), error)) {
      return false;
    }
    inline_batch.clear();
    // Bound reserved capacity between flushes so a large single-line rule does not
    // leave a multi-MB capacity hanging for the rest of configure.
    if (inline_batch.capacity() > kMaxInlineChunkBytes * 2) {
      std::string fresh;
      fresh.reserve(kMaxInlineChunkBytes);
      inline_batch.swap(fresh);
    }
    return true;
  };

  // When the last accepted line requested a chain continuation, do not flush
  // until the next non-empty SecRule/SecAction (chain child) is appended —
  // splitting parent/child across msc_rules_add calls has trapped V8.
  bool pending_chain = false;

  auto is_file_phrase_op = [](const std::string& line) -> bool {
    // @pmFromFile / @ipMatchFromFile build large automata; loading them in the
    // same msc_rules_add batch as many other Path B SecRules has caused Envoy
    // V8 "unreachable" traps. Isolate each such rule in its own load chunk.
    return line.find("@pmFromFile") != std::string::npos ||
           line.find("@ipMatchFromFile") != std::string::npos;
  };

  auto line_requests_chain = [](const std::string& line) -> bool {
    // Match chain as a whole action token: ,chain" or ,chain, or "chain,
    return line.find(",chain\"") != std::string::npos ||
           line.find(",chain,") != std::string::npos ||
           line.find("\"chain\"") != std::string::npos ||
           line.find(",chain\n") != std::string::npos ||
           (line.size() >= 6 && line.compare(line.size() - 6, 6, ",chain") == 0);
  };

  for (const auto& line_raw : lines) {
    std::string line = trim(line_raw);
    if (line.empty() || line.rfind("#", 0) == 0) continue;

    if (line.rfind("Include ", 0) == 0) {
      if (pending_chain) {
        // Orphan chain: still flush what we have and continue (ModSecurity will error).
        pending_chain = false;
      }
      if (!flushInline()) return false;
      std::string target = trim(line.substr(8));
      if (!resolveIncludeLoad(target, loader, user, seen, error)) return false;
      continue;
    }

    const bool phrase_file = is_file_phrase_op(line);
    const bool is_chain_parent = !pending_chain && line_requests_chain(line);

    // Phrase-file operators: load in isolation (flush before and after).
    if (phrase_file) {
      if (pending_chain) {
        // Unusual: chain parent then @pmFromFile child — keep together.
      } else if (!flushInline()) {
        return false;
      }
      inline_batch.append(line);
      inline_batch.push_back('\n');
      pending_chain = line_requests_chain(line);
      if (!pending_chain) {
        if (!flushInline()) return false;
      }
      continue;
    }

    // Isolate SecRule chains (parent + children) in their own msc_rules_add
    // chunk. Path B REQUEST-949 rule 949111 (deny+chain) loaded in the same
    // batch as many setvar score rules has trapped Envoy V8 as "unreachable".
    // Keep parent+children together; flush before the parent and after the
    // last child (line without chain).
    if (is_chain_parent) {
      if (!flushInline()) return false;
    } else if (!inline_batch.empty() && !pending_chain &&
               inline_batch.size() + line.size() + 1 > kMaxInlineChunkBytes) {
      // Single oversize line still loads alone (cannot split mid-directive),
      // unless we are holding a chain parent that must stay with its child.
      if (!flushInline()) return false;
    }

    inline_batch.append(line);
    inline_batch.push_back('\n');
    const bool was_pending = pending_chain || is_chain_parent;
    pending_chain = line_requests_chain(line);
    if (was_pending && !pending_chain) {
      // Completed chain (final child has no chain action) — load in isolation.
      if (!flushInline()) return false;
      continue;
    }
    if (!pending_chain && inline_batch.size() >= kMaxInlineChunkBytes) {
      if (!flushInline()) return false;
    }
  }

  return flushInline();
}

bool resolveIncludeExpand(const std::string& target, std::string& out, std::set<std::string>& seen,
                          std::string& error);

bool appendOwaspCrsGlobExpand(const modsecurity_proxy_wasm_rules::RuleAsset& asset, void* user) {
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

bool resolveIncludeExpand(const std::string& target, std::string& out, std::set<std::string>& seen,
                          std::string& error) {
  if (target == "@kubewaf-defaults") {
    return appendKubeWafDefaults(out, seen);
  }

  if (target == "@demo-conf" || target == "@ftw-conf") {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
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

  if (target == "@crs-setup-conf") {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = pathACatalogHint(target);
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
    int count = 0;
    modsecurity_proxy_wasm_rules::foreach_owasp_crs(
        [](const modsecurity_proxy_wasm_rules::RuleAsset&, void* user) -> bool {
          *static_cast<int*>(user) += 1;
          return true;
        },
        &count);
    if (count == 0) {
      error = pathACatalogHint(target);
      return false;
    }
    struct Ctx {
      std::string* out;
      std::set<std::string>* seen;
      std::string* error;
    } ctx{&out, &seen, &error};
    modsecurity_proxy_wasm_rules::foreach_owasp_crs(appendOwaspCrsGlobExpand, &ctx);
    return error.empty();
  }

  if (target.rfind("@owasp_crs/", 0) == 0) {
    const auto* asset = modsecurity_proxy_wasm_rules::lookup(target.c_str());
    if (asset == nullptr) {
      error = pathACatalogHint(target);
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

  std::vector<std::string> directives;
  if (!loadDirectiveList(json, profile, directives, error)) {
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

bool hasKubeWafIdentity(const std::string& config, const WafPluginOptions* opts) {
  if (opts != nullptr) {
    if (opts->mode == "kubewaf") {
      return true;
    }
    if (!opts->config_id.empty() && opts->config_id.rfind("kubewaf/", 0) == 0) {
      return true;
    }
    for (const auto& kv : opts->metrics.labels) {
      if (kv.first == "waf_name" || kv.first == "waf_namespace") {
        return true;
      }
    }
  }
  if (!looksLikeJson(trim(config))) {
    return false;
  }
  if (extractJsonStringValue(config, "mode") == "kubewaf") {
    return true;
  }
  std::string cid = extractJsonStringValue(config, "config_id");
  if (!cid.empty() && cid.rfind("kubewaf/", 0) == 0) {
    return true;
  }
  std::vector<std::pair<std::string, std::string>> labels;
  if (extractMetricLabels(config, labels)) {
    for (const auto& kv : labels) {
      if (kv.first == "waf_name" || kv.first == "waf_namespace") {
        return true;
      }
    }
  }
  return false;
}

void fillMetricOptions(const std::string& config, WafMetricOptions& out) {
  out.labels.clear();
  out.enabled = true;
  // Slim defaults: core tx/interrupt gauges only unless operator enables detail.
  out.per_rule_id = false;
  out.rule_tags = false;
  out.dual_prefix = false;

  if (!looksLikeJson(trim(config))) {
    return;
  }
  extractMetricLabels(config, out.labels);

  // Nested metrics object preferred; flat keys remain as aliases.
  std::string metrics_obj;
  if (extractJsonObjectSlice(config, "metrics", metrics_obj)) {
    out.enabled = extractJsonBoolValue(metrics_obj, "enabled", true);
    out.per_rule_id = extractJsonBoolValue(metrics_obj, "per_rule_id", false);
    out.rule_tags = extractJsonBoolValue(metrics_obj, "rule_tags", false);
    out.dual_prefix = extractJsonBoolValue(metrics_obj, "dual_prefix", false);
  } else {
    out.per_rule_id = extractJsonBoolValue(config, "metrics_per_rule_id", false);
    out.rule_tags = extractJsonBoolValue(config, "metrics_rule_tags", false);
    // Flat enable flag not historically present; default true.
    out.enabled = extractJsonBoolValue(config, "metrics_enabled", true);
  }

  // Flat aliases override nested when present (explicit operator knobs).
  if (config.find("\"metrics_per_rule_id\"") != std::string::npos) {
    out.per_rule_id = extractJsonBoolValue(config, "metrics_per_rule_id", out.per_rule_id);
  }
  if (config.find("\"metrics_rule_tags\"") != std::string::npos) {
    out.rule_tags = extractJsonBoolValue(config, "metrics_rule_tags", out.rule_tags);
  }
}

void fillTransformOptions(const std::string& config, WafPluginOptions& out) {
  // Default on: CRS fullwidth XSS (941110-7/8). Operators / perf profiles can disable.
  out.fullwidth_normalize = true;
  if (!looksLikeJson(trim(config))) {
    return;
  }
  std::string transforms_obj;
  if (extractJsonObjectSlice(config, "transforms", transforms_obj)) {
    out.fullwidth_normalize =
        extractJsonBoolValue(transforms_obj, "fullwidth_normalize", true);
  } else if (config.find("\"fullwidth_normalize\"") != std::string::npos) {
    // Flat alias for simple smoke configs.
    out.fullwidth_normalize = extractJsonBoolValue(config, "fullwidth_normalize", true);
  }
}

void fillBlockOptions(const std::string& config, WafBlockOptions& out) {
  out = WafBlockOptions{};
  if (!looksLikeJson(trim(config))) {
    return;
  }
  std::string block_obj;
  if (extractJsonObjectSlice(config, "block", block_obj)) {
    std::string msg = extractJsonStringValue(block_obj, "message");
    if (!msg.empty()) {
      out.message = msg;
    }
    out.status = extractJsonIntValue(block_obj, "status", 0);
    // Explicit empty string is allowed to omit the marker header.
    if (block_obj.find("\"blocked_header\"") != std::string::npos) {
      out.blocked_header = extractJsonStringValue(block_obj, "blocked_header");
    }
    out.add_rule_id_header = extractJsonBoolValue(block_obj, "add_rule_id_header", false);
    std::string hdr = extractJsonStringValue(block_obj, "rule_id_header");
    if (!hdr.empty()) {
      out.rule_id_header = hdr;
    }
    out.add_request_id_header = extractJsonBoolValue(block_obj, "add_request_id_header", false);
    std::string req_hdr = extractJsonStringValue(block_obj, "request_id_header");
    if (!req_hdr.empty()) {
      out.request_id_header = req_hdr;
    }
  } else {
    std::string msg = extractJsonStringValue(config, "block_message");
    if (!msg.empty()) {
      out.message = msg;
    }
  }
}

}  // namespace

const char* kubeWafDefaultsConf() { return kKubeWafDefaultsConf; }

const char* defaultWafJsonConfig() {
  // Path B–oriented default: helpers only (no Path A CRS includes).
  return R"({
  "directives_map": {
    "default": [
      "Include @kubewaf-defaults",
      "Include @demo-conf",
      "SecDebugLogLevel 9",
      "SecRuleEngine On"
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

bool parseWafMetricOptions(const std::string& config, WafMetricOptions& out) {
  fillMetricOptions(config, out);
  return true;
}

// Max sizes for runtime data_files inflate (aligned with operator 2 MiB budget).
static constexpr std::size_t kMaxDataFileInflatedBytes = 2 * 1024 * 1024;
static constexpr std::size_t kMaxDataFilesTotalInflatedBytes = 2 * 1024 * 1024;

// Minimal object-map extractor: "data_files": { "a.data": "b64...", ... }
// Values must be JSON strings (base64 or gzip+base64 payloads).
bool extractDataFilesObject(const std::string& json,
                            std::unordered_map<std::string, std::string>& encoded,
                            std::string& error) {
  encoded.clear();
  const std::string key = "\"data_files\"";
  size_t pos = json.find(key);
  if (pos == std::string::npos) {
    return true;  // optional
  }
  pos = json.find('{', pos + key.size());
  if (pos == std::string::npos) {
    error = "data_files is not an object";
    return false;
  }
  size_t i = pos + 1;
  while (i < json.size()) {
    while (i < json.size() && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' ||
                               json[i] == '\t' || json[i] == ',')) {
      ++i;
    }
    if (i < json.size() && json[i] == '}') {
      return true;
    }
    if (i >= json.size() || json[i] != '"') {
      error = "data_files: expected string key";
      return false;
    }
    ++i;
    size_t key_end = i;
    while (key_end < json.size() && json[key_end] != '"') {
      if (json[key_end] == '\\') ++key_end;  // skip escaped
      ++key_end;
    }
    if (key_end >= json.size()) {
      error = "data_files: unterminated key";
      return false;
    }
    std::string fname = json.substr(i, key_end - i);
    i = key_end + 1;
    while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == ':')) ++i;
    if (i >= json.size() || json[i] != '"') {
      error = "data_files: expected string value for " + fname;
      return false;
    }
    ++i;
    std::string val;
    while (i < json.size() && json[i] != '"') {
      if (json[i] == '\\' && i + 1 < json.size()) {
        val.push_back(json[i + 1]);
        i += 2;
        continue;
      }
      val.push_back(json[i++]);
    }
    if (i >= json.size()) {
      error = "data_files: unterminated value for " + fname;
      return false;
    }
    ++i;  // closing quote
    encoded[fname] = std::move(val);
  }
  error = "data_files: unclosed object";
  return false;
}

bool parseDataFiles(const std::string& config,
                    std::unordered_map<std::string, std::string>& out,
                    std::string& error) {
  out.clear();
  error.clear();
  if (!looksLikeJson(trim(config))) {
    return true;
  }
  std::unordered_map<std::string, std::string> encoded;
  if (!extractDataFilesObject(config, encoded, error)) {
    return false;
  }
  if (encoded.empty()) {
    return true;
  }
  std::string encoding = extractJsonStringValue(config, "data_files_encoding");
  if (encoding.empty()) {
    encoding = "base64";
  }
  std::size_t total = 0;
  for (const auto& kv : encoded) {
    std::string decoded;
    if (encoding == "gzip+base64" || encoding == "gzip") {
      std::string compressed;
      if (!base64Decode(kv.second, compressed, error)) {
        error = "data_files[" + kv.first + "]: " + error;
        return false;
      }
      if (!gzipInflate(compressed, decoded, error)) {
        error = "data_files[" + kv.first + "]: " + error;
        return false;
      }
    } else {
      // base64 (plain)
      if (!base64Decode(kv.second, decoded, error)) {
        error = "data_files[" + kv.first + "]: " + error;
        return false;
      }
    }
    if (decoded.size() > kMaxDataFileInflatedBytes) {
      error = "data_files[" + kv.first + "]: exceeds max inflated size";
      return false;
    }
    total += decoded.size();
    if (total > kMaxDataFilesTotalInflatedBytes) {
      error = "data_files total inflated size exceeds max";
      return false;
    }
    out[kv.first] = std::move(decoded);
  }
  return true;
}

bool parseWafPluginOptions(const std::string& config, WafPluginOptions& out) {
  out = WafPluginOptions{};
  if (!looksLikeJson(trim(config))) {
    return true;
  }
  fillMetricOptions(config, out.metrics);
  fillBlockOptions(config, out.block);
  fillTransformOptions(config, out);
  out.mode = extractJsonStringValue(config, "mode");
  out.config_id = extractJsonStringValue(config, "config_id");
  out.allow_fallback = extractJsonBoolValue(config, "allow_fallback", false);
  // kubeWAF operator path is always fail-closed.
  if (hasKubeWafIdentity(config, &out)) {
    out.allow_fallback = false;
    // Never expose product/vendor names on client-visible deny replies.
    if (out.block.message == "blocked by modsecurity" ||
        out.block.message == "blocked by kubeWAF") {
      out.block.message = "Forbidden";
    }
    // Product dashboards expect kubewaf_waf.* unless dual_prefix was set explicitly.
    const bool dual_explicit =
        (config.find("\"dual_prefix\"") != std::string::npos) ||
        (config.find("\"metrics_dual_prefix\"") != std::string::npos);
    if (!dual_explicit) {
      out.metrics.dual_prefix = true;
    }
  }
  return true;
}

bool wafConfigAllowsFallback(const std::string& config) {
  if (!looksLikeJson(trim(config))) {
    return false;
  }
  if (hasKubeWafIdentity(config, nullptr)) {
    return false;
  }
  return extractJsonBoolValue(config, "allow_fallback", false);
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
