#include "wasm_vfs.h"

#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>

#include "generated/rules_catalog.h"

namespace {

constexpr char kRulesDir[] = "/modsecurity-proxy-wasm-rules";
constexpr char kCrsDataPrefix[] = "@crs-data/";
constexpr size_t kCrsDataPrefixLen = sizeof(kCrsDataPrefix) - 1;

// Configure-scoped runtime map (basename → body). Preferred over catalog.
// Single-threaded sequential onConfigure assumption (proxy-wasm V8).
std::unordered_map<std::string, std::string> g_runtime_data_files;

std::string ruleRefPathImpl(const char* label) {
  static thread_local std::string ref;
  ref.clear();
  ref.append(kRulesDir);
  ref.push_back('/');

  if (label == nullptr || label[0] == '\0') {
    ref.append("rules.conf");
    return ref;
  }

  const std::string_view l(label);
  if (l == "inline-directives") {
    ref.append("inline.conf");
    return ref;
  }
  if (l == "@demo-conf") {
    ref.append("demo-conf.conf");
    return ref;
  }
  if (l == "@kubewaf-defaults") {
    ref.append("kubewaf-defaults.conf");
    return ref;
  }
  if (l == "@crs-setup-conf") {
    ref.append("crs-setup.conf");
    return ref;
  }
  if (l.rfind("@owasp_crs/", 0) == 0) {
    ref.append(l.substr(11));
    return ref;
  }
  if (l == "plain-config") {
    ref.append("plain.conf");
    return ref;
  }
  if (l.front() == '@') {
    ref.append(l.substr(1));
    return ref;
  }
  ref.append(l);
  return ref;
}

// Count embedded CRS .data assets (sanity for configure).
int countCrsDataFiles() {
  int n = 0;
  modsecurity_proxy_wasm_rules::foreach_crs_data_file(
      [](const modsecurity_proxy_wasm_rules::RuleAsset&, void* user) -> bool {
        *static_cast<int*>(user) += 1;
        return true;
      },
      &n);
  return n;
}

}  // namespace

// Called from ModSecurity PmFromFile (patched) instead of ifstream when the
// Envoy V8 runtime has no writable filesystem. name is a CRS .data basename
// (e.g. "scanners-user-agents.data") or a path ending in that basename.
// Prefer runtime data_files (path-b operator inject); fall back to @crs-data catalog
// only when present (full / Path A builds).
extern "C" const char* modsecurity_proxy_wasm_resolve_data_file(const char* name,
                                                                std::size_t* out_size) {
  if (name == nullptr || name[0] == '\0') {
    return nullptr;
  }
  // Basename only (find_resource may pass "dir/file.data").
  const char* base = name;
  if (const char* slash = std::strrchr(name, '/')) {
    base = slash + 1;
  }
  if (const char* bslash = std::strrchr(base, '\\')) {
    base = bslash + 1;
  }
  if (base[0] == '\0') {
    return nullptr;
  }

  // 1) Configure-scoped runtime map (plugin JSON data_files) — primary for path-b.
  if (!g_runtime_data_files.empty()) {
    auto it = g_runtime_data_files.find(base);
    if (it != g_runtime_data_files.end()) {
      if (out_size != nullptr) {
        *out_size = it->second.size();
      }
      return it->second.data();
    }
  }

  // 2) Optional embedded CRS catalog (full catalog builds only; path-b embeds none).
  std::string key;
  key.reserve(kCrsDataPrefixLen + std::strlen(base));
  key.append(kCrsDataPrefix);
  key.append(base);

  const auto* asset = modsecurity_proxy_wasm_rules::lookup(key.c_str());
  if (asset == nullptr || asset->data == nullptr) {
    return nullptr;
  }
  if (out_size != nullptr) {
    *out_size = asset->size;
  }
  return asset->data;
}

void modsecurity_proxy_wasm_set_runtime_data_files(
    const std::unordered_map<std::string, std::string>& files) {
  g_runtime_data_files = files;
}

void modsecurity_proxy_wasm_clear_runtime_data_files() {
  g_runtime_data_files.clear();
}

bool modsecurity_proxy_wasm_mount_crs_data_files() {
  // Envoy V8 has no writable host FS. Phrase lists are served via
  // modsecurity_proxy_wasm_resolve_data_file from:
  //   1) plugin JSON data_files (path-b / operator inject) and/or
  //   2) optional @crs-data catalog (full builds only).
  // Empty catalog is OK for path-b when rules either need no @pmFromFile or
  // receive bodies via data_files. Missing basenames fail at PmFromFile::init.
  (void)countCrsDataFiles();
  return true;
}

const char* modsecurity_proxy_wasm_rule_ref_path(const char* label) {
  static thread_local std::string storage;
  storage = ruleRefPathImpl(label);
  return storage.c_str();
}
