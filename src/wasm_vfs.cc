#include "wasm_vfs.h"

#include <cstring>
#include <string>
#include <string_view>

#include "generated/rules_catalog.h"

namespace {

constexpr char kRulesDir[] = "/modsecurity-proxy-wasm-rules";

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

}  // namespace

bool modsecurity_proxy_wasm_mount_crs_data_files() {
  // @pmFromFile lists are expanded into @pm at build time (generate_rules_catalog.py).
  // Envoy's V8 runtime does not provide WASI path_open or Emscripten embed FS loaders.
  (void)modsecurity_proxy_wasm_rules::lookup;
  return true;
}

const char* modsecurity_proxy_wasm_rule_ref_path(const char* label) {
  static thread_local std::string storage;
  storage = ruleRefPathImpl(label);
  return storage.c_str();
}