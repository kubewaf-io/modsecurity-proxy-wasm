// modsecurity-proxy-wasm: ModSecurity WASM module for Envoy using proxy-wasm-cpp-sdk
// Product engine for kubeWAF (also usable standalone). Supports loading rules
// (including CRS via configuration or defaults). Must be compiled with Emscripten
// for compatibility with Envoy's v8 WASM runtime.

#include <cstdio>
#include <string>
#include <string_view>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <utility>
#include <vector>

#include "proxy_wasm_intrinsics.h"
#include "metrics.h"
#include "version.h"
#include "waf_config.h"
#include "wasm_vfs.h"

static bool methodMayHaveBody(const std::string& method) {
  return method != "GET" && method != "HEAD" && method != "OPTIONS" && method != "TRACE";
}

static bool statusMayHaveBody(int status) {
  if (status < 200) {
    return false;
  }
  return status != 204 && status != 304;
}

static bool headerNameEquals(std::string_view name, std::string_view target) {
  if (name.size() != target.size()) {
    return false;
  }
  for (size_t i = 0; i < name.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(name[i])) !=
        std::tolower(static_cast<unsigned char>(target[i]))) {
      return false;
    }
  }
  return true;
}

static bool isChunkedTransferEncoding(std::string_view value) {
  std::string lower(value);
  for (auto& c : lower) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return lower.find("chunked") != std::string::npos;
}

static size_t parseContentLength(std::string_view cl) {
  if (cl.empty()) {
    return 0;
  }
  char* end = nullptr;
  unsigned long long v = std::strtoull(cl.data(), &end, 10);
  if (end == cl.data()) {
    return 0;
  }
  return static_cast<size_t>(v);
}

// Envoy `request.protocol` is typically "HTTP/1.1" or "HTTP/2".
// ModSecurity processURI() takes the bare version token ("1.1", "2.0") and sets
// REQUEST_PROTOCOL to "HTTP/" + token. Passing a full "HTTP/1.1" would double the prefix.
static std::string modsecHttpVersionToken(std::string protocol) {
  if (protocol.size() >= 5) {
    const char c0 = static_cast<char>(std::tolower(static_cast<unsigned char>(protocol[0])));
    if (c0 == 'h' && (protocol.compare(1, 4, "TTP/") == 0 || protocol.compare(1, 4, "ttp/") == 0)) {
      protocol = protocol.substr(5);
    }
  }
  if (protocol.empty()) {
    return "1.1";
  }
  // Envoy often reports HTTP/2 and HTTP/3 without a minor component.
  if (protocol == "2") {
    return "2.0";
  }
  if (protocol == "3") {
    return "3.0";
  }
  return protocol;
}

static std::string modsecHttpProtocol(const std::string& version_token) {
  return std::string("HTTP/") + version_token;
}

// Sanitize text for classic ModSecurity log fragments: [id "N"] [msg "..."].
static std::string classicLogSanitize(std::string_view s, size_t max_len) {
  std::string out;
  out.reserve(std::min(s.size(), max_len));
  for (size_t i = 0; i < s.size() && out.size() < max_len; ++i) {
    const char c = s[i];
    if (c == '"' || c == '[' || c == ']' || c == '\n' || c == '\r' || c == '\t') {
      out.push_back(' ');
    } else if (static_cast<unsigned char>(c) < 0x20) {
      out.push_back(' ');
    } else {
      out.push_back(c);
    }
  }
  return out;
}

// ModSecurity v3 headers
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"
#include "modsecurity/intervention.h"
#include "modsecurity/debug_log.h"
#include "modsecurity/rule_message.h"

using modsecurity::ModSecurity;
using modsecurity::RulesSet;
using modsecurity::Transaction;
using modsecurity::ModSecurityIntervention;
using modsecurity::RuleMessage;

class ModSecRootContext : public RootContext {
public:
  explicit ModSecRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}

  bool onConfigure(size_t configuration_size) override;
  bool onStart(size_t) override;

  ModSecurity* modsec_{nullptr};
  RulesSet* rules_{nullptr};
  ModSecMetrics metrics_;
  WafPluginOptions plugin_options_;

private:
  bool readPluginConfig(size_t configuration_size, std::string& config);
};

class ModSecContext : public Context {
public:
  explicit ModSecContext(uint32_t id, RootContext* root) : Context(id, root) {}

  void onCreate() override;
  void recordRuleMatch(const RuleMessage& rule_message);
  void noteDisruptiveRule(int64_t rule_id) { last_disruptive_rule_id_ = rule_id; }
  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onRequestBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterTrailersStatus onRequestTrailers(uint32_t trailers) override;
  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onResponseBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterTrailersStatus onResponseTrailers(uint32_t trailers) override;
  void onDelete() override;

  Transaction* transaction_{nullptr};

private:
  size_t request_body_received_{0};
  bool request_body_processed_{false};
  size_t response_body_received_{0};
  bool response_body_processed_{false};
  bool response_body_interrupted_{false};
  bool interrupted_{false};
  int64_t last_disruptive_rule_id_{0};
  std::string request_id_;
  std::string method_;
  std::string path_;
  std::string client_ip_;
  // Bare version token for ModSecurity (e.g. "1.1", "2.0"); derived from Envoy request.protocol.
  std::string http_version_token_{"1.1"};
  ModSecRootContext* rootContext() { return static_cast<ModSecRootContext*>(root()); }

  void activateContext();
  int processIntervention(const char* phase);
  void finalizeResponseBodyPhase();
  void sendBlockLocalResponse(int status);
  FilterHeadersStatus sendBlockResponse(int status);
  FilterDataStatus sendBlockResponseData(int status);
  FilterTrailersStatus sendBlockResponseTrailers(int status);
  FilterDataStatus sanitizeInterruptedResponseBody(size_t body_buffer_length);
  void appendBufferedRequestBody();
  void appendBufferedResponseBody(size_t& buffer_size);
  void logRequestBodyProcessorErrors();
  void logStructuredEvent(const char* event, int64_t rule_id, int phase, const char* phase_name,
                          int severity, bool disruptive, const std::string& msg,
                          const std::string& tags_csv, const std::string& data = "",
                          const std::string& match = "");
};

static RegisterContextFactory register_ModSecContext(CONTEXT_FACTORY(ModSecContext),
                                                     ROOT_FACTORY(ModSecRootContext));

static thread_local ModSecContext* g_active_modsec_context = nullptr;

// ---------------------------------------------------------------------------
// JSON logging (one primary JSON object per Envoy wasm log line).
// go-ftw recognizes `"id":N` / `"ruleId":N` via its JSON rule-id regex.
// Rule-match lines also append a classic `[id "N"] [msg "…"]` fragment for
// go-ftw match_regex tests (CRS 922130). Keep lines compact — Envoy truncates
// wasm log lines (~512 chars with prefix).
// ---------------------------------------------------------------------------

static std::string jsonEscape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
          out += buf;
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

// Emit a pure-JSON lifecycle/diagnostic line. `fields` is a comma-joined fragment
// of additional JSON members without a leading comma (may be empty).
static void logJson(bool is_error, const char* event, const std::string& fields = {}) {
  std::ostringstream js;
  js << "{\"component\":\"modsecurity-proxy-wasm\",\"event\":\"" << event << "\"";
  if (!fields.empty()) {
    js << "," << fields;
  }
  js << "}";
  if (is_error) {
    LOG_ERROR(js.str());
  } else {
    LOG_WARN(js.str());
  }
}

// Fallback rule-match line when no stream context is active (rare configure-time).
// "id" is required for go-ftw JSON log parsing.
// Classic [id "N"] [msg "..."] tail is required for go-ftw match_regex tests (e.g. 922130).
static void logRuleMatchJson(const RuleMessage& rule_message) {
  std::ostringstream js;
  js << "{\"component\":\"modsecurity-proxy-wasm\",\"event\":\"rule_match\""
     << ",\"engine\":\"modsecurity\""
     << ",\"id\":" << rule_message.m_rule.m_ruleId
     << ",\"rule_id\":" << rule_message.m_rule.m_ruleId
     << ",\"phase\":" << rule_message.getPhase()
     << ",\"severity\":" << rule_message.m_severity
     << ",\"disruptive\":" << (rule_message.m_isDisruptive ? "true" : "false");
  if (!rule_message.m_message.empty()) {
    js << ",\"msg\":\"" << jsonEscape(rule_message.m_message.substr(0, 256)) << "\"";
  }
  // data/match carry X-CRS-Test marker values for go-ftw log synchronization.
  if (!rule_message.m_data.empty()) {
    js << ",\"data\":\"" << jsonEscape(rule_message.m_data.substr(0, 180)) << "\"";
  }
  if (!rule_message.m_match.empty()) {
    js << ",\"match\":\"" << jsonEscape(rule_message.m_match.substr(0, 180)) << "\"";
  }
  js << "}";
  std::string line = js.str();
  if (rule_message.m_rule.m_ruleId > 0 && !rule_message.m_message.empty()) {
    line += " [id \"";
    line += std::to_string(rule_message.m_rule.m_ruleId);
    line += "\"] [msg \"";
    line += classicLogSanitize(rule_message.m_message, 180);
    line += "\"]";
  }
  LOG_WARN(line);
}

// Log callback for ModSecurity rule matches
static void modsecurity_proxy_wasm_log_cb(void* data, const void* ruleMessagev) {
  (void)data;
  if (ruleMessagev == nullptr) {
    logJson(false, "log_cb_null");
    return;
  }
  const RuleMessage* ruleMessage = reinterpret_cast<const RuleMessage*>(ruleMessagev);
  if (g_active_modsec_context != nullptr) {
    g_active_modsec_context->recordRuleMatch(*ruleMessage);
  } else {
    // Fallback when no active stream context (configure-time matches are rare).
    logRuleMatchJson(*ruleMessage);
  }
}

// Default minimal rules (engine on + basic). CRS can be appended via plugin config.
static const char* kDefaultRules = R"(
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
     "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
     "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
# Basic test rule (XSS-ish) - real CRS provides many more
SecRule ARGS "@rx <script" "id:1000,phase:2,deny,status:403,msg:'Basic XSS block'"
)";

namespace {

bool loadRuleChunk(const char* label, const char* data, std::size_t size, void* user, std::string& err) {
  if (data == nullptr || size == 0) {
    return true;
  }
  auto* rules = static_cast<RulesSet*>(user);
  const char* lab = (label != nullptr && label[0] != '\0') ? label : "(anonymous)";
  // Progress log — if Envoy dies with "unreachable" right after a label, that chunk is the culprit.
  {
    std::ostringstream fields;
    fields << "\"label\":\"" << jsonEscape(lab) << "\",\"bytes\":" << size;
    logJson(false, "rules_loading", fields.str());
  }
  // Always log a short preview for small inline chunks (custom user rules).
  if (size > 0 && size < 512) {
    std::string preview(data, size);
    // Collapse newlines so the JSON string stays single-line.
    for (char& c : preview) {
      if (c == '\n' || c == '\r') c = ' ';
    }
    std::ostringstream fields;
    fields << "\"label\":\"" << jsonEscape(lab) << "\",\"preview\":\"" << jsonEscape(preview) << "\"";
    logJson(false, "rules_preview", fields.str());
  }

  // Keep ref in a real std::string for the duration of load() (API takes const std::string&).
  std::string ref(modsecurity_proxy_wasm_rule_ref_path(label));
  // Always copy into a mutable buffer. RulesSet::load may mutate/parse in place;
  // zero-copy into read-only catalog/rodata has caused unreachable traps on some
  // custom SecRule text after a full CRS load.
  std::string chunk;
  chunk.reserve(size + 1);
  chunk.assign(data, size);
  int ret = rules->load(chunk.c_str(), ref);
  if (ret < 0) {
    err = rules->m_parserError.str();
    if (err.empty()) {
      err = std::string("RulesSet::load failed for ") + lab;
    }
    std::ostringstream fields;
    fields << "\"label\":\"" << jsonEscape(lab) << "\",\"error\":\"" << jsonEscape(err) << "\"";
    logJson(true, "rules_load_failed", fields.str());
    return false;
  }
  {
    std::ostringstream fields;
    fields << "\"label\":\"" << jsonEscape(lab) << "\"";
    logJson(false, "rules_loaded", fields.str());
  }
  return true;
}

}  // namespace

bool ModSecRootContext::onStart(size_t /*vm_configuration_size*/) {
  // First log line from this VM — use it to confirm which .wasm Envoy actually loaded.
  // Also touch embedded metadata so LTO cannot strip the inspect-wasm block.
  (void)modsecurity_proxy_wasm_metadata();
  LOG_WARN(MODSECURITY_PROXY_WASM_VERSION_LINE);
  return true;
}

bool ModSecRootContext::onConfigure(size_t configuration_size) {
  // Repeat version first on every configure (Envoy may not surface onStart in all dumps).
  (void)modsecurity_proxy_wasm_metadata();
  LOG_WARN(MODSECURITY_PROXY_WASM_VERSION_LINE);
  {
    std::ostringstream fields;
    fields << "\"size\":" << configuration_size;
    logJson(false, "configure_start", fields.str());
  }

  std::string config;
  if (!readPluginConfig(configuration_size, config)) {
    logJson(true, "configure_failed", "\"error\":\"Failed to read plugin configuration\"");
    return false;
  }

  if (!parseWafPluginOptions(config, plugin_options_)) {
    logJson(true, "configure_failed", "\"error\":\"Failed to parse plugin configuration options\"");
    return false;
  }
  metrics_.configure(plugin_options_.metrics);

  std::string connector = "kubeWAF/modsecurity-proxy-wasm";
  if (!plugin_options_.config_id.empty()) {
    connector.append(" (");
    connector.append(plugin_options_.config_id);
    connector.append(")");
  } else if (plugin_options_.mode == "kubewaf") {
    connector.append(" (mode=kubewaf)");
  } else {
    connector = "modsecurity-proxy-wasm/1.0 (Envoy proxy-wasm-cpp-sdk)";
  }

  modsec_ = new ModSecurity();
  modsec_->setConnectorInformation(connector);
  modsec_->setServerLogCb(modsecurity_proxy_wasm_log_cb, modsecurity::RuleMessageLogProperty);

  rules_ = new RulesSet();

  // Phrase lists live in the embedded catalog and are served to PmFromFile via
  // modsecurity_proxy_wasm_resolve_data_file (Envoy V8 has no writable MEMFS).
  if (!modsecurity_proxy_wasm_mount_crs_data_files()) {
    logJson(true, "configure_failed",
            "\"error\":\"CRS .data catalog missing — @pmFromFile rules will not load\"");
    return false;
  }
  logJson(false, "crs_data_ready", "\"source\":\"catalog\"");

  std::string err;
  if (!applyWafConfiguration(config, loadRuleChunk, rules_, err)) {
    if (!plugin_options_.allow_fallback || !wafConfigAllowsFallback(config)) {
      std::ostringstream fields;
      fields << "\"error\":\"" << jsonEscape(err) << "\",\"fail_closed\":true";
      logJson(true, "config_load_failed", fields.str());
      return false;
    }
    {
      std::ostringstream fields;
      fields << "\"error\":\"" << jsonEscape(err)
             << "\",\"allow_fallback\":true,\"action\":\"load_minimal_builtin\"";
      logJson(false, "config_load_failed", fields.str());
    }
    int ret = rules_->load(kDefaultRules);
    if (ret < 0) {
      std::ostringstream fields;
      fields << "\"error\":\"" << jsonEscape(rules_->m_parserError.str()) << "\"";
      logJson(true, "fallback_rules_failed", fields.str());
      return false;
    }
    logJson(false, "fallback_rules_loaded");
    metrics_.countConfigureFallbackRules();
    return true;
  }

  {
    std::ostringstream fields;
    if (!plugin_options_.config_id.empty()) {
      fields << "\"config_id\":\"" << jsonEscape(plugin_options_.config_id) << "\",";
    }
    if (!plugin_options_.mode.empty()) {
      fields << "\"mode\":\"" << jsonEscape(plugin_options_.mode) << "\",";
    }
    fields << "\"metric_labels\":" << plugin_options_.metrics.labels.size()
           << ",\"per_rule_id\":" << (plugin_options_.metrics.per_rule_id ? "true" : "false")
           << ",\"stats\":" << (plugin_options_.metrics.enabled ? "true" : "false");
    logJson(false, "config_applied", fields.str());
  }
  return true;
}

bool ModSecRootContext::readPluginConfig(size_t configuration_size, std::string& config) {
  if (configuration_size > 0) {
    auto buf = getBufferBytes(WasmBufferType::PluginConfiguration, 0, configuration_size);
    if (!buf) {
      return false;
    }
    config.assign(buf->view());
    return true;
  }
  config.assign(defaultWafJsonConfig());
  return true;
}

void ModSecContext::onCreate() {
  request_body_received_ = 0;
  request_body_processed_ = false;
  response_body_received_ = 0;
  response_body_processed_ = false;
  response_body_interrupted_ = false;
  interrupted_ = false;
  last_disruptive_rule_id_ = 0;
  request_id_.clear();
  method_.clear();
  path_.clear();
  client_ip_.clear();
  http_version_token_ = "1.1";
}

void ModSecContext::activateContext() {
  g_active_modsec_context = this;
}

void ModSecContext::logStructuredEvent(const char* event, int64_t rule_id, int phase,
                                       const char* phase_name, int severity, bool disruptive,
                                       const std::string& msg, const std::string& tags_csv,
                                       const std::string& data, const std::string& match) {
  auto* root = rootContext();
  std::ostringstream js;
  // Pure JSON — no text prefix. component identifies the filter in Envoy multi-plugin dumps.
  js << "{\"component\":\"modsecurity-proxy-wasm\",\"event\":\"" << event << "\""
     << ",\"engine\":\"modsecurity\"";
  if (!root->plugin_options_.config_id.empty()) {
    js << ",\"config_id\":\"" << jsonEscape(root->plugin_options_.config_id) << "\"";
  }
  if (!root->plugin_options_.mode.empty()) {
    js << ",\"mode\":\"" << jsonEscape(root->plugin_options_.mode) << "\"";
  }
  for (const auto& kv : root->plugin_options_.metrics.labels) {
    if (kv.first == "waf_namespace" || kv.first == "waf_name" || kv.first == "engine") {
      js << ",\"" << jsonEscape(kv.first) << "\":\"" << jsonEscape(kv.second) << "\"";
    }
  }
  if (!request_id_.empty()) {
    js << ",\"request_id\":\"" << jsonEscape(request_id_) << "\"";
  }
  if (!method_.empty()) {
    js << ",\"method\":\"" << jsonEscape(method_) << "\"";
  }
  if (!path_.empty()) {
    // Truncate path for log volume / PII risk.
    std::string p = path_.substr(0, 256);
    js << ",\"path\":\"" << jsonEscape(p) << "\"";
  }
  if (!client_ip_.empty()) {
    js << ",\"client_ip\":\"" << jsonEscape(client_ip_) << "\"";
  }
  if (rule_id > 0) {
    // "id" is recognized by go-ftw's JSON log parser; keep rule_id for kubeWAF consumers.
    js << ",\"id\":" << rule_id << ",\"rule_id\":" << rule_id;
  }
  if (phase >= 0) {
    js << ",\"phase\":" << phase;
  }
  if (phase_name != nullptr && phase_name[0] != '\0') {
    js << ",\"phase_name\":\"" << jsonEscape(phase_name) << "\"";
  }
  if (severity >= 0) {
    js << ",\"severity\":" << severity;
  }
  js << ",\"disruptive\":" << (disruptive ? "true" : "false");
  if (!msg.empty()) {
    js << ",\"msg\":\"" << jsonEscape(msg.substr(0, 256)) << "\"";
  }
  // data/match carry matched values (incl. X-CRS-Test markers for go-ftw).
  if (!data.empty()) {
    js << ",\"data\":\"" << jsonEscape(data.substr(0, 180)) << "\"";
  }
  if (!match.empty()) {
    js << ",\"match\":\"" << jsonEscape(match.substr(0, 180)) << "\"";
  }
  if (!tags_csv.empty()) {
    js << ",\"tags\":\"" << jsonEscape(tags_csv.substr(0, 256)) << "\"";
  }
  js << "}";
  std::string line = js.str();
  // Classic ModSecurity fragment for go-ftw match_regex (CRS 922130 and similar).
  // Kept on the same line so the JSON object remains the primary record.
  if (rule_id > 0 && !msg.empty()) {
    line += " [id \"";
    line += std::to_string(rule_id);
    line += "\"] [msg \"";
    line += classicLogSanitize(msg, 180);
    line += "\"]";
  }
  LOG_WARN(line);
}

void ModSecContext::logRequestBodyProcessorErrors() {
  if (!transaction_) {
    return;
  }
  // Public AnchoredVariable members on Transaction (libModSecurity v3).
  std::string* err_flag = transaction_->m_variableReqbodyError.evaluate();
  std::string* proc_flag = transaction_->m_variableReqbodyProcessorError.evaluate();
  const bool has_error =
      (err_flag != nullptr && *err_flag == "1") || (proc_flag != nullptr && *proc_flag == "1");
  if (!has_error) {
    return;
  }
  std::string* msg = transaction_->m_variableReqbodyErrorMsg.evaluate();
  if (msg == nullptr || msg->empty()) {
    msg = transaction_->m_variableReqbodyProcessorErrorMsg.evaluate();
  }
  if (msg == nullptr || msg->empty()) {
    return;
  }
  // Raw engine text is required for go-ftw match_regex on multipart parse failures:
  // "Multipart parsing error: Multipart: Invalid part header (contains invalid character)"
  LOG_WARN(*msg);
  logJson(false, "reqbody_error",
          std::string("\"msg\":\"") + jsonEscape(msg->substr(0, 256)) + "\"");
}

void ModSecContext::recordRuleMatch(const RuleMessage& rule_message) {
  if (rule_message.m_isDisruptive) {
    noteDisruptiveRule(rule_message.m_rule.m_ruleId);
  }
  rootContext()->metrics_.countRuleMatch(rule_message.getPhase(), rule_message.m_severity,
                                         rule_message.m_isDisruptive, rule_message.m_rule.m_ruleId,
                                         rule_message.m_tags);

  std::string tags_csv;
  for (const auto& t : rule_message.m_tags) {
    if (!tags_csv.empty()) tags_csv.push_back(',');
    tags_csv.append(t);
    if (tags_csv.size() > 200) break;
  }
  // Single pure-JSON line: go-ftw parses "id"; msg/data carry marker text.
  logStructuredEvent("rule_match", rule_message.m_rule.m_ruleId, rule_message.getPhase(), nullptr,
                     rule_message.m_severity, rule_message.m_isDisruptive, rule_message.m_message,
                     tags_csv, rule_message.m_data, rule_message.m_match);
}

int ModSecContext::processIntervention(const char* phase) {
  ModSecurityIntervention intervention;
  intervention.status = 200;
  intervention.url = nullptr;
  intervention.log = nullptr;
  intervention.disruptive = 0;

  if (!transaction_->intervention(&intervention)) {
    return 0;
  }

  interrupted_ = true;
  rootContext()->metrics_.countTxInterruption(phase, last_disruptive_rule_id_);

  int status = intervention.status;
  std::string intervention_msg;
  if (intervention.log != nullptr) {
    intervention_msg = intervention.log;
    free(intervention.log);
  }
  if (intervention.url != nullptr) {
    free(intervention.url);
  }

  const auto& block = rootContext()->plugin_options_.block;
  if (block.status >= 100 && block.status <= 599) {
    status = block.status;
  }
  logStructuredEvent("tx_interrupt", last_disruptive_rule_id_, -1, phase, -1, true, intervention_msg,
                     "");
  return status;
}

void ModSecContext::sendBlockLocalResponse(int status) {
  if (status < 100 || status > 599) status = 403;
  const auto& block = rootContext()->plugin_options_.block;
  std::string details = block.message.empty() ? "blocked by kubeWAF" : block.message;
  std::vector<std::pair<std::string, std::string>> extra_headers;
  extra_headers.emplace_back("x-kubewaf-blocked", "1");
  if (block.add_rule_id_header && last_disruptive_rule_id_ > 0 && !block.rule_id_header.empty()) {
    extra_headers.emplace_back(block.rule_id_header, std::to_string(last_disruptive_rule_id_));
  }
  sendLocalResponse(static_cast<uint32_t>(status), details, "", extra_headers);
}

FilterHeadersStatus ModSecContext::sendBlockResponse(int status) {
  sendBlockLocalResponse(status);
  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus ModSecContext::sendBlockResponseData(int status) {
  sendBlockLocalResponse(status);
  return FilterDataStatus::StopIterationNoBuffer;
}

FilterTrailersStatus ModSecContext::sendBlockResponseTrailers(int status) {
  sendBlockLocalResponse(status);
  return FilterTrailersStatus::StopIteration;
}

void ModSecContext::appendBufferedRequestBody() {
  size_t buffer_size = 0;
  uint32_t flags = 0;
  if (getBufferStatus(WasmBufferType::HttpRequestBody, &buffer_size, &flags) != WasmResult::Ok) {
    return;
  }
  if (buffer_size <= request_body_received_) {
    return;
  }
  const size_t chunk_size = buffer_size - request_body_received_;
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, request_body_received_, chunk_size);
  if (body && body->size() > 0) {
    transaction_->appendRequestBody(reinterpret_cast<const unsigned char*>(body->data()), body->size());
    request_body_received_ += body->size();
  } else {
    request_body_received_ = buffer_size;
  }
}

void ModSecContext::appendBufferedResponseBody(size_t& buffer_size) {
  buffer_size = 0;
  uint32_t flags = 0;
  if (getBufferStatus(WasmBufferType::HttpResponseBody, &buffer_size, &flags) != WasmResult::Ok) {
    return;
  }
  if (buffer_size <= response_body_received_) {
    return;
  }
  const size_t chunk_size = buffer_size - response_body_received_;
  auto body = getBufferBytes(WasmBufferType::HttpResponseBody, response_body_received_, chunk_size);
  if (body && body->size() > 0) {
    transaction_->appendResponseBody(reinterpret_cast<const unsigned char*>(body->data()), body->size());
    response_body_received_ += body->size();
  } else {
    response_body_received_ = buffer_size;
  }
}

void ModSecContext::finalizeResponseBodyPhase() {
  if (!transaction_ || response_body_processed_) {
    return;
  }
  transaction_->processResponseBody();
  response_body_processed_ = true;
  response_body_received_ = 0;
}

FilterDataStatus ModSecContext::sanitizeInterruptedResponseBody(size_t body_buffer_length) {
  static const char kBlocked[] = "blocked by modsecurity\n";
  const std::string blocked(kBlocked);
  if (!response_body_interrupted_) {
    rootContext()->metrics_.countResponseBodySanitized();
  }
  if (body_buffer_length > 0) {
    setBuffer(WasmBufferType::HttpResponseBody, 0, body_buffer_length, blocked);
  }
  replaceResponseHeader("content-length", std::to_string(blocked.size()));
  response_body_interrupted_ = true;
  return FilterDataStatus::Continue;
}

FilterHeadersStatus ModSecContext::onRequestHeaders(uint32_t, bool end_of_stream) {
  auto* root = rootContext();
  if (!root->modsec_ || !root->rules_) {
    return FilterHeadersStatus::Continue;
  }

  activateContext();
  std::string tx_id = "wasm-" + std::to_string(id());
  transaction_ = new Transaction(root->modsec_, root->rules_, tx_id.c_str(), nullptr);
  root->metrics_.countTxTotal();

  std::string client_ip = "127.0.0.1";
  std::string server_ip = "127.0.0.1";
  uint64_t client_port = 0;
  uint64_t server_port = 0;
  getValue({"source", "address"}, &client_ip);
  getValue({"source", "port"}, &client_port);
  getValue({"destination", "address"}, &server_ip);
  getValue({"destination", "port"}, &server_port);
  client_ip_ = client_ip;

  std::string path = "/";
  std::string method = "GET";
  if (auto h = getRequestHeader(":path")) {
    path = h->toString();
  } else {
    getValue({"request", "headers", ":path"}, &path);
  }
  if (auto h = getRequestHeader(":method")) {
    method = h->toString();
  } else {
    getValue({"request", "headers", ":method"}, &method);
  }
  path_ = path;
  method_ = method;

  // Correlate with Envoy / client request id when present.
  if (auto h = getRequestHeader("x-request-id")) {
    request_id_ = h->toString();
  } else if (auto h = getRequestHeader("x-envoy-request-id")) {
    request_id_ = h->toString();
  } else {
    getValue({"request", "id"}, &request_id_);
  }
  if (request_id_.empty()) {
    request_id_ = tx_id;
  }

  transaction_->processConnection(client_ip.c_str(), static_cast<int>(client_port),
                                  server_ip.c_str(), static_cast<int>(server_port));
  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kRequestHeaders); st != 0) {
    return sendBlockResponse(st);
  }

  // Prefer Envoy's negotiated protocol so REQUEST_PROTOCOL / CRS 920430 see the real version.
  // Falls back to HTTP/1.1 when the property is unavailable (common on some runtimes).
  std::string request_protocol;
  getValue({"request", "protocol"}, &request_protocol);
  http_version_token_ = modsecHttpVersionToken(request_protocol);
  transaction_->processURI(path.c_str(), method.c_str(), http_version_token_.c_str());
  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kRequestHeaders); st != 0) {
    return sendBlockResponse(st);
  }

  size_t body_size = 0;
  bool has_host = false;
  bool chunked = false;
  if (auto headers_buf = getRequestHeaderPairs()) {
    for (auto& p : headers_buf->pairs()) {
      const std::string name = std::string(p.first);
      const std::string value = std::string(p.second);
      transaction_->addRequestHeader(name, value);
      if (name == "host" || name == "Host") {
        has_host = true;
      }
      if (headerNameEquals(name, "content-length")) {
        body_size = parseContentLength(value);
      }
      if (headerNameEquals(name, "transfer-encoding") && isChunkedTransferEncoding(value)) {
        chunked = true;
      }
    }
  }
  // Envoy HTTP/2 uses :authority; CRS expects Host (920280) without a bare numeric:port form.
  if (!has_host) {
    std::string authority;
    if (auto h = getRequestHeader(":authority")) {
      authority = h->toString();
    } else {
      getValue({"request", "headers", ":authority"}, &authority);
    }
    if (!authority.empty()) {
      std::string host = authority;
      if (host[0] == '[') {
        size_t end = host.find(']');
        if (end != std::string::npos) {
          host = host.substr(1, end - 1);
        }
      } else {
        const size_t colon = host.rfind(':');
        if (colon != std::string::npos && host.find(':') == colon) {
          host = host.substr(0, colon);
        }
      }
      transaction_->addRequestHeader("Host", host);
    }
  }
  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kRequestHeaders); st != 0) {
    return sendBlockResponse(st);
  }

  transaction_->processRequestHeaders();
  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kRequestHeaders); st != 0) {
    return sendBlockResponse(st);
  }

  // Phase-2 rules need request-body phase; processRequestBody() without a synthetic append.
  // HTTP/2 often omits Content-Length; if end_of_stream is false on headers, a body may still
  // follow even when body_size==0 and Transfer-Encoding is not chunked.
  const bool has_known_body = body_size > 0 || chunked;
  const bool may_receive_body = methodMayHaveBody(method) && !end_of_stream;
  const bool needs_body_buffer = has_known_body || may_receive_body;
  if (!needs_body_buffer) {
    // Run phase-2 without synthesizing a body byte; a fake append triggers CRS 920640 on GET.
    transaction_->processRequestBody();
    logRequestBodyProcessorErrors();
    request_body_processed_ = true;
    if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kRequestBody); st != 0) {
      return sendBlockResponse(st);
    }
    return FilterHeadersStatus::Continue;
  }

  // Continue on headers; buffer in onRequestBody via StopIterationAndBuffer.
  // (Requires routing to an upstream cluster — direct_response skips body callbacks.)
  return FilterHeadersStatus::Continue;
}

FilterTrailersStatus ModSecContext::onRequestTrailers(uint32_t) {
  if (!transaction_ || request_body_processed_) {
    return FilterTrailersStatus::Continue;
  }
  activateContext();
  // HTTP/2 may not set end_of_stream on the last body chunk when trailers follow.
  appendBufferedRequestBody();
  transaction_->processRequestBody();
  logRequestBodyProcessorErrors();
  request_body_processed_ = true;
  request_body_received_ = 0;
  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kRequestBody); st != 0) {
    return sendBlockResponseTrailers(st);
  }
  return FilterTrailersStatus::Continue;
}

FilterDataStatus ModSecContext::onRequestBody(size_t body_buffer_length, bool end_of_stream) {
  if (!transaction_) {
    return FilterDataStatus::Continue;
  }
  activateContext();
  if (request_body_processed_) {
    return FilterDataStatus::Continue;
  }
  // Envoy passes cumulative buffered size, not just the new chunk (see coraza-proxy-wasm).
  if (body_buffer_length > request_body_received_) {
    const size_t chunk_size = body_buffer_length - request_body_received_;
    auto body = getBufferBytes(WasmBufferType::HttpRequestBody, request_body_received_, chunk_size);
    if (body && body->size() > 0) {
      transaction_->appendRequestBody(reinterpret_cast<const unsigned char*>(body->data()), body->size());
      request_body_received_ += body->size();
    } else {
      request_body_received_ = body_buffer_length;
    }
  }

  if (!end_of_stream) {
    return FilterDataStatus::StopIterationAndBuffer;
  }

  transaction_->processRequestBody();
  logRequestBodyProcessorErrors();
  request_body_processed_ = true;
  request_body_received_ = 0;
  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kRequestBody); st != 0) {
    return sendBlockResponseData(st);
  }
  return FilterDataStatus::Continue;
}

FilterHeadersStatus ModSecContext::onResponseHeaders(uint32_t, bool end_of_stream) {
  if (!transaction_) {
    return FilterHeadersStatus::Continue;
  }
  activateContext();

  // HTTP/2 may not call onRequestBody with end_of_stream when trailers exist; ensure phase 2 runs.
  if (!request_body_processed_) {
    transaction_->processRequestBody();
    logRequestBodyProcessorErrors();
    request_body_processed_ = true;
    if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kRequestBody); st != 0) {
      return sendBlockResponse(st);
    }
  }

  size_t body_size = 0;
  bool chunked = false;
  auto headers_buf = getResponseHeaderPairs();
  int status_code = 200;
  if (headers_buf) {
    for (auto& p : headers_buf->pairs()) {
      const std::string name = std::string(p.first);
      const std::string value = std::string(p.second);
      transaction_->addResponseHeader(name, value);
      if (name == ":status") {
        char* end = nullptr;
        long v = std::strtol(value.c_str(), &end, 10);
        if (end != value.c_str()) {
          status_code = static_cast<int>(v);
        }
      }
      if (headerNameEquals(name, "content-length")) {
        body_size = parseContentLength(value);
      }
      if (headerNameEquals(name, "transfer-encoding") && isChunkedTransferEncoding(value)) {
        chunked = true;
      }
    }
  }

  transaction_->processResponseHeaders(status_code, modsecHttpProtocol(http_version_token_));

  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kResponseHeaders); st != 0) {
    return sendBlockResponse(st);
  }

  const bool has_known_body = body_size > 0 || chunked;
  const bool may_receive_body = statusMayHaveBody(status_code) && !end_of_stream;
  const bool needs_body_buffer = has_known_body || may_receive_body;
  if (!needs_body_buffer) {
    static const unsigned char empty_body[1] = {0};
    transaction_->appendResponseBody(empty_body, 1);
    if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kResponseBody); st != 0) {
      return sendBlockResponse(st);
    }
    finalizeResponseBodyPhase();
    if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kResponseBody); st != 0) {
      return sendBlockResponse(st);
    }
  }

  return FilterHeadersStatus::Continue;
}

FilterTrailersStatus ModSecContext::onResponseTrailers(uint32_t) {
  if (!transaction_ || response_body_processed_) {
    return FilterTrailersStatus::Continue;
  }
  activateContext();

  size_t buffer_size = 0;
  if (response_body_interrupted_) {
    uint32_t flags = 0;
    if (getBufferStatus(WasmBufferType::HttpResponseBody, &buffer_size, &flags) == WasmResult::Ok) {
      sanitizeInterruptedResponseBody(buffer_size);
    }
    return FilterTrailersStatus::Continue;
  }

  appendBufferedResponseBody(buffer_size);
  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kResponseBody); st != 0) {
    response_body_processed_ = true;
    sanitizeInterruptedResponseBody(buffer_size);
    return FilterTrailersStatus::Continue;
  }

  finalizeResponseBodyPhase();
  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kResponseBody); st != 0) {
    sanitizeInterruptedResponseBody(buffer_size);
  }
  return FilterTrailersStatus::Continue;
}

FilterDataStatus ModSecContext::onResponseBody(size_t body_buffer_length, bool end_of_stream) {
  if (!transaction_) {
    return FilterDataStatus::Continue;
  }
  activateContext();

  if (response_body_interrupted_) {
    return sanitizeInterruptedResponseBody(body_buffer_length);
  }

  if (response_body_processed_) {
    return FilterDataStatus::Continue;
  }

  if (body_buffer_length > response_body_received_) {
    const size_t chunk_size = body_buffer_length - response_body_received_;
    auto body = getBufferBytes(WasmBufferType::HttpResponseBody, response_body_received_, chunk_size);
    if (body && body->size() > 0) {
      transaction_->appendResponseBody(reinterpret_cast<const unsigned char*>(body->data()), body->size());
      response_body_received_ += body->size();
      if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kResponseBody); st != 0) {
        response_body_processed_ = true;
        return sanitizeInterruptedResponseBody(body_buffer_length);
      }
    } else {
      response_body_received_ = body_buffer_length;
    }
  }

  if (!end_of_stream) {
    return FilterDataStatus::StopIterationAndBuffer;
  }

  finalizeResponseBodyPhase();
  if (int st = processIntervention(modsecurity_proxy_wasm_metric_phase::kResponseBody); st != 0) {
    return sanitizeInterruptedResponseBody(body_buffer_length);
  }
  return FilterDataStatus::Continue;
}

void ModSecContext::onDelete() {
  if (transaction_ != nullptr && !interrupted_) {
    rootContext()->metrics_.countTxAllowed();
  }
  if (g_active_modsec_context == this) {
    g_active_modsec_context = nullptr;
  }
  delete transaction_;
  transaction_ = nullptr;
}
