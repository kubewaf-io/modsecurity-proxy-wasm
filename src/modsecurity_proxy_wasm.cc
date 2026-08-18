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
#include <unordered_map>
#include <utility>
#include <vector>

#include "proxy_wasm_intrinsics.h"
#include "metrics.h"
#include "version.h"
#include "waf_config.h"
#include "wasm_vfs.h"

#include <emscripten/heap.h>

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

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Map Unicode fullwidth ASCII (U+FF01..U+FF5E) to ASCII 0x21..0x7E.
// Needed so CRS XSS rules see "<script" after clients send fullwidth tags
// (CRS 941110-7/8). libModSecurity's utf8toUnicode+urlDecodeUni path is
// order-sensitive and can miss values that arrive already URL-decoded.
// Fast path: pure ASCII without '%' cannot contain fullwidth or %EF%BC sequences.
static bool mayContainFullwidth(const std::string& s) {
  for (unsigned char c : s) {
    if (c >= 0x80 || c == static_cast<unsigned char>('%')) {
      return true;
    }
  }
  return false;
}

static void normalizeFullwidthAsciiInPlace(std::string& s) {
  if (s.size() < 3 || !mayContainFullwidth(s)) {
    return;
  }
  std::string out;
  out.reserve(s.size());
  bool changed = false;
  for (size_t i = 0; i < s.size();) {
    const auto b0 = static_cast<unsigned char>(s[i]);
    // UTF-8 fullwidth: EF BC 81..BF → U+FF01..FF3F; EF BD 80..9E → U+FF40..FF5E
    if (b0 == 0xEF && i + 2 < s.size()) {
      const auto b1 = static_cast<unsigned char>(s[i + 1]);
      const auto b2 = static_cast<unsigned char>(s[i + 2]);
      int cp = -1;
      if (b1 == 0xBC && b2 >= 0x81 && b2 <= 0xBF) {
        cp = 0xFF00 + (b2 - 0x80);  // FF01..FF3F
      } else if (b1 == 0xBD && b2 >= 0x80 && b2 <= 0x9E) {
        cp = 0xFF40 + (b2 - 0x80);  // FF40..FF5E
      }
      if (cp >= 0xFF01 && cp <= 0xFF5E) {
        out.push_back(static_cast<char>(cp - 0xFEE0));
        i += 3;
        changed = true;
        continue;
      }
    }
    // Percent-encoded fullwidth UTF-8: %EF%BC%9C → '<' (case-insensitive).
    if (b0 == '%' && i + 8 < s.size() && s[i + 3] == '%' && s[i + 6] == '%') {
      const int h0 = hexNibble(s[i + 1]);
      const int h1 = hexNibble(s[i + 2]);
      const int h2 = hexNibble(s[i + 4]);
      const int h3 = hexNibble(s[i + 5]);
      const int h4 = hexNibble(s[i + 7]);
      const int h5 = hexNibble(s[i + 8]);
      if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0 && h4 >= 0 && h5 >= 0) {
        const unsigned bA = static_cast<unsigned>((h0 << 4) | h1);
        const unsigned bB = static_cast<unsigned>((h2 << 4) | h3);
        const unsigned bC = static_cast<unsigned>((h4 << 4) | h5);
        int cp = -1;
        if (bA == 0xEF && bB == 0xBC && bC >= 0x81 && bC <= 0xBF) {
          cp = 0xFF00 + static_cast<int>(bC - 0x80);
        } else if (bA == 0xEF && bB == 0xBD && bC >= 0x80 && bC <= 0x9E) {
          cp = 0xFF40 + static_cast<int>(bC - 0x80);
        }
        if (cp >= 0xFF01 && cp <= 0xFF5E) {
          out.push_back(static_cast<char>(cp - 0xFEE0));
          i += 9;
          changed = true;
          continue;
        }
      }
    }
    out.push_back(s[i]);
    ++i;
  }
  if (changed) {
    s.swap(out);
  }
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
  void onLog() override;
  void onDelete() override;

  Transaction* transaction_{nullptr};

private:
  size_t request_body_received_{0};
  bool request_body_processed_{false};
  size_t response_body_received_{0};
  bool response_body_processed_{false};
  bool response_body_interrupted_{false};
  bool logging_phase_done_{false};
  bool interrupted_{false};
  int64_t last_disruptive_rule_id_{0};
  // How many Transaction::m_rulesMessages entries we have already metric/log-flushed.
  std::size_t rules_messages_seen_{0};
  std::string request_id_;
  std::string method_;
  std::string path_;
  std::string client_ip_;
  // Bare version token for ModSecurity (e.g. "1.1", "2.0"); derived from Envoy request.protocol.
  std::string http_version_token_{"1.1"};
  std::string action_{"pass"};
  std::string last_phase_;
  bool export_annotated_{false};
  struct ExportMatch {
    std::string event;
    int64_t rule_id{0};
    std::string phase;
    int severity{-1};
    bool disruptive{false};
    std::string msg;
    std::string data;
  };
  std::vector<ExportMatch> export_matches_;
  ModSecRootContext* rootContext() { return static_cast<ModSecRootContext*>(root()); }

  void activateContext();
  // ModSecurity only calls serverLog for *non-disruptive* matches. Deny/block
  // rules land in m_rulesMessages without the log CB — drain those for metrics.
  void flushNewRuleMessages();
  int processIntervention(const char* phase);
  void finalizeResponseBodyPhase();
  void runLoggingPhaseIfNeeded();
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
  void stashExportMatch(const char* event, int64_t rule_id, const char* phase, int severity,
                        bool disruptive, const std::string& msg, const std::string& data);
  void maybeAnnotateExport();
  static bool sampleAt(double rate, const std::string& seed);
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

static const char* catalogPhaseName(int rule_phase) {
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

// Configure-phase heap ladder (WS0). Envoy log grep: "event":"heap_sample".
// Used to tune INITIAL_MEMORY — peak during msc_rules_add drives the floor.
static uint64_t wasmHeapBytes() {
  return static_cast<uint64_t>(emscripten_get_heap_size());
}

static void logHeapSample(const char* stage, const char* label = nullptr, std::size_t bytes = 0) {
  std::ostringstream fields;
  fields << "\"stage\":\"" << stage << "\""
         << ",\"wasm_heap_bytes\":" << static_cast<unsigned long long>(wasmHeapBytes());
  if (label != nullptr && label[0] != '\0') {
    fields << ",\"label\":\"" << jsonEscape(label) << "\"";
  }
  if (bytes > 0) {
    fields << ",\"bytes\":" << bytes;
  }
  logJson(false, "heap_sample", fields.str());
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
  // Path B CRS is many small "inline-directives" chunks. Logging every one floods
  // envoy.log and makes go-ftw marker scans O(log size)×tests (multi-minute suites).
  // Keep progress logs for catalog Includes; silent success for inline batches.
  const bool log_progress = std::strcmp(lab, "inline-directives") != 0;
  if (log_progress) {
    std::ostringstream fields;
    fields << "\"label\":\"" << jsonEscape(lab) << "\",\"bytes\":" << size
           << ",\"wasm_heap_bytes\":" << static_cast<unsigned long long>(wasmHeapBytes());
    logJson(false, "rules_loading", fields.str());
    logHeapSample("rules_loading", lab, size);
  }
  // Short preview only for small non-inline chunks (debug custom Includes).
  if (log_progress && size > 0 && size < 512) {
    std::string preview(data, size);
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
  // Peak during configure ≈ catalog rodata + this chunk + RulesSet graph. Drop the
  // temporary as soon as load() returns so sequential Path B chunks do not stack copies.
  std::string chunk;
  chunk.reserve(size + 1);
  chunk.assign(data, size);
  int ret = rules->load(chunk.c_str(), ref);
  chunk.clear();
  chunk.shrink_to_fit();
  if (ret < 0) {
    err = rules->m_parserError.str();
    if (err.empty()) {
      err = std::string("RulesSet::load failed for ") + lab;
    }
    std::ostringstream fields;
    fields << "\"label\":\"" << jsonEscape(lab) << "\",\"error\":\"" << jsonEscape(err)
           << "\",\"wasm_heap_bytes\":" << static_cast<unsigned long long>(wasmHeapBytes());
    logJson(true, "rules_load_failed", fields.str());
    return false;
  }
  if (log_progress) {
    std::ostringstream fields;
    fields << "\"label\":\"" << jsonEscape(lab) << "\""
           << ",\"wasm_heap_bytes\":" << static_cast<unsigned long long>(wasmHeapBytes());
    logJson(false, "rules_loaded", fields.str());
    logHeapSample("rules_loaded", lab, size);
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
    fields << "\"size\":" << configuration_size
           << ",\"wasm_heap_bytes\":" << static_cast<unsigned long long>(wasmHeapBytes());
    logJson(false, "configure_start", fields.str());
  }
  logHeapSample("configure_start");

  std::string config;
  if (!readPluginConfig(configuration_size, config)) {
    logJson(true, "configure_failed", "\"error\":\"Failed to read plugin configuration\"");
    return false;
  }
  logHeapSample("config_read", nullptr, config.size());

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
  logHeapSample("modsec_init");

  // Phrase lists: install runtime data_files (path-b primary path). Optional
  // @crs-data catalog still consulted by resolve_data_file on full builds.
  // Envoy V8 has no writable MEMFS for fopen.
  {
    std::unordered_map<std::string, std::string> runtime_files;
    std::string df_err;
    if (!parseDataFiles(config, runtime_files, df_err)) {
      std::ostringstream fields;
      fields << "\"error\":\"" << jsonEscape(df_err) << "\"";
      logJson(true, "configure_failed", fields.str());
      return false;
    }
    modsecurity_proxy_wasm_set_runtime_data_files(runtime_files);
    if (!runtime_files.empty()) {
      std::ostringstream fields;
      fields << "\"runtime_data_files\":" << runtime_files.size()
             << ",\"wasm_heap_bytes\":" << static_cast<unsigned long long>(wasmHeapBytes());
      logJson(false, "runtime_data_files_ready", fields.str());
    }
  }
  // No longer fail-closed when the build omits @crs-data (path-b default).
  (void)modsecurity_proxy_wasm_mount_crs_data_files();
  {
    std::ostringstream fields;
    fields << "\"source\":\"runtime_or_catalog\""
           << ",\"wasm_heap_bytes\":" << static_cast<unsigned long long>(wasmHeapBytes());
    logJson(false, "crs_data_ready", fields.str());
  }
  logHeapSample("after_crs_data");

  std::string err;
  if (!applyWafConfiguration(config, loadRuleChunk, rules_, err)) {
    if (!plugin_options_.allow_fallback || !wafConfigAllowsFallback(config)) {
      std::ostringstream fields;
      fields << "\"error\":\"" << jsonEscape(err) << "\",\"fail_closed\":true"
             << ",\"wasm_heap_bytes\":" << static_cast<unsigned long long>(wasmHeapBytes());
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
    logHeapSample("fallback_rules_loaded");
    metrics_.recordWasmMemory();
    return true;
  }

  logHeapSample("rules_applied");
  // Drop the raw plugin config string now that rules are loaded (can be multi-MB gzip JSON).
  config.clear();
  config.shrink_to_fit();
  logHeapSample("config_freed");

  metrics_.recordWasmMemory();
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
           << ",\"dual_prefix\":" << (plugin_options_.metrics.dual_prefix ? "true" : "false")
           << ",\"fullwidth_normalize\":"
           << (plugin_options_.fullwidth_normalize ? "true" : "false")
           << ",\"stats\":" << (plugin_options_.metrics.enabled ? "true" : "false")
           << ",\"wasm_heap_bytes\":" << static_cast<unsigned long long>(wasmHeapBytes());
    logJson(false, "config_applied", fields.str());
  }
  logHeapSample("config_applied");
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
  rules_messages_seen_ = 0;
  request_id_.clear();
  method_.clear();
  path_.clear();
  client_ip_.clear();
  http_version_token_ = "1.1";
  action_ = "pass";
  last_phase_.clear();
  export_annotated_ = false;
  export_matches_.clear();
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

void ModSecContext::stashExportMatch(const char* event, int64_t rule_id, const char* phase,
                                     int severity, bool disruptive, const std::string& msg,
                                     const std::string& data) {
  ExportMatch m;
  m.event = event ? event : "";
  m.rule_id = rule_id;
  if (phase != nullptr) {
    m.phase = phase;
    last_phase_ = phase;
  }
  m.severity = severity;
  m.disruptive = disruptive;
  m.msg = msg.substr(0, 256);
  m.data = data.substr(0, 180);
  constexpr size_t kCap = 16;
  if (export_matches_.size() < kCap) {
    export_matches_.push_back(std::move(m));
    return;
  }
  // Keep first 16; always retain the interrupting rule.
  if (disruptive && last_disruptive_rule_id_ == rule_id) {
    export_matches_.back() = std::move(m);
  }
}

bool ModSecContext::sampleAt(double rate, const std::string& seed) {
  return wafTelemetrySampleAt(rate, seed);
}

void ModSecContext::maybeAnnotateExport() {
  auto* root = rootContext();
  const auto& tel = root->plugin_options_.telemetry;
  if (tel.mode != "Managed" || !tel.traces_enabled) {
    return;
  }
  const bool has_match = !export_matches_.empty() || interrupted_;
  if (!has_match) {
    return;
  }
  // Hash the stream id, not a client-controlled request header.
  const std::string seed = std::to_string(id());
  if (interrupted_) {
    if (!sampleAt(tel.sample_disruptive, seed)) {
      return;
    }
  } else if (!sampleAt(tel.sample_rate, seed)) {
    return;
  }

  std::ostringstream js;
  js << "{\"interrupted\":" << (interrupted_ ? "true" : "false")
     << ",\"action\":\"" << jsonEscape(action_) << "\"";
  if (!last_phase_.empty()) {
    js << ",\"phase\":\"" << jsonEscape(last_phase_) << "\"";
  }
  if (!root->plugin_options_.config_id.empty()) {
    js << ",\"config_id\":\"" << jsonEscape(root->plugin_options_.config_id) << "\"";
  }
  for (const auto& kv : root->plugin_options_.metrics.labels) {
    if (kv.first == "waf_namespace" || kv.first == "waf_name" || kv.first == "engine") {
      js << ",\"" << jsonEscape(kv.first) << "\":\"" << jsonEscape(kv.second) << "\"";
    }
  }
  if (!tel.redact && !client_ip_.empty()) {
    js << ",\"client.address\":\"" << jsonEscape(client_ip_) << "\"";
  }
  js << ",\"matches\":[";
  bool first = true;
  for (const auto& m : export_matches_) {
    if (!first) {
      js << ",";
    }
    first = false;
    const char* ev = m.event == "tx_interrupt" ? "waf.tx_interrupt" : "waf.rule_match";
    js << "{\"event\":\"" << ev << "\"";
    if (m.rule_id > 0) {
      js << ",\"rule_id\":" << m.rule_id;
    }
    if (!m.phase.empty()) {
      js << ",\"phase\":\"" << jsonEscape(m.phase) << "\"";
    }
    if (m.severity >= 0) {
      js << ",\"severity\":" << m.severity;
    }
    js << ",\"disruptive\":" << (m.disruptive ? "true" : "false");
    if (!m.msg.empty()) {
      js << ",\"msg\":\"" << jsonEscape(m.msg) << "\"";
    }
    if (tel.include_match_data && !m.data.empty() && !wafTelemetryLooksSecret(m.data)) {
      js << ",\"data\":\"" << jsonEscape(m.data) << "\"";
    }
    js << "}";
  }
  js << "]}";

  const std::string rollup = js.str();
  // Envoy Context::setProperty stores CelState under "wasm." + path.
  // Access-log %FILTER_STATE(wasm.kubewaf.event:PLAIN)% and the CEL
  // filter on filter_state['wasm.kubewaf.export'] need these keys.
  // (Envoy 1.38 does not map proxy_set_property onto dynamic metadata.)
  const WasmResult st = setFilterState("kubewaf.event", rollup);
  const WasmResult md_st = setFilterState("kubewaf.export", "1");
  if (st == WasmResult::Ok || md_st == WasmResult::Ok) {
    export_annotated_ = true;
  }
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
  stashExportMatch("rule_match", rule_message.m_rule.m_ruleId,
                   catalogPhaseName(rule_message.getPhase()), rule_message.m_severity,
                   rule_message.m_isDisruptive, rule_message.m_message, rule_message.m_data);
}

void ModSecContext::flushNewRuleMessages() {
  if (!transaction_) {
    return;
  }
  // libModSecurity performLogging():
  //   - non-disruptive + log  → serverLog (our log CB) AND m_rulesMessages
  //   - disruptive (deny/block) → m_rulesMessages only (no serverLog)
  // Drain new disruptive entries so rule_match metrics and last_disruptive_rule_id_
  // work for the smoke rules that use deny/block.
  //
  // DetectionOnly (FTW): block/deny actions are not executed, so m_isDisruptive
  // often stays false and serverLog already logged them. Still drain any true
  // disruptive leftovers. Phase-5 processLogging() may also append messages after
  // response body — always drain those (seen_ cursor avoids double metrics).
  const auto& msgs = transaction_->m_rulesMessages;
  std::size_t idx = 0;
  for (const auto& rm : msgs) {
    if (idx++ < rules_messages_seen_) {
      continue;
    }
    if (rm.m_isDisruptive) {
      recordRuleMatch(rm);
    }
  }
  rules_messages_seen_ = msgs.size();
}

int ModSecContext::processIntervention(const char* phase) {
  // Capture disruptive rule matches before reading intervention status.
  flushNewRuleMessages();

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
  std::string redirect_url;
  if (intervention.log != nullptr) {
    intervention_msg = intervention.log;
    free(intervention.log);
  }
  if (intervention.url != nullptr) {
    redirect_url = intervention.url;
    free(intervention.url);
  }
  action_ = wafTelemetryAction(true, !redirect_url.empty(), status, intervention_msg);
  last_phase_ = phase ? phase : last_phase_;
  stashExportMatch("tx_interrupt", last_disruptive_rule_id_, phase, -1, true, intervention_msg, "");
  // Annotate as soon as the interrupt is decided so the access-log metadata
  // filter can see kubewaf.export even if onLog is delayed.
  maybeAnnotateExport();

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
  // Client-visible details stay product-neutral (no vendor/product names).
  std::string details = block.message.empty() ? "Forbidden" : block.message;
  std::vector<std::pair<std::string, std::string>> extra_headers;
  // Generic marker only; empty blocked_header omits it entirely.
  if (!block.blocked_header.empty()) {
    extra_headers.emplace_back(block.blocked_header, "1");
  }
  if (block.add_rule_id_header && last_disruptive_rule_id_ > 0 && !block.rule_id_header.empty()) {
    extra_headers.emplace_back(block.rule_id_header, std::to_string(last_disruptive_rule_id_));
  }
  if (block.add_request_id_header && !request_id_.empty() && !block.request_id_header.empty()) {
    extra_headers.emplace_back(block.request_id_header, request_id_);
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
    std::string chunk(body->data(), body->size());
    // Fold fullwidth UTF-8 / %EF%BC%xx in bodies (form + JSON) for CRS XSS (941110-7).
    if (rootContext()->plugin_options_.fullwidth_normalize) {
      normalizeFullwidthAsciiInPlace(chunk);
    }
    transaction_->appendRequestBody(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
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

// CRS RESPONSE-980 phase 5 (e.g. 980170). Run as soon as the response is complete
// so go-ftw sees the id before the end-marker request, not only on stream destroy.
void ModSecContext::runLoggingPhaseIfNeeded() {
  if (!transaction_ || logging_phase_done_) {
    return;
  }
  activateContext();  // so serverLog → recordRuleMatch uses this stream context
  const std::size_t before = rules_messages_seen_;
  transaction_->processLogging();
  // CRS 980170 is a SecAction with pass+msg; inject "log" in Path B generator.
  // Drain every NEW m_rulesMessages entry (list — no random access). Non-disruptive
  // matches may also hit serverLog during processLogging (possible double log line;
  // go-ftw only needs the id present).
  const auto& msgs = transaction_->m_rulesMessages;
  std::size_t idx = 0;
  for (const auto& rm : msgs) {
    if (idx++ < before) {
      continue;
    }
    recordRuleMatch(rm);
  }
  rules_messages_seen_ = msgs.size();
  logging_phase_done_ = true;
}

FilterDataStatus ModSecContext::sanitizeInterruptedResponseBody(size_t body_buffer_length) {
  // Product-neutral body replacement when a response-phase interrupt is sanitized.
  static const char kBlocked[] = "Forbidden\n";
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
  // Prefer :path as seen by Envoy. With normalize_path=false (FTW envoy YAML),
  // percent-encoding is preserved so REQUEST_URI_RAW / double-encoding rules
  // (920230, 920271–273) and path XSS (941101) see client bytes.
  // Fall back to request.path / request.url_path when :path is absent.
  if (auto h = getRequestHeader(":path")) {
    path = h->toString();
  } else if (!getValue({"request", "headers", ":path"}, &path) || path.empty()) {
    if (!getValue({"request", "path"}, &path) || path.empty()) {
      getValue({"request", "url_path"}, &path);
    }
  }
  if (path.empty()) {
    path = "/";
  }
  if (auto h = getRequestHeader(":method")) {
    method = h->toString();
  } else {
    getValue({"request", "headers", ":method"}, &method);
  }
  // Fold fullwidth Unicode in path/query so ARGS from URI match CRS XSS regexes.
  // Does not percent-decode — keeps %xx sequences for protocol-enforcement rules.
  if (root->plugin_options_.fullwidth_normalize) {
    normalizeFullwidthAsciiInPlace(path);
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
      std::string value = std::string(p.second);
      // Cookie names/values and other headers may carry fullwidth XSS (CRS 941110-8).
      if (root->plugin_options_.fullwidth_normalize) {
        normalizeFullwidthAsciiInPlace(value);
      }
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
    // Inbound anomaly scores are final after phase 2. Run phase 5 early so CRS
    // 980170 appears in logs before go-ftw's end marker (response body may lag).
    runLoggingPhaseIfNeeded();
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
  runLoggingPhaseIfNeeded();
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
      std::string chunk(body->data(), body->size());
      if (rootContext()->plugin_options_.fullwidth_normalize) {
        normalizeFullwidthAsciiInPlace(chunk);
      }
      transaction_->appendRequestBody(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
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
  runLoggingPhaseIfNeeded();
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
    runLoggingPhaseIfNeeded();
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
  runLoggingPhaseIfNeeded();
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
  runLoggingPhaseIfNeeded();
  return FilterDataStatus::Continue;
}

void ModSecContext::onLog() {
  // Access logger runs after the stream finishes; commit export metadata here.
  if (transaction_ != nullptr) {
    activateContext();
    runLoggingPhaseIfNeeded();
  }
  maybeAnnotateExport();
}

void ModSecContext::onDelete() {
  // Fallback: if response path skipped finalize (client cancel, etc.), still run phase 5.
  if (transaction_ != nullptr) {
    activateContext();
    if (!request_body_processed_) {
      transaction_->processRequestBody();
      logRequestBodyProcessorErrors();
      request_body_processed_ = true;
      processIntervention(modsecurity_proxy_wasm_metric_phase::kRequestBody);
    }
    if (!response_body_processed_) {
      finalizeResponseBodyPhase();
      processIntervention(modsecurity_proxy_wasm_metric_phase::kResponseBody);
    }
    runLoggingPhaseIfNeeded();
    maybeAnnotateExport();
  }
  if (transaction_ != nullptr && !interrupted_) {
    rootContext()->metrics_.countTxAllowed();
  }
  if (g_active_modsec_context == this) {
    g_active_modsec_context = nullptr;
  }
  delete transaction_;
  transaction_ = nullptr;
}
