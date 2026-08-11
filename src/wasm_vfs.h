#ifndef MODSECURITY_PROXY_WASM_VFS_H_
#define MODSECURITY_PROXY_WASM_VFS_H_

#include <cstddef>
#include <string>
#include <unordered_map>

// Verify embedded CRS .data phrase lists are present in the rules catalog.
// Actual file bytes are served to ModSecurity via
// modsecurity_proxy_wasm_resolve_data_file (no host filesystem).
bool modsecurity_proxy_wasm_mount_crs_data_files();

// Map a virtual catalog label to the filesystem-style path passed as the
// ModSecurity rule reference (directory used by find_resource for relatives).
const char* modsecurity_proxy_wasm_rule_ref_path(const char* label);

// C ABI used by the patched ModSecurity PmFromFile and IpMatchFromFile operators.
// Returns a pointer into the configure-scoped runtime map (if set) or the
// embedded catalog (full builds). Returned pointers outlive operator init
// (copy into string/stringstream); do not free.
// name may be a basename ("scanners-user-agents.data") or a longer path.
extern "C" const char* modsecurity_proxy_wasm_resolve_data_file(const char* name,
                                                                std::size_t* out_size);

// Install (replace) the configure-scoped runtime data_files map for the current
// root-context load. Bodies are copied. Call before RulesSet::load so
// PmFromFile::init resolves custom lists. Sequential onConfigure only
// (single-threaded wasm VM assumption).
void modsecurity_proxy_wasm_set_runtime_data_files(
    const std::unordered_map<std::string, std::string>& files);

// Clear the runtime map (optional after load; safe to leave for root lifetime).
void modsecurity_proxy_wasm_clear_runtime_data_files();

#endif
