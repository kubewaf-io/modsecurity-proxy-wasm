#ifndef MODSEC_WASM_VFS_H_
#define MODSEC_WASM_VFS_H_

// Mount embedded CRS .data files into the in-memory filesystem so ModSecurity
// @pmFromFile can resolve them at rule-load time (no build-time inlining).
bool modsec_wasm_mount_crs_data_files();

// Map a virtual catalog label to the filesystem path passed as the ModSecurity
// rule reference (used by find_resource for @pmFromFile resolution).
const char* modsec_wasm_rule_ref_path(const char* label);

#endif