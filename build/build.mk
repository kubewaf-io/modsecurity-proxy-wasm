# Build logic for modsecurity-proxy-wasm (used locally and inside the Docker builder).
# Dependency pins: Makefile (Renovate-managed *_VERSION / *_SHA variables).

SHELL := /bin/bash

BUILD_DIR       ?= $(abspath .)
PREFIX          ?= $(BUILD_DIR)/.cache/deps
JOBS            ?= $(shell nproc 2>/dev/null || echo 4)

EMSDK           ?= $(PREFIX)/emsdk

PROXY_WASM_CPP_SDK ?= $(PREFIX)/proxy-wasm-cpp-sdk
PCRE2_SRC       ?= $(PREFIX)/pcre2-wasm
PCRE2_EM        ?= $(PREFIX)/pcre2-em
YAJL_SRC        ?= $(PREFIX)/yajl
YAJL_EM         ?= $(PREFIX)/yajl-em
LIBXML2_SRC     ?= $(PREFIX)/libxml2
LIBXML2_EM      ?= $(PREFIX)/libxml2-em
MODSEC_SRC      ?= $(PREFIX)/modsec
MODSECURITY_LIB ?= $(PREFIX)/modsecurity-lib
CRS_DIR         ?= $(PREFIX)/crs

MODSECURITY_PROXY_WASM_OUT ?= $(BUILD_DIR)/dist/modsecurity-proxy-wasm.wasm
MODSECURITY_PROXY_WAT_OUT  ?= $(BUILD_DIR)/dist/modsecurity-proxy-wasm.wat

STAMPS_DIR      := $(BUILD_DIR)/.cache/stamps
OBJ_DIR         := $(BUILD_DIR)/.cache/obj
WASM_GETENTROPY_OBJ := $(OBJ_DIR)/wasm_getentropy.o
WASM_STUBS_OBJ      := $(OBJ_DIR)/wasm_stubs.o

BUILD_RULES_DIR    := $(BUILD_DIR)/build/rules
BUILD_SCRIPTS_DIR  := $(BUILD_DIR)/build/scripts

GENERATED_CC    := $(BUILD_DIR)/src/generated/rules_catalog.cc
GENERATED_H     := $(BUILD_DIR)/src/generated/rules_catalog.h

PCRE2_PKG_VERSION := $(patsubst pcre2-%,%,$(PCRE2_VERSION))

EMS_ENV         := EMSDK=$(EMSDK) . $(EMSDK)/emsdk_env.sh &&

MODSEC_CONFIGURE_FLAGS := \
	--with-pcre2=$(PCRE2_EM) \
	--with-yajl=$(YAJL_EM) \
	--with-libxml=$(LIBXML2_EM) \
	--without-geoip --without-curl \
	--without-lua --disable-shared --disable-examples --disable-libtool-lock \
	--disable-debug-logs --disable-mutex-on-pm --without-lmdb --without-maxmind \
	--without-ssdeep

# Memory (Envoy V8 reserves Wasm linear memory *per worker VM*).
# Defaults depend on CATALOG_MODE (set below). ALLOW_MEMORY_GROWTH is on.
# Override: INITIAL_MEMORY=32MB make modsecurity-proxy-wasm.wasm
# Do not put # comments inside the continued EMSCRIPTEN_LINK_OPTS assignment.
MAXIMUM_MEMORY ?= 512MB
STACK_SIZE     ?= 4MB

PLUGIN_SRCS := \
	$(BUILD_DIR)/src/modsecurity_proxy_wasm.cc \
	$(BUILD_DIR)/src/metrics.cc \
	$(BUILD_DIR)/src/waf_config.cc \
	$(BUILD_DIR)/src/wasm_vfs.cc \
	$(BUILD_DIR)/src/version.cc \
	$(GENERATED_CC)

# Identity baked into the wasm (logged first on onStart/onConfigure + inspect-wasm).
# Override VERSION= from CI/release; git fields are best-effort when .git exists.
VERSION                 ?= 0.1.0-alpha8
GIT_COMMIT              ?= $(shell git -C $(BUILD_DIR) rev-parse --short HEAD 2>/dev/null || echo unknown)
GIT_DESCRIBE            ?= $(shell git -C $(BUILD_DIR) describe --tags --always --dirty 2>/dev/null || echo unknown)
BUILD_DATE              ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
BUILD_HOST              ?= $(shell hostname 2>/dev/null || echo unknown)
SOURCE_REPO             ?= github.com/kubewaf-io/kubewaf/modsecurity-proxy-wasm
WASM_VERSION_CPPFLAGS   := \
	-DMODSECURITY_PROXY_WASM_VERSION=\"$(VERSION)\" \
	-DMODSECURITY_PROXY_WASM_GIT_COMMIT=\"$(GIT_COMMIT)\" \
	-DMODSECURITY_PROXY_WASM_GIT_DESCRIBE=\"$(GIT_DESCRIBE)\" \
	-DMODSECURITY_PROXY_WASM_CRS_VERSION=\"$(CRS_VERSION)\" \
	-DMODSECURITY_PROXY_WASM_MODSECURITY_VERSION=\"$(MODSECURITY_VERSION)\" \
	-DMODSECURITY_PROXY_WASM_SOURCE=\"$(SOURCE_REPO)\" \
	-DMODSECURITY_PROXY_WASM_BUILD_DATE=\"$(BUILD_DATE)\" \
	-DMODSECURITY_PROXY_WASM_BUILD_HOST=\"$(BUILD_HOST)\"

.PHONY: all build deps clean-build modsecurity-proxy-wasm.wasm modsecurity-proxy-wasm.wat

all: modsecurity-proxy-wasm.wasm modsecurity-proxy-wasm.wat
build: all

modsecurity-proxy-wasm.wasm: $(MODSECURITY_PROXY_WASM_OUT)
modsecurity-proxy-wasm.wat: $(MODSECURITY_PROXY_WAT_OUT)

deps: $(STAMPS_DIR)/emsdk \
	$(STAMPS_DIR)/proxy-wasm-cpp-sdk \
	$(STAMPS_DIR)/pcre2 \
	$(STAMPS_DIR)/yajl \
	$(STAMPS_DIR)/libxml2 \
	$(STAMPS_DIR)/modsecurity \
	$(STAMPS_DIR)/crs

$(STAMPS_DIR)/emsdk:
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(EMSDK)
	git clone --depth 1 https://github.com/emscripten-core/emsdk.git $(EMSDK)
	cd $(EMSDK) && ./emsdk install $(EMSDK_VERSION) --shallow && ./emsdk activate $(EMSDK_VERSION)
	touch $@

$(STAMPS_DIR)/proxy-wasm-cpp-sdk: | $(STAMPS_DIR)/emsdk
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(PROXY_WASM_CPP_SDK)
	git clone https://github.com/proxy-wasm/proxy-wasm-cpp-sdk.git $(PROXY_WASM_CPP_SDK)
	cd $(PROXY_WASM_CPP_SDK) && git checkout $(PROXY_WASM_CPP_SDK_VERSION)
	test "$$(git -C $(PROXY_WASM_CPP_SDK) rev-parse HEAD)" = "$(PROXY_WASM_CPP_SDK_VERSION)"
	python3 $(BUILD_SCRIPTS_DIR)/patch-sdk-getentropy.py $(PROXY_WASM_CPP_SDK)/proxy_wasm_intrinsics.cc
	touch $@

$(STAMPS_DIR)/pcre2: | $(STAMPS_DIR)/emsdk
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(PCRE2_SRC)
	git clone --branch "$(PCRE2_VERSION)" https://github.com/PCRE2Project/pcre2.git $(PCRE2_SRC)
	test "$$(git -C $(PCRE2_SRC) rev-parse HEAD)" = "$(PCRE2_SHA)"
	cd $(PCRE2_SRC) && autoreconf -ivf
	cd $(PCRE2_SRC) && $(EMS_ENV) emconfigure ./configure --host wasm32 \
		--disable-dependency-tracking \
		--enable-utf8 \
		--enable-pcre2-8 \
		--enable-pcre2-16 \
		--enable-pcre2-32 \
		--enable-unicode-properties \
		--disable-shared \
		--disable-cpp
	cd $(PCRE2_SRC) && $(EMS_ENV) emmake make
	mkdir -p $(PCRE2_SRC)/targets/wasm32-emscripten
	cp $(PCRE2_SRC)/.libs/*.a $(PCRE2_SRC)/targets/wasm32-emscripten/
	mkdir -p $(PCRE2_EM)/include $(PCRE2_EM)/lib/pkgconfig
	cp $(PCRE2_SRC)/src/pcre2.h $(PCRE2_EM)/include/
	cp $(PCRE2_SRC)/targets/wasm32-emscripten/libpcre2-8.a $(PCRE2_EM)/lib/
	printf '%s\n' \
		'prefix=$(PCRE2_EM)' \
		'exec_prefix=$${prefix}' \
		'libdir=$${exec_prefix}/lib' \
		'includedir=$${prefix}/include' \
		'Name: libpcre2-8' \
		'Description: Perl Compatible Regular Expressions (2)' \
		'Version: $(PCRE2_PKG_VERSION)' \
		'Libs: -L$${libdir} -lpcre2-8' \
		'Cflags: -I$${includedir}' \
		> $(PCRE2_EM)/lib/pkgconfig/libpcre2-8.pc
	touch $@

$(STAMPS_DIR)/yajl: | $(STAMPS_DIR)/emsdk
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(YAJL_SRC) $(YAJL_EM)
	git clone https://github.com/lloyd/yajl.git $(YAJL_SRC)
	cd $(YAJL_SRC) && git checkout $(YAJL_SHA)
	test "$$(git -C $(YAJL_SRC) rev-parse HEAD)" = "$(YAJL_SHA)"
	# Static lib only; install headers + libyajl_s.a under YAJL_EM for ModSecurity --with-yajl.
	@mkdir -p $(YAJL_SRC)/build $(YAJL_EM)
	cd $(YAJL_SRC)/build && $(EMS_ENV) emcmake cmake .. \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_INSTALL_PREFIX=$(YAJL_EM) \
		-DBUILD_SHARED_LIBS=OFF
	cd $(YAJL_SRC)/build && $(EMS_ENV) emmake make -j$(JOBS)
	cd $(YAJL_SRC)/build && $(EMS_ENV) emmake make install
	# ModSecurity looks for libyajl / libyajl2; provide a plain libyajl.a alias.
	@if [ -f "$(YAJL_EM)/lib/libyajl_s.a" ] && [ ! -f "$(YAJL_EM)/lib/libyajl.a" ]; then \
		cp "$(YAJL_EM)/lib/libyajl_s.a" "$(YAJL_EM)/lib/libyajl.a"; \
	fi
	@if [ -f "$(YAJL_EM)/lib/libyajl_s.a" ] && [ ! -f "$(YAJL_EM)/lib/libyajl2.a" ]; then \
		cp "$(YAJL_EM)/lib/libyajl_s.a" "$(YAJL_EM)/lib/libyajl2.a"; \
	fi
	touch $@

# libxml2 for CRS XML://@* body inspection (requestBodyProcessor=XML).
# Static-only wasm build: no python/iconv/zlib/http/threads; headers under
# include/libxml2/libxml (standard pkg-config layout for --with-libxml).
$(STAMPS_DIR)/libxml2: | $(STAMPS_DIR)/emsdk
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(LIBXML2_SRC) $(LIBXML2_EM)
	git clone --branch "$(LIBXML2_VERSION)" https://github.com/GNOME/libxml2.git $(LIBXML2_SRC)
	test "$$(git -C $(LIBXML2_SRC) rev-parse HEAD)" = "$(LIBXML2_SHA)"
	# Skip autogen's native configure: on Debian Trixie it probes python-3.13
	# pkg-config (needs python3-dev) even though we pass --without-python below.
	cd $(LIBXML2_SRC) && NOCONFIGURE=1 ./autogen.sh
	cd $(LIBXML2_SRC) && $(EMS_ENV) emconfigure ./configure \
		--host=wasm32-unknown-emscripten \
		--prefix=$(LIBXML2_EM) \
		--disable-shared \
		--enable-static \
		--disable-dependency-tracking \
		--without-python \
		--without-lzma \
		--without-iconv \
		--without-icu \
		--without-zlib \
		--without-http \
		--without-ftp \
		--without-legacy \
		--without-modules \
		--without-debug \
		--without-threads \
		--without-readline \
		--without-history \
		--without-catalog
	# Build only the library — skip xmllint/xmlcatalog (need full emscripten link).
	cd $(LIBXML2_SRC) && $(EMS_ENV) emmake make -j$(JOBS) libxml2.la
	cd $(LIBXML2_SRC) && $(EMS_ENV) emmake make install-libLTLIBRARIES install-pkgconfigDATA
	cd $(LIBXML2_SRC)/include && $(EMS_ENV) emmake make install
	test -f "$(LIBXML2_EM)/lib/libxml2.a"
	test -f "$(LIBXML2_EM)/include/libxml2/libxml/parser.h"
	test -f "$(LIBXML2_EM)/lib/pkgconfig/libxml-2.0.pc"
	touch $@

$(STAMPS_DIR)/modsecurity: $(STAMPS_DIR)/pcre2 $(STAMPS_DIR)/yajl $(STAMPS_DIR)/libxml2 \
		$(BUILD_DIR)/build/patches/modsecurity-pm-from-file-catalog.patch \
		$(BUILD_DIR)/build/patches/modsecurity-ip-match-from-file-catalog.patch
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(MODSEC_SRC)
	git clone https://github.com/owasp-modsecurity/ModSecurity.git $(MODSEC_SRC)
	cd $(MODSEC_SRC) && git checkout $(MODSECURITY_SHA)
	test "$$(git -C $(MODSEC_SRC) rev-parse HEAD)" = "$(MODSECURITY_SHA)"
	cd $(MODSEC_SRC) && git submodule update --init --recursive
	# Serve @pmFromFile / @ipMatchFromFile bodies via proxy-wasm resolve_data_file
	# (Envoy V8 has no host FS for phrase/IP list files).
	cd $(MODSEC_SRC) && patch -p1 < $(BUILD_DIR)/build/patches/modsecurity-pm-from-file-catalog.patch
	cd $(MODSEC_SRC) && patch -p1 < $(BUILD_DIR)/build/patches/modsecurity-ip-match-from-file-catalog.patch
	cd $(MODSEC_SRC) && ./build.sh
	cd $(MODSEC_SRC) && $(EMS_ENV) \
		PKG_CONFIG_PATH=$(PCRE2_EM)/lib/pkgconfig:$(YAJL_EM)/lib/pkgconfig:$(LIBXML2_EM)/lib/pkgconfig \
		CPPFLAGS="-I$(YAJL_EM)/include -I$(LIBXML2_EM)/include/libxml2" \
		LDFLAGS="-L$(YAJL_EM)/lib -L$(LIBXML2_EM)/lib" \
		emconfigure ./configure $(MODSEC_CONFIGURE_FLAGS)
	# Fail fast if libxml2 was not detected (XML://@* would be a no-op).
	# ModSecurity enables XML via CFLAGS -DWITH_LIBXML2 (LIBXML2_CFLAGS), not config.h.
	@grep -E '^LIBXML2_FOUND = 1$$' $(MODSEC_SRC)/Makefile \
		|| (echo "ERROR: ModSecurity configured without LibXML2 (LIBXML2_FOUND != 1)" >&2; \
		    grep -E 'LIBXML2_|LibXML2|libxml' $(MODSEC_SRC)/Makefile $(MODSEC_SRC)/config.log 2>/dev/null | tail -40 >&2; \
		    exit 1)
	@grep -qE 'WITH_LIBXML2' $(MODSEC_SRC)/Makefile \
		|| (echo "ERROR: WITH_LIBXML2 missing from ModSecurity Makefile CFLAGS" >&2; exit 1)
	cd $(MODSEC_SRC) && $(EMS_ENV) emmake make -j$(JOBS) -C others
	cd $(MODSEC_SRC) && $(EMS_ENV) emmake make -j$(JOBS) -C src libmodsecurity.la
	mkdir -p $(MODSECURITY_LIB)/lib $(MODSECURITY_LIB)/include
	cp $(MODSEC_SRC)/src/.libs/libmodsecurity.a $(MODSECURITY_LIB)/lib/
	cp -r $(MODSEC_SRC)/headers/* $(MODSECURITY_LIB)/include/
	touch $@

$(STAMPS_DIR)/crs:
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(CRS_DIR)
	git clone --depth 1 --branch "$(CRS_VERSION)" https://github.com/coreruleset/coreruleset.git $(CRS_DIR)
	touch $@

# Catalog modes (build-time embed into the .wasm):
#   path-b (default, first-class) — helpers only (@kubewaf-defaults / @demo / @ftw).
#     CRS *rules* come from structured SecRule CRs (kubeWAF Path B).
#     @pmFromFile bodies arrive via plugin JSON data_files (operator inject),
#     not as prebuilt @crs-data/*.data in the wasm binary.
#   full (second-class) — also embed @crs-setup-conf + @owasp_crs/*.conf +
#     @crs-data/*.data for Path A ``crsEnable: true``. Publish as *-full tags.
# Switching modes regenerates the catalog (stamp includes the mode name).
CATALOG_MODE ?= path-b
CATALOG_MODE_STAMP := $(BUILD_DIR)/src/generated/.catalog_mode_$(CATALOG_MODE)

# INITIAL_MEMORY defaults (Envoy V8 per-worker reservation):
# - path-b: 16MB (no embedded @crs-data; growth allowed for large data_files / CRS soak)
# - full:   32MB (embedded CRS confs + .data; prior Path A floor)
# History: alpha9 16→64, alpha11 64→128, then 32 validated with embedded data (2026-07-28).
ifeq ($(origin INITIAL_MEMORY),undefined)
  ifeq ($(CATALOG_MODE),full)
    INITIAL_MEMORY := 32MB
  else
    INITIAL_MEMORY := 16MB
  endif
endif

EMSCRIPTEN_LINK_OPTS := --no-entry \
	-sSTANDALONE_WASM -sEXPORTED_FUNCTIONS=_malloc -sFILESYSTEM=1 \
	-sALLOW_MEMORY_GROWTH=1 \
	-sINITIAL_MEMORY=$(INITIAL_MEMORY) \
	-sMAXIMUM_MEMORY=$(MAXIMUM_MEMORY) \
	-sSTACK_SIZE=$(STACK_SIZE) \
	-sDISABLE_EXCEPTION_CATCHING=1 \
	-sUSE_ZLIB=1

# path-b does not need a CRS tree. full still does (rules + .data).
ifeq ($(CATALOG_MODE),full)
CATALOG_CRS_DEP := $(STAMPS_DIR)/crs
CATALOG_CRS_ARG := --crs $(CRS_DIR)
else
CATALOG_CRS_DEP :=
CATALOG_CRS_ARG :=
endif

$(GENERATED_CC) $(GENERATED_H) $(CATALOG_MODE_STAMP): $(CATALOG_CRS_DEP) \
		$(BUILD_RULES_DIR)/demo-conf.conf \
		$(BUILD_RULES_DIR)/ftw-config.conf \
		$(BUILD_RULES_DIR)/kubewaf-defaults.conf \
		$(BUILD_SCRIPTS_DIR)/generate_rules_catalog.py
	@mkdir -p $(BUILD_DIR)/src/generated
	@rm -f $(BUILD_DIR)/src/generated/.catalog_mode_*
	python3 $(BUILD_SCRIPTS_DIR)/generate_rules_catalog.py \
		--mode $(CATALOG_MODE) \
		$(CATALOG_CRS_ARG) \
		--demo $(BUILD_RULES_DIR)/demo-conf.conf \
		--ftw $(BUILD_RULES_DIR)/ftw-config.conf \
		--kubewaf-defaults $(BUILD_RULES_DIR)/kubewaf-defaults.conf \
		--out-cc $(GENERATED_CC) \
		--out-h $(GENERATED_H)
	@touch $(CATALOG_MODE_STAMP)

$(WASM_GETENTROPY_OBJ): $(BUILD_DIR)/src/wasm_getentropy.c | $(STAMPS_DIR)/emsdk
	@mkdir -p $(OBJ_DIR)
	$(EMS_ENV) emcc -c $(BUILD_DIR)/src/wasm_getentropy.c -o $(WASM_GETENTROPY_OBJ)

$(WASM_STUBS_OBJ): $(BUILD_DIR)/src/wasm_stubs.c | $(STAMPS_DIR)/emsdk
	@mkdir -p $(OBJ_DIR)
	$(EMS_ENV) emcc -c $(BUILD_DIR)/src/wasm_stubs.c -o $(WASM_STUBS_OBJ)

$(MODSECURITY_PROXY_WASM_OUT): deps $(GENERATED_CC) $(WASM_GETENTROPY_OBJ) $(WASM_STUBS_OBJ) $(PLUGIN_SRCS) \
		$(BUILD_DIR)/src/waf_config.h $(BUILD_DIR)/src/version.h $(BUILD_DIR)/src/version.cc \
		$(STAMPS_DIR)/proxy-wasm-cpp-sdk
	@mkdir -p $(dir $(MODSECURITY_PROXY_WASM_OUT))
	@echo "Linking modsecurity-proxy-wasm VERSION=$(VERSION) git=$(GIT_COMMIT) crs=$(CRS_VERSION)"
	$(EMS_ENV) em++ --std=c++17 -O3 -flto \
		$(WASM_VERSION_CPPFLAGS) \
		$(EMSCRIPTEN_LINK_OPTS) \
		--js-library $(PROXY_WASM_CPP_SDK)/proxy_wasm_intrinsics.js \
		-I$(BUILD_DIR)/src \
		-I$(PROXY_WASM_CPP_SDK) \
		-I$(MODSECURITY_LIB)/include \
		-I$(PCRE2_EM)/include \
		$(PROXY_WASM_CPP_SDK)/proxy_wasm_intrinsics.cc \
		$(BUILD_DIR)/src/modsecurity_proxy_wasm.cc \
		$(BUILD_DIR)/src/metrics.cc \
		$(BUILD_DIR)/src/waf_config.cc \
		$(BUILD_DIR)/src/wasm_vfs.cc \
		$(BUILD_DIR)/src/version.cc \
		$(GENERATED_CC) \
		$(MODSECURITY_LIB)/lib/libmodsecurity.a \
		$(WASM_GETENTROPY_OBJ) \
		$(WASM_STUBS_OBJ) \
		$(PCRE2_EM)/lib/libpcre2-8.a \
		$(YAJL_EM)/lib/libyajl_s.a \
		$(LIBXML2_EM)/lib/libxml2.a \
		-o $(MODSECURITY_PROXY_WASM_OUT)

# Optional text form for debugging (requires wabt: apt install wabt / brew install wabt).
# Never fail the main build if wasm2wat is missing — leave a placeholder .wat.
$(MODSECURITY_PROXY_WAT_OUT): $(MODSECURITY_PROXY_WASM_OUT)
	@mkdir -p $(dir $(MODSECURITY_PROXY_WAT_OUT))
	@WASM2WAT=$$(command -v wasm2wat 2>/dev/null || true); \
	if [ -z "$$WASM2WAT" ] && [ -n "$$(command -v emsdk 2>/dev/null || true)" ]; then \
	  :; \
	fi; \
	if [ -z "$$WASM2WAT" ]; then \
	  EMS_BIN="$(EMSDK)/upstream/bin/wasm2wat"; \
	  if [ -x "$$EMS_BIN" ]; then WASM2WAT="$$EMS_BIN"; fi; \
	fi; \
	if [ -n "$$WASM2WAT" ]; then \
	  echo "Generating $(MODSECURITY_PROXY_WAT_OUT) with $$WASM2WAT"; \
	  "$$WASM2WAT" $(MODSECURITY_PROXY_WASM_OUT) -o $(MODSECURITY_PROXY_WAT_OUT); \
	else \
	  echo "WARN: wasm2wat not found (install package 'wabt' for .wat output); writing empty placeholder"; \
	  : > $(MODSECURITY_PROXY_WAT_OUT); \
	fi

clean-build:
	rm -rf $(STAMPS_DIR) $(OBJ_DIR) $(BUILD_DIR)/src/generated $(BUILD_DIR)/dist $(BUILD_DIR)/.cache