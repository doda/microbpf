# microBPF Makefile

# Configuration
CC = gcc
AR = ar
CFLAGS = -Wall -Wextra -g -O2 -fPIC
LDFLAGS = -lm

# Directories
SRC_DIR = src
INC_DIR = include
TEST_DIR = tests
BUILD_DIR = build
MQUICKJS_DIR = deps/mquickjs

# MQuickJS integration
MQUICKJS_CFLAGS = -I$(MQUICKJS_DIR)
MQUICKJS_OBJS = $(BUILD_DIR)/mquickjs.o $(BUILD_DIR)/cutils.o \
                $(BUILD_DIR)/dtoa.o $(BUILD_DIR)/libm.o

# Source files
MBPF_SRCS = $(SRC_DIR)/mbpf_runtime.c $(SRC_DIR)/mbpf_package.c $(SRC_DIR)/mbpf_stdlib.c $(SRC_DIR)/ed25519.c
MBPF_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(MBPF_SRCS))

# Include paths
CFLAGS += -I$(INC_DIR) -I$(SRC_DIR) $(MQUICKJS_CFLAGS)

# Tool sources
TOOLS_DIR = tools

# Targets
LIB = $(BUILD_DIR)/libmbpf.a
TEST_BIN = $(BUILD_DIR)/test_basic
TEST_PKG_HEADER = $(BUILD_DIR)/test_package_header
TEST_PARSE_FILE = $(BUILD_DIR)/test_parse_file
TEST_SECTION_TABLE = $(BUILD_DIR)/test_section_table
TEST_MANIFEST = $(BUILD_DIR)/test_manifest
TEST_BYTECODE = $(BUILD_DIR)/test_bytecode
TEST_CRC = $(BUILD_DIR)/test_crc
TEST_SIGNING = $(BUILD_DIR)/test_signing
TEST_RUNTIME = $(BUILD_DIR)/test_runtime
TEST_PROGRAM_LOAD = $(BUILD_DIR)/test_program_load
TEST_PROGRAM_LOAD_VALIDATION = $(BUILD_DIR)/test_program_load_validation
TEST_PROGRAM_UNLOAD = $(BUILD_DIR)/test_program_unload
TEST_ATTACH_DETACH = $(BUILD_DIR)/test_attach_detach
TEST_ATTACH_VALIDATION = $(BUILD_DIR)/test_attach_validation
TEST_INSTANCE = $(BUILD_DIR)/test_instance
TEST_RUN_BASIC = $(BUILD_DIR)/test_run_basic
TEST_CONTEXT_OBJECT = $(BUILD_DIR)/test_context_object
TEST_CONTEXT_READ_METHODS = $(BUILD_DIR)/test_context_read_methods
TEST_CONTEXT_NET_RX_V1 = $(BUILD_DIR)/test_context_net_rx_v1
TEST_HOOK_TRACEPOINT = $(BUILD_DIR)/test_hook_tracepoint
TEST_HOOK_TIMER = $(BUILD_DIR)/test_hook_timer
TEST_HOOK_NET_RX = $(BUILD_DIR)/test_hook_net_rx
TEST_HOOK_NET_TX = $(BUILD_DIR)/test_hook_net_tx
TEST_HOOK_SECURITY = $(BUILD_DIR)/test_hook_security
TEST_HOOK_CUSTOM = $(BUILD_DIR)/test_hook_custom
TEST_ENTRY_POINT = $(BUILD_DIR)/test_entry_point
TEST_MBPF_INIT = $(BUILD_DIR)/test_mbpf_init
TEST_MBPF_FINI = $(BUILD_DIR)/test_mbpf_fini
TEST_RETURN_VALUE = $(BUILD_DIR)/test_return_value
TEST_EXCEPTION_HANDLING = $(BUILD_DIR)/test_exception_handling
TEST_ARRAY_MAP = $(BUILD_DIR)/test_array_map
TEST_HASH_MAP = $(BUILD_DIR)/test_hash_map
CREATE_MBPF = $(BUILD_DIR)/create_mbpf
MQJS = $(MQUICKJS_DIR)/mqjs

# Sanitizer flags for memory leak testing
SANITIZE_FLAGS = -fsanitize=address,leak -fno-omit-frame-pointer

.PHONY: all clean test mquickjs tools

all: $(LIB) $(TEST_BIN) $(TEST_PKG_HEADER) $(TEST_PARSE_FILE) $(TEST_SECTION_TABLE) $(TEST_MANIFEST) $(TEST_BYTECODE) $(TEST_CRC) $(TEST_SIGNING) $(TEST_RUNTIME) $(TEST_PROGRAM_LOAD) $(TEST_PROGRAM_LOAD_VALIDATION) $(TEST_PROGRAM_UNLOAD) $(TEST_ATTACH_DETACH) $(TEST_ATTACH_VALIDATION) $(TEST_INSTANCE) $(TEST_RUN_BASIC) $(TEST_CONTEXT_OBJECT) $(TEST_CONTEXT_READ_METHODS) $(TEST_CONTEXT_NET_RX_V1) $(TEST_HOOK_TRACEPOINT) $(TEST_HOOK_TIMER) $(TEST_HOOK_NET_RX) $(TEST_HOOK_NET_TX) $(TEST_HOOK_SECURITY) $(TEST_HOOK_CUSTOM) $(TEST_ENTRY_POINT) $(TEST_MBPF_INIT) $(TEST_MBPF_FINI) $(TEST_RETURN_VALUE) $(TEST_EXCEPTION_HANDLING) $(TEST_ARRAY_MAP) $(TEST_HASH_MAP) $(CREATE_MBPF) $(MQJS)

tools: $(CREATE_MBPF)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build MQuickJS first
mquickjs: $(MQJS)

$(MQJS):
	$(MAKE) -C $(MQUICKJS_DIR)

# MQuickJS object files
$(BUILD_DIR)/mquickjs.o: $(MQUICKJS_DIR)/mquickjs.c | $(BUILD_DIR) $(MQJS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/cutils.o: $(MQUICKJS_DIR)/cutils.c | $(BUILD_DIR) $(MQJS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/dtoa.o: $(MQUICKJS_DIR)/dtoa.c | $(BUILD_DIR) $(MQJS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/libm.o: $(MQUICKJS_DIR)/libm.c | $(BUILD_DIR) $(MQJS)
	$(CC) $(CFLAGS) -c -o $@ $<

# microBPF object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Static library (includes MQuickJS)
$(LIB): $(MBPF_OBJS) $(MQUICKJS_OBJS) | $(BUILD_DIR)
	$(AR) rcs $@ $^

# Test binaries
$(BUILD_DIR)/test_basic: $(TEST_DIR)/test_basic.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_package_header: $(TEST_DIR)/test_package_header.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_parse_file: $(TEST_DIR)/test_parse_file.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_section_table: $(TEST_DIR)/test_section_table.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_manifest: $(TEST_DIR)/test_manifest.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_bytecode: $(TEST_DIR)/test_bytecode.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_crc: $(TEST_DIR)/test_crc.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_signing: $(TEST_DIR)/test_signing.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_runtime: $(TEST_DIR)/test_runtime.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_program_load: $(TEST_DIR)/test_program_load.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_program_load_validation: $(TEST_DIR)/test_program_load_validation.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_program_unload: $(TEST_DIR)/test_program_unload.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_attach_detach: $(TEST_DIR)/test_attach_detach.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_attach_validation: $(TEST_DIR)/test_attach_validation.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_instance: $(TEST_DIR)/test_instance.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_run_basic: $(TEST_DIR)/test_run_basic.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_context_object: $(TEST_DIR)/test_context_object.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_context_read_methods: $(TEST_DIR)/test_context_read_methods.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_context_net_rx_v1: $(TEST_DIR)/test_context_net_rx_v1.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_hook_tracepoint: $(TEST_DIR)/test_hook_tracepoint.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_hook_timer: $(TEST_DIR)/test_hook_timer.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_hook_net_rx: $(TEST_DIR)/test_hook_net_rx.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_hook_net_tx: $(TEST_DIR)/test_hook_net_tx.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_hook_security: $(TEST_DIR)/test_hook_security.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_hook_custom: $(TEST_DIR)/test_hook_custom.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_entry_point: $(TEST_DIR)/test_entry_point.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_mbpf_init: $(TEST_DIR)/test_mbpf_init.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_mbpf_fini: $(TEST_DIR)/test_mbpf_fini.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_return_value: $(TEST_DIR)/test_return_value.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_exception_handling: $(TEST_DIR)/test_exception_handling.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_array_map: $(TEST_DIR)/test_array_map.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_hash_map: $(TEST_DIR)/test_hash_map.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

# Tool binaries
$(BUILD_DIR)/create_mbpf: $(TOOLS_DIR)/create_mbpf.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Run tests
test: $(MQJS) $(TEST_BIN) $(TEST_PKG_HEADER) $(TEST_SECTION_TABLE) $(TEST_MANIFEST) $(TEST_BYTECODE) $(TEST_CRC) $(TEST_SIGNING) $(TEST_RUNTIME) $(TEST_PROGRAM_LOAD) $(TEST_PROGRAM_LOAD_VALIDATION) $(TEST_PROGRAM_UNLOAD) $(TEST_ATTACH_DETACH) $(TEST_ATTACH_VALIDATION) $(TEST_INSTANCE) $(TEST_RUN_BASIC) $(TEST_CONTEXT_OBJECT) $(TEST_CONTEXT_READ_METHODS) $(TEST_CONTEXT_NET_RX_V1) $(TEST_HOOK_TRACEPOINT) $(TEST_HOOK_TIMER) $(TEST_HOOK_NET_RX) $(TEST_HOOK_NET_TX) $(TEST_HOOK_SECURITY) $(TEST_HOOK_CUSTOM) $(TEST_ENTRY_POINT) $(TEST_MBPF_INIT) $(TEST_MBPF_FINI) $(TEST_RETURN_VALUE) $(TEST_EXCEPTION_HANDLING) $(TEST_ARRAY_MAP) $(TEST_HASH_MAP)
	./$(TEST_BIN)
	./$(TEST_PKG_HEADER)
	./$(TEST_SECTION_TABLE)
	./$(TEST_MANIFEST)
	./$(TEST_BYTECODE)
	./$(TEST_CRC)
	./$(TEST_SIGNING)
	./$(TEST_RUNTIME)
	./$(TEST_PROGRAM_LOAD)
	./$(TEST_PROGRAM_LOAD_VALIDATION)
	./$(TEST_PROGRAM_UNLOAD)
	./$(TEST_ATTACH_DETACH)
	./$(TEST_ATTACH_VALIDATION)
	./$(TEST_INSTANCE)
	./$(TEST_RUN_BASIC)
	./$(TEST_CONTEXT_OBJECT)
	./$(TEST_CONTEXT_READ_METHODS)
	./$(TEST_CONTEXT_NET_RX_V1)
	./$(TEST_HOOK_TRACEPOINT)
	./$(TEST_HOOK_TIMER)
	./$(TEST_HOOK_NET_RX)
	./$(TEST_HOOK_NET_TX)
	./$(TEST_HOOK_SECURITY)
	./$(TEST_HOOK_CUSTOM)
	./$(TEST_ENTRY_POINT)
	./$(TEST_MBPF_INIT)
	./$(TEST_MBPF_FINI)
	./$(TEST_RETURN_VALUE)
	./$(TEST_EXCEPTION_HANDLING)
	./$(TEST_ARRAY_MAP)
	./$(TEST_HASH_MAP)

# Build and run with sanitizers (for memory leak detection)
.PHONY: test-sanitize
test-sanitize: clean
	$(MAKE) CFLAGS="$(CFLAGS) $(SANITIZE_FLAGS)" LDFLAGS="$(LDFLAGS) $(SANITIZE_FLAGS)" $(TEST_RUNTIME)
	./$(TEST_RUNTIME)

# Verify MQuickJS compiler works
test-mqjs: $(MQJS)
	@echo "Testing MQuickJS bytecode compilation..."
	$(MQJS) --no-column -o $(BUILD_DIR)/test.qjbc examples/net_rx_filter.js
	@echo "Bytecode generated: $(BUILD_DIR)/test.qjbc"
	@ls -la $(BUILD_DIR)/test.qjbc

# Clean
clean:
	rm -rf $(BUILD_DIR)

# Deep clean (including MQuickJS)
distclean: clean
	$(MAKE) -C $(MQUICKJS_DIR) clean 2>/dev/null || true

# Show configuration
info:
	@echo "microBPF Build Configuration"
	@echo "============================"
	@echo "CC: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "Sources: $(MBPF_SRCS)"
	@echo "Library: $(LIB)"
	@echo "MQuickJS: $(MQUICKJS_DIR)"
