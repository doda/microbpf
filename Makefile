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
MBPF_SRCS = $(SRC_DIR)/mbpf_runtime.c $(SRC_DIR)/mbpf_package.c $(SRC_DIR)/mbpf_stdlib.c $(SRC_DIR)/ed25519.c $(SRC_DIR)/mbpf_typed_array.c
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
TEST_MAP_MAX_ENTRIES = $(BUILD_DIR)/test_map_max_entries
TEST_MAP_TYPE_VALIDATION = $(BUILD_DIR)/test_map_type_validation
TEST_LRU_HASH_MAP = $(BUILD_DIR)/test_lru_hash_map
TEST_PERCPU_MAP = $(BUILD_DIR)/test_percpu_map
TEST_RING_BUFFER = $(BUILD_DIR)/test_ring_buffer
TEST_COUNTER_MAP = $(BUILD_DIR)/test_counter_map
TEST_MAP_ITERATION = $(BUILD_DIR)/test_map_iteration
TEST_MAP_PERSISTENCE = $(BUILD_DIR)/test_map_persistence
TEST_MAP_CONCURRENCY = $(BUILD_DIR)/test_map_concurrency
TEST_HELPER_API_VERSION = $(BUILD_DIR)/test_helper_api_version
TEST_HELPER_LOG = $(BUILD_DIR)/test_helper_log
TEST_HELPER_U64_LOAD_STORE = $(BUILD_DIR)/test_helper_u64_load_store
TEST_HELPER_NOW_NS = $(BUILD_DIR)/test_helper_now_ns
TEST_HELPER_EMIT = $(BUILD_DIR)/test_helper_emit
TEST_HELPER_STATS = $(BUILD_DIR)/test_helper_stats
TEST_MAP_LOWLEVEL = $(BUILD_DIR)/test_map_lowlevel
TEST_BUDGET_MAX_STEPS = $(BUILD_DIR)/test_budget_max_steps
TEST_BUDGET_MAX_HELPERS = $(BUILD_DIR)/test_budget_max_helpers
TEST_BUDGET_MAX_WALL_TIME = $(BUILD_DIR)/test_budget_max_wall_time
TEST_BUDGET_INTERRUPT_HANDLER = $(BUILD_DIR)/test_budget_interrupt_handler
TEST_HEAP_SIZE = $(BUILD_DIR)/test_heap_size
TEST_MEMORY_MINIMUM_HEAP = $(BUILD_DIR)/test_memory_minimum_heap
TEST_CAPABILITY_ENFORCEMENT = $(BUILD_DIR)/test_capability_enforcement
TEST_CAPABILITY_CATEGORIES = $(BUILD_DIR)/test_capability_categories
TEST_NESTED_EXECUTION = $(BUILD_DIR)/test_nested_execution
TEST_FAILURE_ISOLATION = $(BUILD_DIR)/test_failure_isolation
TEST_CIRCUIT_BREAKER = $(BUILD_DIR)/test_circuit_breaker
TEST_API_VERSION_ENFORCEMENT = $(BUILD_DIR)/test_api_version_enforcement
TEST_PER_HELPER_VERSIONING = $(BUILD_DIR)/test_per_helper_versioning
TEST_TYPED_ARRAY_SHIM = $(BUILD_DIR)/test_typed_array_shim
TEST_ALLOCATION_FREE_HELPERS = $(BUILD_DIR)/test_allocation_free_helpers
TEST_GC_REFERENCE = $(BUILD_DIR)/test_gc_reference
TEST_DEFERRED_QUEUE = $(BUILD_DIR)/test_deferred_queue
TEST_DEFERRED_BACKPRESSURE = $(BUILD_DIR)/test_deferred_backpressure
TEST_DEFERRED_CONTEXT_SNAPSHOT = $(BUILD_DIR)/test_deferred_context_snapshot
TEST_GLOBAL_MBPF_OBJECT = $(BUILD_DIR)/test_global_mbpf_object
TEST_GLOBAL_MAPS_OBJECT = $(BUILD_DIR)/test_global_maps_object
TEST_CONSOLE_DEBUG = $(BUILD_DIR)/test_console_debug
TEST_DISALLOWED_GLOBALS = $(BUILD_DIR)/test_disallowed_globals
CREATE_MBPF = $(BUILD_DIR)/create_mbpf
MQJS = $(MQUICKJS_DIR)/mqjs

# Sanitizer flags for memory leak testing
SANITIZE_FLAGS = -fsanitize=address,leak -fno-omit-frame-pointer

.PHONY: all clean test mquickjs tools

all: $(LIB) $(TEST_BIN) $(TEST_PKG_HEADER) $(TEST_PARSE_FILE) $(TEST_SECTION_TABLE) $(TEST_MANIFEST) $(TEST_BYTECODE) $(TEST_CRC) $(TEST_SIGNING) $(TEST_RUNTIME) $(TEST_PROGRAM_LOAD) $(TEST_PROGRAM_LOAD_VALIDATION) $(TEST_PROGRAM_UNLOAD) $(TEST_ATTACH_DETACH) $(TEST_ATTACH_VALIDATION) $(TEST_INSTANCE) $(TEST_RUN_BASIC) $(TEST_CONTEXT_OBJECT) $(TEST_CONTEXT_READ_METHODS) $(TEST_CONTEXT_NET_RX_V1) $(TEST_HOOK_TRACEPOINT) $(TEST_HOOK_TIMER) $(TEST_HOOK_NET_RX) $(TEST_HOOK_NET_TX) $(TEST_HOOK_SECURITY) $(TEST_HOOK_CUSTOM) $(TEST_ENTRY_POINT) $(TEST_MBPF_INIT) $(TEST_MBPF_FINI) $(TEST_RETURN_VALUE) $(TEST_EXCEPTION_HANDLING) $(TEST_ARRAY_MAP) $(TEST_HASH_MAP) $(TEST_MAP_MAX_ENTRIES) $(TEST_MAP_TYPE_VALIDATION) $(TEST_LRU_HASH_MAP) $(TEST_PERCPU_MAP) $(TEST_RING_BUFFER) $(TEST_COUNTER_MAP) $(TEST_MAP_ITERATION) $(TEST_MAP_PERSISTENCE) $(TEST_MAP_CONCURRENCY) $(TEST_HELPER_API_VERSION) $(TEST_HELPER_LOG) $(TEST_HELPER_U64_LOAD_STORE) $(TEST_HELPER_NOW_NS) $(TEST_HELPER_EMIT) $(TEST_HELPER_STATS) $(TEST_MAP_LOWLEVEL) $(TEST_BUDGET_MAX_STEPS) $(TEST_BUDGET_MAX_HELPERS) $(TEST_BUDGET_MAX_WALL_TIME) $(TEST_BUDGET_INTERRUPT_HANDLER) $(TEST_HEAP_SIZE) $(TEST_MEMORY_MINIMUM_HEAP) $(TEST_CAPABILITY_ENFORCEMENT) $(TEST_CAPABILITY_CATEGORIES) $(TEST_NESTED_EXECUTION) $(TEST_FAILURE_ISOLATION) $(TEST_CIRCUIT_BREAKER) $(TEST_API_VERSION_ENFORCEMENT) $(TEST_PER_HELPER_VERSIONING) $(TEST_TYPED_ARRAY_SHIM) $(TEST_ALLOCATION_FREE_HELPERS) $(TEST_GC_REFERENCE) $(TEST_DEFERRED_QUEUE) $(TEST_DEFERRED_BACKPRESSURE) $(TEST_DEFERRED_CONTEXT_SNAPSHOT) $(TEST_GLOBAL_MBPF_OBJECT) $(TEST_GLOBAL_MAPS_OBJECT) $(TEST_CONSOLE_DEBUG) $(TEST_DISALLOWED_GLOBALS) $(CREATE_MBPF) $(MQJS)

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

$(BUILD_DIR)/test_map_max_entries: $(TEST_DIR)/test_map_max_entries.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_map_type_validation: $(TEST_DIR)/test_map_type_validation.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_lru_hash_map: $(TEST_DIR)/test_lru_hash_map.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_percpu_map: $(TEST_DIR)/test_percpu_map.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_ring_buffer: $(TEST_DIR)/test_ring_buffer.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_counter_map: $(TEST_DIR)/test_counter_map.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_map_iteration: $(TEST_DIR)/test_map_iteration.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_map_persistence: $(TEST_DIR)/test_map_persistence.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_map_concurrency: $(TEST_DIR)/test_map_concurrency.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS) -lpthread

$(BUILD_DIR)/test_helper_api_version: $(TEST_DIR)/test_helper_api_version.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_helper_log: $(TEST_DIR)/test_helper_log.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_helper_u64_load_store: $(TEST_DIR)/test_helper_u64_load_store.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_helper_now_ns: $(TEST_DIR)/test_helper_now_ns.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_helper_emit: $(TEST_DIR)/test_helper_emit.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_helper_stats: $(TEST_DIR)/test_helper_stats.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_map_lowlevel: $(TEST_DIR)/test_map_lowlevel.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_budget_max_steps: $(TEST_DIR)/test_budget_max_steps.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_budget_max_helpers: $(TEST_DIR)/test_budget_max_helpers.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_budget_max_wall_time: $(TEST_DIR)/test_budget_max_wall_time.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_budget_interrupt_handler: $(TEST_DIR)/test_budget_interrupt_handler.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_heap_size: $(TEST_DIR)/test_heap_size.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_memory_minimum_heap: $(TEST_DIR)/test_memory_minimum_heap.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_capability_enforcement: $(TEST_DIR)/test_capability_enforcement.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_capability_categories: $(TEST_DIR)/test_capability_categories.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_nested_execution: $(TEST_DIR)/test_nested_execution.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS) -lpthread

$(BUILD_DIR)/test_failure_isolation: $(TEST_DIR)/test_failure_isolation.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_circuit_breaker: $(TEST_DIR)/test_circuit_breaker.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_api_version_enforcement: $(TEST_DIR)/test_api_version_enforcement.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_per_helper_versioning: $(TEST_DIR)/test_per_helper_versioning.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_typed_array_shim: $(TEST_DIR)/test_typed_array_shim.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_allocation_free_helpers: $(TEST_DIR)/test_allocation_free_helpers.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_gc_reference: $(TEST_DIR)/test_gc_reference.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_deferred_queue: $(TEST_DIR)/test_deferred_queue.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_deferred_backpressure: $(TEST_DIR)/test_deferred_backpressure.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_deferred_context_snapshot: $(TEST_DIR)/test_deferred_context_snapshot.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_global_mbpf_object: $(TEST_DIR)/test_global_mbpf_object.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_global_maps_object: $(TEST_DIR)/test_global_maps_object.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_console_debug: $(TEST_DIR)/test_console_debug.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

$(BUILD_DIR)/test_disallowed_globals: $(TEST_DIR)/test_disallowed_globals.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

# Tool binaries
$(BUILD_DIR)/create_mbpf: $(TOOLS_DIR)/create_mbpf.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Run tests
test: $(MQJS) $(TEST_BIN) $(TEST_PKG_HEADER) $(TEST_SECTION_TABLE) $(TEST_MANIFEST) $(TEST_BYTECODE) $(TEST_CRC) $(TEST_SIGNING) $(TEST_RUNTIME) $(TEST_PROGRAM_LOAD) $(TEST_PROGRAM_LOAD_VALIDATION) $(TEST_PROGRAM_UNLOAD) $(TEST_ATTACH_DETACH) $(TEST_ATTACH_VALIDATION) $(TEST_INSTANCE) $(TEST_RUN_BASIC) $(TEST_CONTEXT_OBJECT) $(TEST_CONTEXT_READ_METHODS) $(TEST_CONTEXT_NET_RX_V1) $(TEST_HOOK_TRACEPOINT) $(TEST_HOOK_TIMER) $(TEST_HOOK_NET_RX) $(TEST_HOOK_NET_TX) $(TEST_HOOK_SECURITY) $(TEST_HOOK_CUSTOM) $(TEST_ENTRY_POINT) $(TEST_MBPF_INIT) $(TEST_MBPF_FINI) $(TEST_RETURN_VALUE) $(TEST_EXCEPTION_HANDLING) $(TEST_ARRAY_MAP) $(TEST_HASH_MAP) $(TEST_MAP_MAX_ENTRIES) $(TEST_MAP_TYPE_VALIDATION) $(TEST_LRU_HASH_MAP) $(TEST_PERCPU_MAP) $(TEST_RING_BUFFER) $(TEST_COUNTER_MAP) $(TEST_MAP_ITERATION) $(TEST_MAP_PERSISTENCE) $(TEST_MAP_CONCURRENCY) $(TEST_HELPER_API_VERSION) $(TEST_HELPER_LOG) $(TEST_HELPER_U64_LOAD_STORE) $(TEST_HELPER_NOW_NS) $(TEST_HELPER_EMIT) $(TEST_MAP_LOWLEVEL) $(TEST_BUDGET_MAX_STEPS) $(TEST_HEAP_SIZE)
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
	./$(TEST_MAP_MAX_ENTRIES)
	./$(TEST_MAP_TYPE_VALIDATION)
	./$(TEST_LRU_HASH_MAP)
	./$(TEST_PERCPU_MAP)
	./$(TEST_RING_BUFFER)
	./$(TEST_COUNTER_MAP)
	./$(TEST_MAP_ITERATION)
	./$(TEST_MAP_PERSISTENCE)
	./$(TEST_MAP_CONCURRENCY)
	./$(TEST_HELPER_API_VERSION)
	./$(TEST_HELPER_LOG)
	./$(TEST_HELPER_U64_LOAD_STORE)
	./$(TEST_HELPER_NOW_NS)
	./$(TEST_HELPER_EMIT)
	./$(TEST_MAP_LOWLEVEL)
	./$(TEST_BUDGET_MAX_STEPS)
	./$(TEST_HEAP_SIZE)

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

# Run toolchain compile tests
test-toolchain-compile: $(MQJS)
	@echo "Running toolchain compile tests..."
	./tests/test_toolchain_compile.sh

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
