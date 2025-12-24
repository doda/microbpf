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
MBPF_SRCS = $(SRC_DIR)/mbpf_runtime.c $(SRC_DIR)/mbpf_package.c
MBPF_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(MBPF_SRCS))

# Include paths
CFLAGS += -I$(INC_DIR) $(MQUICKJS_CFLAGS)

# Targets
LIB = $(BUILD_DIR)/libmbpf.a
TEST_BIN = $(BUILD_DIR)/test_basic
MQJS = $(MQUICKJS_DIR)/mqjs

.PHONY: all clean test mquickjs

all: $(LIB) $(TEST_BIN) $(MQJS)

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

# Static library
$(LIB): $(MBPF_OBJS) | $(BUILD_DIR)
	$(AR) rcs $@ $^

# Test binary
$(BUILD_DIR)/test_basic: $(TEST_DIR)/test_basic.c $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< -L$(BUILD_DIR) -lmbpf $(LDFLAGS)

# Run tests
test: $(TEST_BIN)
	./$(TEST_BIN)

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
