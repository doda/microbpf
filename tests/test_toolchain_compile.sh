#!/bin/bash
# Test script for toolchain-js-compile task
# Verifies JavaScript to bytecode compilation using mqjs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MQJS="$PROJECT_ROOT/deps/mquickjs/mqjs"
MBPF_COMPILE="$PROJECT_ROOT/tools/mbpf-compile"
EXAMPLES_DIR="$PROJECT_ROOT/examples"
BUILD_DIR="$PROJECT_ROOT/build"

PASSED=0
FAILED=0

pass() {
    echo "  ✓ $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo "  ✗ $1"
    FAILED=$((FAILED + 1))
}

echo "================================================"
echo "Toolchain JS Compile Test Suite"
echo "================================================"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Cleanup previous test artifacts
rm -f "$BUILD_DIR"/test_*.qjbc

# Test 1: Verify mqjs compiler exists
echo ""
echo "Test 1: mqjs compiler exists"
if [ -x "$MQJS" ]; then
    pass "mqjs compiler found and executable"
else
    fail "mqjs compiler not found at $MQJS"
fi

# Test 1b: Verify mbpf-compile tool exists
echo ""
echo "Test 1b: mbpf-compile tool exists"
if [ -x "$MBPF_COMPILE" ]; then
    pass "mbpf-compile tool found and executable"
else
    fail "mbpf-compile tool not found at $MBPF_COMPILE"
fi

# Test 2: Compile simple mbpf_prog using mbpf-compile tool
echo ""
echo "Test 2: Compile simple mbpf_prog JS file using mbpf-compile"
cat > "$BUILD_DIR/test_simple.js" << 'EOF'
function mbpf_prog(ctx) {
    return 0;
}
EOF

if "$MBPF_COMPILE" "$BUILD_DIR/test_simple.js" -o "$BUILD_DIR/test_simple.qjbc" 2>/dev/null; then
    pass "Compilation with mbpf-compile succeeded"
else
    fail "Compilation with mbpf-compile failed"
fi

# Test 3: Verify bytecode file is generated
echo ""
echo "Test 3: Verify bytecode file is generated"
if [ -f "$BUILD_DIR/test_simple.qjbc" ]; then
    pass "Bytecode file exists"
    SIZE=$(stat -c%s "$BUILD_DIR/test_simple.qjbc" 2>/dev/null || stat -f%z "$BUILD_DIR/test_simple.qjbc")
    if [ "$SIZE" -gt 0 ]; then
        pass "Bytecode file has content ($SIZE bytes)"
    else
        fail "Bytecode file is empty"
    fi
else
    fail "Bytecode file not created"
fi

# Test 4: Verify bytecode has valid magic header
echo ""
echo "Test 4: Verify bytecode magic header"
if [ -f "$BUILD_DIR/test_simple.qjbc" ]; then
    # Read first 3 bytes as hex
    MAGIC=$(od -A n -t x1 -N 3 "$BUILD_DIR/test_simple.qjbc" | tr -d ' ')
    if [ "$MAGIC" = "fbac01" ]; then
        pass "Bytecode has valid MQuickJS magic (0xfbac01)"
    else
        fail "Bytecode has invalid magic: $MAGIC (expected fbac01)"
    fi
fi

# Test 5: Compile with -m32 flag for 32-bit targets using mbpf-compile
echo ""
echo "Test 5: Compile with -m32 flag for 32-bit targets"
if "$MBPF_COMPILE" -m32 "$BUILD_DIR/test_simple.js" -o "$BUILD_DIR/test_simple_32.qjbc" 2>/dev/null; then
    pass "32-bit compilation with mbpf-compile succeeded"
else
    fail "32-bit compilation with mbpf-compile failed"
fi

# Test 6: Verify 32-bit bytecode is generated and valid
echo ""
echo "Test 6: Verify 32-bit bytecode file"
if [ -f "$BUILD_DIR/test_simple_32.qjbc" ]; then
    pass "32-bit bytecode file exists"
    SIZE_32=$(stat -c%s "$BUILD_DIR/test_simple_32.qjbc" 2>/dev/null || stat -f%z "$BUILD_DIR/test_simple_32.qjbc")
    SIZE_64=$(stat -c%s "$BUILD_DIR/test_simple.qjbc" 2>/dev/null || stat -f%z "$BUILD_DIR/test_simple.qjbc")
    if [ "$SIZE_32" -gt 0 ]; then
        pass "32-bit bytecode has content ($SIZE_32 bytes, 64-bit is $SIZE_64 bytes)"
    else
        fail "32-bit bytecode file is empty"
    fi

    # Verify 32-bit bytecode differs from 64-bit (they use different pointer sizes)
    if ! cmp -s "$BUILD_DIR/test_simple_32.qjbc" "$BUILD_DIR/test_simple.qjbc"; then
        pass "32-bit bytecode differs from 64-bit bytecode"
    else
        fail "32-bit bytecode identical to 64-bit bytecode"
    fi

    # Verify magic header
    MAGIC_32=$(od -A n -t x1 -N 3 "$BUILD_DIR/test_simple_32.qjbc" | tr -d ' ')
    if [ "$MAGIC_32" = "fbac01" ]; then
        pass "32-bit bytecode has valid magic"
    else
        fail "32-bit bytecode has invalid magic: $MAGIC_32"
    fi
else
    fail "32-bit bytecode file not created"
fi

# Test 7: Compile more complex program (from examples) using mbpf-compile
echo ""
echo "Test 7: Compile example NET_RX filter program"
if [ -f "$EXAMPLES_DIR/net_rx_filter.js" ]; then
    if "$MBPF_COMPILE" "$EXAMPLES_DIR/net_rx_filter.js" -o "$BUILD_DIR/test_net_rx_filter.qjbc" 2>/dev/null; then
        pass "Example program compilation with mbpf-compile succeeded"
        SIZE=$(stat -c%s "$BUILD_DIR/test_net_rx_filter.qjbc" 2>/dev/null || stat -f%z "$BUILD_DIR/test_net_rx_filter.qjbc")
        pass "Example bytecode size: $SIZE bytes"
    else
        fail "Example program compilation failed"
    fi
else
    fail "Example file not found: $EXAMPLES_DIR/net_rx_filter.js"
fi

# Test 8: Compile program with mbpf_init and mbpf_fini
echo ""
echo "Test 8: Compile program with init/fini entry points"
cat > "$BUILD_DIR/test_full.js" << 'EOF'
var counter = 0;

function mbpf_init() {
    counter = 1;
}

function mbpf_prog(ctx) {
    counter++;
    return counter;
}

function mbpf_fini() {
    counter = 0;
}
EOF

if "$MBPF_COMPILE" "$BUILD_DIR/test_full.js" -o "$BUILD_DIR/test_full.qjbc" 2>/dev/null; then
    pass "Full program (init/prog/fini) compilation with mbpf-compile succeeded"
else
    fail "Full program compilation failed"
fi

# Test 9: Verify 32-bit compilation of complex program using mbpf-compile
echo ""
echo "Test 9: 32-bit compilation of complex program"
if "$MBPF_COMPILE" -m32 "$BUILD_DIR/test_full.js" -o "$BUILD_DIR/test_full_32.qjbc" 2>/dev/null; then
    pass "32-bit complex program compilation with mbpf-compile succeeded"
else
    fail "32-bit complex program compilation failed"
fi

# Summary
echo ""
echo "================================================"
echo "Test Summary: $PASSED passed, $FAILED failed"
echo "================================================"

# Cleanup
rm -f "$BUILD_DIR"/test_*.js
rm -f "$BUILD_DIR"/test_*.qjbc

if [ $FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi
