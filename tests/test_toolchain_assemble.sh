#!/bin/bash
# Test script for mbpf-assemble toolchain integration
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
TOOLS_DIR="$PROJECT_ROOT/tools"
TMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "=== mbpf-assemble Toolchain Test ==="
echo ""

# Check required tools exist
if [ ! -x "$BUILD_DIR/mbpf_assemble" ]; then
    echo "FAIL: mbpf_assemble not built"
    exit 1
fi

if [ ! -x "$TOOLS_DIR/mbpf-assemble" ]; then
    echo "FAIL: mbpf-assemble wrapper not found"
    exit 1
fi

echo "Test 1: Basic assembly with JSON manifest"
cat > "$TMP_DIR/manifest.json" << 'EOF'
{
    "program_name": "test_prog",
    "program_version": "1.0.0",
    "hook_type": 1,
    "hook_ctx_abi_version": 1,
    "mquickjs_bytecode_version": 32769,
    "target": {"word_size": 64, "endianness": "little"},
    "mbpf_api_version": 65536,
    "heap_size": 16384,
    "budgets": {"max_steps": 10000, "max_helpers": 100},
    "capabilities": ["CAP_LOG"]
}
EOF

cat > "$TMP_DIR/prog.js" << 'EOF'
function mbpf_prog(ctx) {
    return 42;
}
EOF

# Compile JS to bytecode
"$PROJECT_ROOT/deps/mquickjs/mqjs" --no-column -o "$TMP_DIR/prog.qjbc" "$TMP_DIR/prog.js"

# Assemble package
"$TOOLS_DIR/mbpf-assemble" -m "$TMP_DIR/manifest.json" -b "$TMP_DIR/prog.qjbc" -o "$TMP_DIR/prog.mbpf"

# Verify output exists and has content
if [ ! -f "$TMP_DIR/prog.mbpf" ]; then
    echo "FAIL: Output file not created"
    exit 1
fi

SIZE=$(stat -c %s "$TMP_DIR/prog.mbpf" 2>/dev/null || stat -f %z "$TMP_DIR/prog.mbpf")
if [ "$SIZE" -lt 100 ]; then
    echo "FAIL: Output file too small ($SIZE bytes)"
    exit 1
fi

# Verify magic number
MAGIC=$(od -A n -t x1 -N 4 "$TMP_DIR/prog.mbpf" | tr -d ' ')
if [ "$MAGIC" != "4650424d" ]; then
    echo "FAIL: Wrong magic number: $MAGIC"
    exit 1
fi

echo "  PASS: Created package ($SIZE bytes)"

echo ""
echo "Test 2: Assembly with CRC enabled"
"$TOOLS_DIR/mbpf-assemble" -m "$TMP_DIR/manifest.json" -b "$TMP_DIR/prog.qjbc" --crc -o "$TMP_DIR/prog_crc.mbpf"

# Check CRC field is non-zero (bytes 16-19)
CRC=$(od -A n -t x1 -j 16 -N 4 "$TMP_DIR/prog_crc.mbpf" | tr -d ' ')
if [ "$CRC" = "00000000" ]; then
    echo "FAIL: CRC not set"
    exit 1
fi
echo "  PASS: CRC enabled (crc=$CRC)"

echo ""
echo "Test 3: Assembly with debug flag"
"$TOOLS_DIR/mbpf-assemble" -m "$TMP_DIR/manifest.json" -b "$TMP_DIR/prog.qjbc" --debug -o "$TMP_DIR/prog_debug.mbpf"

# Check flags field (bytes 8-11)
FLAGS=$(od -A n -t x1 -j 8 -N 4 "$TMP_DIR/prog_debug.mbpf" | tr -d ' ')
if [ "$FLAGS" != "02000000" ]; then
    echo "FAIL: Debug flag not set: $FLAGS"
    exit 1
fi
echo "  PASS: Debug flag set"

echo ""
echo "Test 4: Error handling - missing manifest"
set +e
OUTPUT=$("$TOOLS_DIR/mbpf-assemble" -b "$TMP_DIR/prog.qjbc" -o "$TMP_DIR/err.mbpf" 2>&1)
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -eq 0 ]; then
    echo "FAIL: Should fail without manifest"
    exit 1
fi
echo "  PASS: Correctly reports missing manifest"

echo ""
echo "Test 5: Error handling - missing bytecode"
set +e
OUTPUT=$("$TOOLS_DIR/mbpf-assemble" -m "$TMP_DIR/manifest.json" -o "$TMP_DIR/err.mbpf" 2>&1)
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -eq 0 ]; then
    echo "FAIL: Should fail without bytecode"
    exit 1
fi
echo "  PASS: Correctly reports missing bytecode"

echo ""
echo "=== All tests passed ==="
