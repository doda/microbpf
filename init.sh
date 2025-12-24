#!/bin/bash
# microBPF Environment Setup and Smoke Test
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "====================================="
echo "microBPF Project Setup and Smoke Test"
echo "====================================="

# Check for required tools
echo ""
echo "Checking build tools..."
for tool in gcc make ar; do
    if ! command -v $tool &> /dev/null; then
        echo "ERROR: $tool is not installed"
        exit 1
    fi
    echo "  ✓ $tool"
done

# Check project structure
echo ""
echo "Verifying project structure..."
for dir in src include tools tests examples deps/mquickjs; do
    if [ ! -d "$dir" ]; then
        echo "ERROR: Directory $dir does not exist"
        exit 1
    fi
    echo "  ✓ $dir/"
done

# Check MQuickJS source files
echo ""
echo "Checking MQuickJS files..."
for file in deps/mquickjs/mquickjs.c deps/mquickjs/mquickjs.h; do
    if [ ! -f "$file" ]; then
        echo "ERROR: $file not found"
        exit 1
    fi
    echo "  ✓ $file"
done

# Build MQuickJS if needed
echo ""
echo "Building MQuickJS..."
if [ ! -f deps/mquickjs/mqjs ]; then
    (cd deps/mquickjs && make) || {
        echo "ERROR: MQuickJS build failed"
        exit 1
    }
fi
echo "  ✓ mqjs compiler built"

# Clean and build microBPF
echo ""
echo "Building microBPF..."
make clean > /dev/null 2>&1 || true
make 2>&1 | grep -E "(Error|error|gcc -o)" || true
if [ ! -f build/libmbpf.a ]; then
    echo "ERROR: libmbpf.a not built"
    exit 1
fi
echo "  ✓ libmbpf.a built"

if [ ! -f build/test_basic ]; then
    echo "ERROR: test_basic not built"
    exit 1
fi
echo "  ✓ test_basic built"

# Run tests
echo ""
echo "Running tests..."
./build/test_basic
TEST_RESULT=$?
if [ $TEST_RESULT -ne 0 ]; then
    echo "ERROR: Basic tests failed"
    exit 1
fi

# Run package header tests
if [ -f build/test_package_header ]; then
    ./build/test_package_header
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Package header tests failed"
        exit 1
    fi
fi

# Run section table tests
if [ -f build/test_section_table ]; then
    ./build/test_section_table
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Section table tests failed"
        exit 1
    fi
fi

# Run manifest tests
if [ -f build/test_manifest ]; then
    ./build/test_manifest
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Manifest tests failed"
        exit 1
    fi
fi

# Test MQuickJS bytecode compilation
echo ""
echo "Testing bytecode compilation..."
deps/mquickjs/mqjs --no-column -o build/example.qjbc examples/net_rx_filter.js
if [ ! -f build/example.qjbc ]; then
    echo "ERROR: Bytecode compilation failed"
    exit 1
fi
echo "  ✓ Bytecode compilation successful"

# Summary
echo ""
echo "====================================="
echo "All checks passed!"
echo "====================================="
echo ""
echo "Project Status:"
echo "  - C compiler: $(gcc --version | head -1)"
echo "  - MQuickJS: $(deps/mquickjs/mqjs --help 2>&1 | head -1)"
echo "  - Library: build/libmbpf.a ($(ls -la build/libmbpf.a | awk '{print $5}') bytes)"
echo "  - Tests: All passed"
echo ""

exit 0
