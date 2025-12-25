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

# Run bytecode tests
if [ -f build/test_bytecode ]; then
    ./build/test_bytecode
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Bytecode tests failed"
        exit 1
    fi
fi

# Run CRC validation tests
if [ -f build/test_crc ]; then
    ./build/test_crc
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: CRC validation tests failed"
        exit 1
    fi
fi

# Run signature verification tests
if [ -f build/test_signing ]; then
    ./build/test_signing
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Signature verification tests failed"
        exit 1
    fi
fi

# Run runtime init/shutdown tests
if [ -f build/test_runtime ]; then
    ./build/test_runtime
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Runtime init/shutdown tests failed"
        exit 1
    fi
fi

# Run program load tests
if [ -f build/test_program_load ]; then
    ./build/test_program_load
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Program load tests failed"
        exit 1
    fi
fi

# Run program load validation tests
if [ -f build/test_program_load_validation ]; then
    ./build/test_program_load_validation
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Program load validation tests failed"
        exit 1
    fi
fi

# Run program unload tests
if [ -f build/test_program_unload ]; then
    ./build/test_program_unload
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Program unload tests failed"
        exit 1
    fi
fi

# Run program attach/detach tests
if [ -f build/test_attach_detach ]; then
    ./build/test_attach_detach
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Program attach/detach tests failed"
        exit 1
    fi
fi

# Run program attach validation tests
if [ -f build/test_attach_validation ]; then
    ./build/test_attach_validation
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Program attach validation tests failed"
        exit 1
    fi
fi

# Run runtime run basic tests
if [ -f build/test_run_basic ]; then
    ./build/test_run_basic
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Runtime run basic tests failed"
        exit 1
    fi
fi

# Run context object tests
if [ -f build/test_context_object ]; then
    ./build/test_context_object
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Context object tests failed"
        exit 1
    fi
fi

# Run context read methods tests
if [ -f build/test_context_read_methods ]; then
    ./build/test_context_read_methods
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Context read methods tests failed"
        exit 1
    fi
fi

# Run NET_RX v1 context tests
if [ -f build/test_context_net_rx_v1 ]; then
    ./build/test_context_net_rx_v1
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: NET_RX v1 context tests failed"
        exit 1
    fi
fi

# Run TRACEPOINT hook tests
if [ -f build/test_hook_tracepoint ]; then
    ./build/test_hook_tracepoint
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: TRACEPOINT hook tests failed"
        exit 1
    fi
fi

# Run TIMER hook tests
if [ -f build/test_hook_timer ]; then
    ./build/test_hook_timer
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: TIMER hook tests failed"
        exit 1
    fi
fi

# Run NET_RX hook tests
if [ -f build/test_hook_net_rx ]; then
    ./build/test_hook_net_rx
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: NET_RX hook tests failed"
        exit 1
    fi
fi

# Run NET_TX hook tests
if [ -f build/test_hook_net_tx ]; then
    ./build/test_hook_net_tx
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: NET_TX hook tests failed"
        exit 1
    fi
fi

# Run mbpf_init entry point tests
if [ -f build/test_mbpf_init ]; then
    ./build/test_mbpf_init
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: mbpf_init entry point tests failed"
        exit 1
    fi
fi

# Run mbpf_fini entry point tests
if [ -f build/test_mbpf_fini ]; then
    ./build/test_mbpf_fini
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: mbpf_fini entry point tests failed"
        exit 1
    fi
fi

# Run exception handling tests
if [ -f build/test_exception_handling ]; then
    ./build/test_exception_handling
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Exception handling tests failed"
        exit 1
    fi
fi

# Run array map tests
if [ -f build/test_array_map ]; then
    ./build/test_array_map
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Array map tests failed"
        exit 1
    fi
fi

# Run hash map tests
if [ -f build/test_hash_map ]; then
    ./build/test_hash_map
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Hash map tests failed"
        exit 1
    fi
fi

# Run map max entries tests
if [ -f build/test_map_max_entries ]; then
    ./build/test_map_max_entries
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Map max entries tests failed"
        exit 1
    fi
fi

# Run map type validation tests
if [ -f build/test_map_type_validation ]; then
    ./build/test_map_type_validation
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Map type validation tests failed"
        exit 1
    fi
fi

# Run counter map tests
if [ -f build/test_counter_map ]; then
    ./build/test_counter_map
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Counter map tests failed"
        exit 1
    fi
fi

# Run map iteration tests
if [ -f build/test_map_iteration ]; then
    ./build/test_map_iteration
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Map iteration tests failed"
        exit 1
    fi
fi

# Run map concurrency tests
if [ -f build/test_map_concurrency ]; then
    ./build/test_map_concurrency
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Map concurrency tests failed"
        exit 1
    fi
fi

# Run helper API version tests
if [ -f build/test_helper_api_version ]; then
    ./build/test_helper_api_version
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Helper API version tests failed"
        exit 1
    fi
fi

# Run helper log tests
if [ -f build/test_helper_log ]; then
    ./build/test_helper_log
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Helper log tests failed"
        exit 1
    fi
fi

# Run budget interrupt handler tests
if [ -f build/test_budget_interrupt_handler ]; then
    ./build/test_budget_interrupt_handler
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Budget interrupt handler tests failed"
        exit 1
    fi
fi

# Run memory minimum heap tests
if [ -f build/test_memory_minimum_heap ]; then
    ./build/test_memory_minimum_heap
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Memory minimum heap tests failed"
        exit 1
    fi
fi

# Run capability enforcement tests
if [ -f build/test_capability_enforcement ]; then
    ./build/test_capability_enforcement
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Capability enforcement tests failed"
        exit 1
    fi
fi

# Run capability categories tests
if [ -f build/test_capability_categories ]; then
    ./build/test_capability_categories
    TEST_RESULT=$?
    if [ $TEST_RESULT -ne 0 ]; then
        echo "ERROR: Capability categories tests failed"
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
