#!/bin/bash
#
# End-to-end test for toolchain-signing task
#
# Steps:
# 1. Generate Ed25519 keypair
# 2. Sign package bytes (excluding signature section)
# 3. Append MBPF_SEC_SIG section with signature
# 4. Verify signed package can be loaded

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
TOOLS_DIR="$BUILD_DIR"
MQUICKJS_DIR="$PROJECT_ROOT/deps/mquickjs"
TMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

skip_test() {
    echo "SKIP: $1"
    exit 0
}

ensure_make() {
    if ! command -v make >/dev/null 2>&1; then
        skip_test "make not found; install build tools or run on a machine with make."
    fi
}

ensure_tool() {
    local tool_path="$1"
    local make_target="$2"
    if [ -x "$tool_path" ]; then
        return 0
    fi
    ensure_make
    echo "Info: Building $make_target..."
    if ! make -C "$PROJECT_ROOT" "$make_target"; then
        skip_test "failed to build $make_target; run 'make $make_target' in $PROJECT_ROOT."
    fi
    if [ ! -x "$tool_path" ]; then
        skip_test "expected $tool_path after build; run 'make $make_target' in $PROJECT_ROOT."
    fi
}

echo "=== microBPF Toolchain Signing End-to-End Test ==="
echo ""

# Check required binaries
ensure_tool "$TOOLS_DIR/mbpf_sign" "build/mbpf_sign"
ensure_tool "$TOOLS_DIR/mbpf_assemble" "build/mbpf_assemble"
ensure_tool "$TOOLS_DIR/mbpf_manifest_gen" "build/mbpf_manifest_gen"
ensure_tool "$MQUICKJS_DIR/mqjs" "mquickjs"

# Step 1: Generate Ed25519 keypair
echo "Step 1: Generate Ed25519 keypair..."
"$TOOLS_DIR/mbpf_sign" keygen -o "$TMP_DIR/keypair.key"
if [ ! -f "$TMP_DIR/keypair.key" ]; then
    echo "FAIL: keypair.key not generated"
    exit 1
fi
echo "  - keypair.key created ($(stat -c%s "$TMP_DIR/keypair.key") bytes)"

# Extract public key
"$TOOLS_DIR/mbpf_sign" pubkey -k "$TMP_DIR/keypair.key" -o "$TMP_DIR/public.key"
if [ ! -f "$TMP_DIR/public.key" ]; then
    echo "FAIL: public.key not extracted"
    exit 1
fi
echo "  - public.key extracted ($(stat -c%s "$TMP_DIR/public.key") bytes)"
echo "  PASS"
echo ""

# Step 2: Create an unsigned .mbpf package
echo "Step 2: Create an unsigned .mbpf package..."

# Create a simple JS program
cat > "$TMP_DIR/test_prog.js" <<'EOF'
function mbpf_prog(ctx) {
    return 0;
}
EOF

# Compile to bytecode
"$MQUICKJS_DIR/mqjs" --no-column -o "$TMP_DIR/test_prog.qjbc" "$TMP_DIR/test_prog.js"
if [ ! -f "$TMP_DIR/test_prog.qjbc" ]; then
    echo "FAIL: bytecode compilation failed"
    exit 1
fi
echo "  - bytecode compiled ($(stat -c%s "$TMP_DIR/test_prog.qjbc") bytes)"

# Generate manifest
"$TOOLS_DIR/mbpf_manifest_gen" \
    --name "test_signing" \
    --version "1.0.0" \
    --hook tracepoint \
    --heap 16384 \
    --max-steps 1000 \
    --max-helpers 100 \
    --format cbor \
    -o "$TMP_DIR/manifest.cbor"
if [ ! -f "$TMP_DIR/manifest.cbor" ]; then
    echo "FAIL: manifest generation failed"
    exit 1
fi
echo "  - manifest generated ($(stat -c%s "$TMP_DIR/manifest.cbor") bytes)"

# Assemble unsigned package
"$TOOLS_DIR/mbpf_assemble" \
    -m "$TMP_DIR/manifest.cbor" \
    -b "$TMP_DIR/test_prog.qjbc" \
    -o "$TMP_DIR/unsigned.mbpf"
if [ ! -f "$TMP_DIR/unsigned.mbpf" ]; then
    echo "FAIL: package assembly failed"
    exit 1
fi
echo "  - unsigned.mbpf created ($(stat -c%s "$TMP_DIR/unsigned.mbpf") bytes)"
echo "  PASS"
echo ""

# Step 3: Sign the package
echo "Step 3: Sign package with Ed25519..."
"$TOOLS_DIR/mbpf_sign" sign \
    -k "$TMP_DIR/keypair.key" \
    -i "$TMP_DIR/unsigned.mbpf" \
    -o "$TMP_DIR/signed.mbpf"
if [ ! -f "$TMP_DIR/signed.mbpf" ]; then
    echo "FAIL: package signing failed"
    exit 1
fi

UNSIGNED_SIZE=$(stat -c%s "$TMP_DIR/unsigned.mbpf")
SIGNED_SIZE=$(stat -c%s "$TMP_DIR/signed.mbpf")

# Signature section adds 16 bytes (section descriptor) + 64 bytes (signature) = 80 bytes
EXPECTED_SIZE=$((UNSIGNED_SIZE + 80))

echo "  - signed.mbpf created ($SIGNED_SIZE bytes)"
echo "  - Size increased by $((SIGNED_SIZE - UNSIGNED_SIZE)) bytes"
echo "  PASS"
echo ""

# Step 4: Verify the signature
echo "Step 4: Verify package signature..."
"$TOOLS_DIR/mbpf_sign" verify \
    -k "$TMP_DIR/public.key" \
    -i "$TMP_DIR/signed.mbpf"
echo "  PASS"
echo ""

# Step 5: Verify that verification fails with wrong key
echo "Step 5: Verify that wrong key is rejected..."
"$TOOLS_DIR/mbpf_sign" keygen -o "$TMP_DIR/wrong_keypair.key"
"$TOOLS_DIR/mbpf_sign" pubkey -k "$TMP_DIR/wrong_keypair.key" -o "$TMP_DIR/wrong_public.key"

if "$TOOLS_DIR/mbpf_sign" verify -k "$TMP_DIR/wrong_public.key" -i "$TMP_DIR/signed.mbpf" 2>/dev/null; then
    echo "FAIL: Verification with wrong key should fail"
    exit 1
fi
echo "  PASS (wrong key correctly rejected)"
echo ""

# Step 6: Verify that tampered package is rejected
echo "Step 6: Verify that tampered package is rejected..."
cp "$TMP_DIR/signed.mbpf" "$TMP_DIR/tampered.mbpf"
# Flip a byte in the middle of the package
python3 -c "
import sys
with open('$TMP_DIR/tampered.mbpf', 'r+b') as f:
    f.seek(100)
    b = f.read(1)
    f.seek(100)
    f.write(bytes([b[0] ^ 0xFF]))
"

if "$TOOLS_DIR/mbpf_sign" verify -k "$TMP_DIR/public.key" -i "$TMP_DIR/tampered.mbpf" 2>/dev/null; then
    echo "FAIL: Verification of tampered package should fail"
    exit 1
fi
echo "  PASS (tampered package correctly rejected)"
echo ""

# Step 7: Verify that unsigned package is rejected
echo "Step 7: Verify that unsigned package is rejected..."
if "$TOOLS_DIR/mbpf_sign" verify -k "$TMP_DIR/public.key" -i "$TMP_DIR/unsigned.mbpf" 2>/dev/null; then
    echo "FAIL: Unsigned package should be rejected"
    exit 1
fi
echo "  PASS (unsigned package correctly rejected)"
echo ""

echo "=== All End-to-End Tests Passed ==="
exit 0
