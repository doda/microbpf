# microBPF Package Format (.mbpf)

This document describes the binary format of `.mbpf` package files for tooling authors. The format is designed to be parseable in a single pass with bounded memory, and to support adding new sections without breaking older loaders.

## Table of Contents

- [Overview](#overview)
- [File Structure](#file-structure)
  - [File Header](#file-header)
  - [Section Table](#section-table)
  - [Section Data](#section-data)
- [Section Types](#section-types)
  - [MANIFEST Section](#manifest-section)
  - [BYTECODE Section](#bytecode-section)
  - [MAPS Section](#maps-section)
  - [DEBUG Section](#debug-section)
  - [SIG Section](#sig-section)
- [Manifest Schema](#manifest-schema)
  - [Required Fields](#required-fields)
  - [Optional Fields](#optional-fields)
  - [Field Formats](#field-formats)
  - [CBOR Encoding](#cbor-encoding)
  - [JSON Encoding](#json-encoding)
- [Integrity Validation](#integrity-validation)
  - [CRC32 Checksums](#crc32-checksums)
- [Signing Procedure](#signing-procedure)
  - [Keypair Generation](#keypair-generation)
  - [Signing a Package](#signing-a-package)
  - [Signature Verification](#signature-verification)
- [Assembly Procedure](#assembly-procedure)
- [Tooling Reference](#tooling-reference)
- [Examples](#examples)

---

## Overview

A `.mbpf` (microBPF Package Format) file is a binary container that bundles:

- **Manifest**: Metadata about the program (name, version, hook type, budgets, etc.)
- **Bytecode**: Precompiled MQuickJS bytecode
- **Maps** (optional): Map definitions (may also be in manifest)
- **Debug** (optional): Symbol names and source hash for debugging
- **Signature** (optional): Ed25519 signature for integrity verification

All integer fields in the format are **little-endian**.

### Design Goals

1. Single-pass parsing with bounded memory
2. Extensible: unknown section types are skipped gracefully
3. Signed packages bind all content under a single signature
4. Support for offline compilation and OTA updates

### Magic Number

Files start with the 32-bit magic value `0x4D425046` ("MBPF" in ASCII when interpreted as a little-endian word). On disk, the first four bytes appear as `0x46 0x50 0x42 0x4D`.

---

## File Structure

A `.mbpf` file consists of three regions:

```
+------------------+
|   File Header    |  20 bytes
+------------------+
|  Section Table   |  16 bytes × section_count
+------------------+
|   Section Data   |  Variable length
+------------------+
```

### File Header

The file header is 20 bytes with the following layout:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `magic` | Magic number: `0x4D425046` |
| 4 | 2 | `format_version` | Format version (currently 1) |
| 6 | 2 | `header_size` | Total header size including section table |
| 8 | 4 | `flags` | Header flags (see below) |
| 12 | 4 | `section_count` | Number of sections |
| 16 | 4 | `file_crc32` | Optional CRC32 of file (0 if unused) |

#### Header Flags

| Flag | Value | Description |
|------|-------|-------------|
| `MBPF_FLAG_SIGNED` | `0x01` | Package has a signature section |
| `MBPF_FLAG_DEBUG` | `0x02` | Package has debug information |

#### C Definition

```c
typedef struct __attribute__((packed)) {
    uint32_t magic;           /* MBPF_MAGIC = 0x4D425046 */
    uint16_t format_version;  /* 1 */
    uint16_t header_size;     /* sizeof(header) + section_count * sizeof(section_desc) */
    uint32_t flags;           /* MBPF_FLAG_* */
    uint32_t section_count;
    uint32_t file_crc32;      /* 0 if unused */
} mbpf_file_header_t;
```

### Section Table

Immediately following the file header is the section table. Each entry is 16 bytes:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `type` | Section type (see Section Types) |
| 4 | 4 | `offset` | Byte offset from file start |
| 8 | 4 | `length` | Section length in bytes |
| 12 | 4 | `crc32` | Optional CRC32 of section data (0 if unused) |

#### C Definition

```c
typedef struct __attribute__((packed)) {
    uint32_t type;
    uint32_t offset;
    uint32_t length;
    uint32_t crc32;
} mbpf_section_desc_t;
```

#### Validation Rules

1. Section offsets must be ≥ `header_size`
2. Section bounds (`offset + length`) must not exceed file size
3. Sections must not overlap
4. Unknown section types should be skipped (for forward compatibility)

### Section Data

Section data follows the header and section table. Sections may be placed in any order, but the recommended order is:

1. MANIFEST
2. BYTECODE
3. MAPS (optional)
4. DEBUG (optional)
5. SIG (must be last if present)

---

## Section Types

| Type | Value | Required | Description |
|------|-------|----------|-------------|
| `MBPF_SEC_MANIFEST` | 1 | Yes | Program metadata (CBOR or JSON) |
| `MBPF_SEC_BYTECODE` | 2 | Yes | MQuickJS bytecode |
| `MBPF_SEC_MAPS` | 3 | No | Map definitions (alternative to manifest) |
| `MBPF_SEC_DEBUG` | 4 | No | Debug symbols and source hash |
| `MBPF_SEC_SIG` | 5 | No | Ed25519 signature |

### MANIFEST Section

Contains program metadata encoded as either CBOR (preferred) or JSON. The loader auto-detects the encoding:

- CBOR: First byte is `0xA0`–`0xBF` (map with 0–23 elements) or `0xBF` (indefinite map)
- JSON: First byte is `0x7B` (`{`)

See [Manifest Schema](#manifest-schema) for field definitions.

### BYTECODE Section

Contains the MQuickJS bytecode blob in "relocated-to-zero" form. This is the output of:

```bash
mqjs --no-column -o prog.qjbc prog.js
```

Key properties:
- Architecture-dependent (word size and endianness)
- Version-dependent (`JS_BYTECODE_VERSION`)
- Must be copied to writable memory before relocation

The loader must:
1. Copy the bytecode to a writable buffer
2. Call `JS_RelocateBytecode(ctx, buf, len)`
3. Call `JS_LoadBytecode(ctx, buf)` to obtain the main function
4. Reject if `JS_IsBytecode()` fails or version mismatches

### MAPS Section

Optional section containing map definitions. Maps may alternatively be defined in the manifest. The binary layout is:

```
[4 bytes: map_count]
For each map:
  [32 bytes: name (null-padded)]
  [4 bytes: type]
  [4 bytes: key_size]
  [4 bytes: value_size]
  [4 bytes: max_entries]
  [4 bytes: flags]
```

### DEBUG Section

Optional section containing debug symbols for development and provenance tracking.

#### Binary Layout

```
[4 bytes: flags]
[32 bytes: source_hash (SHA-256)]
[4 bytes: entry_symbol_len]
[entry_symbol_len bytes: entry_symbol]
[4 bytes: hook_name_len]
[hook_name_len bytes: hook_name]
[4 bytes: map_count]
For each map:
  [4 bytes: name_len]
  [name_len bytes: name]
```

#### Debug Flags

| Flag | Value | Description |
|------|-------|-------------|
| `MBPF_DEBUG_FLAG_HAS_SOURCE_HASH` | `0x01` | source_hash field is valid |

#### String Encoding Notes

- Strings are length-prefixed with a 32-bit little-endian byte count.
- The bytes are treated as raw bytes; tools typically write a trailing NUL, but the parser does not require it.
- Zero-length strings are allowed.
- Parsers cap copied strings at `MBPF_DEBUG_MAX_SYMBOL_LEN - 1` and NUL-terminate the in-memory copy.
- `map_count` is validated by the loader and must be ≤ 256.

If `MBPF_DEBUG_FLAG_HAS_SOURCE_HASH` is not set, `source_hash` is expected to be zeroed.

### SIG Section

Contains a 64-byte Ed25519 signature. This section must be the **last section** in the file when present.

#### Binary Layout

```
[64 bytes: Ed25519 signature]
```

The signature covers all bytes from file offset 0 up to (but excluding) the signature section data. The loader enforces:

- `length == 64`
- `sig_offset + 64 == file_length` (no trailing unsigned bytes)
- Signature coverage uses `sig_offset` as the signed length

---

## Manifest Schema

The manifest is a key-value structure encoded as CBOR or JSON.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `program_name` | string | Program identifier (max 63 chars) |
| `program_version` | string | Version string (e.g., "1.0.0") |
| `hook_type` | integer | Hook type enum (1–6) |
| `hook_ctx_abi_version` | integer | Required context ABI version |
| `mquickjs_bytecode_version` | integer | Expected `JS_BYTECODE_VERSION` |
| `target` | object | Target architecture |
| `mbpf_api_version` | integer | Required API version (`major<<16 \| minor`) |
| `heap_size` | integer | Heap size in bytes (min 8192) |
| `budgets` | object | Execution budgets |
| `capabilities` | array | Required capabilities |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `entry_symbol` | string | `"mbpf_prog"` | Entry function name |
| `helper_versions` | object | none | Per-helper version requirements |
| `maps` | array | none | Map definitions |

### Field Formats

#### hook_type

| Value | Name | Description |
|-------|------|-------------|
| 1 | `MBPF_HOOK_TRACEPOINT` | Tracepoint/observability |
| 2 | `MBPF_HOOK_TIMER` | Timer/periodic execution |
| 3 | `MBPF_HOOK_NET_RX` | Network receive path |
| 4 | `MBPF_HOOK_NET_TX` | Network transmit path |
| 5 | `MBPF_HOOK_SECURITY` | Security authorization |
| 6 | `MBPF_HOOK_CUSTOM` | Platform-defined custom hook |

#### target

```json
{
  "word_size": 64,      // 32 or 64
  "endianness": "little" // "little" or "big"
}
```

#### budgets

```json
{
  "max_steps": 10000,      // Maximum VM steps per invocation
  "max_helpers": 100,      // Maximum helper calls per invocation
  "max_wall_time_us": 0    // Optional wall-clock timeout (0 = disabled)
}
```

#### capabilities

Array of capability strings:

| Capability | Description |
|------------|-------------|
| `"CAP_LOG"` | `mbpf.log()` helper |
| `"CAP_MAP_READ"` | Map lookup operations |
| `"CAP_MAP_WRITE"` | Map update/delete operations |
| `"CAP_MAP_ITERATE"` | Map iteration (`nextKey`) |
| `"CAP_EMIT"` | `mbpf.emit()` helper |
| `"CAP_TIME"` | `mbpf.nowNs()` helper |
| `"CAP_STATS"` | `mbpf.stats()` helper |

#### helper_versions

Optional map of helper name to required version:

```json
{
  "log": 65537,    // major=1, minor=1 → (1<<16)|1
  "emit": 131072   // major=2, minor=0 → (2<<16)|0
}
```

#### maps

Array of map definitions:

```json
[
  {
    "name": "counters",
    "type": 2,            // MBPF_MAP_TYPE_HASH
    "key_size": 8,
    "value_size": 4,
    "max_entries": 100,
    "flags": 0
  }
]
```

Map type values:

| Value | Name | Description |
|-------|------|-------------|
| 1 | `MBPF_MAP_TYPE_ARRAY` | Fixed-size array |
| 2 | `MBPF_MAP_TYPE_HASH` | Hash table |
| 3 | `MBPF_MAP_TYPE_LRU` | LRU hash map |
| 5 | `MBPF_MAP_TYPE_RING` | Ring buffer |
| 6 | `MBPF_MAP_TYPE_COUNTER` | Atomic counter |
| 7 | `MBPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU array |
| 8 | `MBPF_MAP_TYPE_PERCPU_HASH` | Per-CPU hash |

### CBOR Encoding

CBOR is the preferred encoding for manifests due to its compact size. Use standard CBOR maps with string keys.

Example CBOR structure (in diagnostic notation):

```
{
  "program_name": "my_filter",
  "program_version": "1.0.0",
  "hook_type": 3,
  "hook_ctx_abi_version": 1,
  "mquickjs_bytecode_version": 2,
  "target": {
    "word_size": 64,
    "endianness": "little"
  },
  "mbpf_api_version": 1,
  "heap_size": 16384,
  "budgets": {
    "max_steps": 10000,
    "max_helpers": 100
  },
  "capabilities": ["CAP_LOG", "CAP_MAP_READ", "CAP_MAP_WRITE"],
  "maps": [
    {
      "name": "stats",
      "type": 1,
      "key_size": 0,
      "value_size": 8,
      "max_entries": 16,
      "flags": 0
    }
  ]
}
```

### JSON Encoding

JSON encoding is allowed for development/debugging but CBOR is preferred for production.

```json
{
  "program_name": "my_filter",
  "program_version": "1.0.0",
  "hook_type": 3,
  "hook_ctx_abi_version": 1,
  "mquickjs_bytecode_version": 2,
  "target": {
    "word_size": 64,
    "endianness": "little"
  },
  "mbpf_api_version": 1,
  "heap_size": 16384,
  "budgets": {
    "max_steps": 10000,
    "max_helpers": 100
  },
  "capabilities": ["CAP_LOG", "CAP_MAP_READ", "CAP_MAP_WRITE"],
  "maps": [
    {
      "name": "stats",
      "type": 1,
      "key_size": 0,
      "value_size": 8,
      "max_entries": 16,
      "flags": 0
    }
  ]
}
```

---

## Integrity Validation

### CRC32 Checksums

The package format supports two levels of CRC32 validation:

#### File-Level CRC

If `file_crc32` in the header is non-zero, it must equal the CRC32 of:
- All bytes from offset 0 to the end of file
- **Excluding bytes 16–19** (the `file_crc32` field itself is skipped during computation)

#### Per-Section CRC

If a section descriptor's `crc32` field is non-zero, it must equal the CRC32 of the section data bytes.

#### CRC32 Algorithm

Standard CRC-32 (polynomial 0x04C11DB7, reflected, initial value 0xFFFFFFFF, final XOR 0xFFFFFFFF). This matches the common zlib/PNG CRC-32.

---

## Signing Procedure

Package signing uses Ed25519 for compact signatures and fast verification.

### Keypair Generation

Generate an Ed25519 keypair:

```bash
# Using mbpf_sign tool
mbpf_sign keygen -o keypair.key

# Or using OpenSSL
openssl genpkey -algorithm Ed25519 -out private.pem
```

The keypair file contains:
- 32 bytes: seed (private scalar)
- 32 bytes: public key

Extract the public key for distribution:

```bash
mbpf_sign pubkey -k keypair.key -o public.key
```

### Signing a Package

To sign an unsigned package:

```bash
mbpf_sign sign -k keypair.key -i unsigned.mbpf -o signed.mbpf
```

The signing process:

1. Parse the unsigned package
2. Verify package is not already signed
3. Create new header with `section_count + 1` and `MBPF_FLAG_SIGNED`
4. Adjust all section offsets for the larger header
5. Append SIG section descriptor
6. Compute Ed25519 signature over bytes `[0, sig_section.offset)`
7. Append 64-byte signature

#### Programmatic Signing

```c
#include "mbpf_package.h"
#include "ed25519.h"

int sign_package(const uint8_t *pkg, size_t pkg_len,
                 const uint8_t *secret_key,
                 uint8_t **out_signed, size_t *out_len) {
    // 1. Parse original header
    mbpf_file_header_t header;
    mbpf_package_parse_header(pkg, pkg_len, &header);

    // 2. Calculate new sizes
    uint32_t new_section_count = header.section_count + 1;
    size_t new_header_size = sizeof(mbpf_file_header_t) +
                             new_section_count * sizeof(mbpf_section_desc_t);
    size_t old_header_size = header.header_size;
    size_t data_size = pkg_len - old_header_size;
    size_t sig_offset = new_header_size + data_size;
    size_t new_pkg_len = sig_offset + 64;

    // 3. Allocate and build new package
    uint8_t *signed_pkg = malloc(new_pkg_len);
    // ... copy header, adjust offsets, copy data ...

    // 4. Sign everything before signature section
    uint8_t signature[64];
    ed25519_sign(signature, signed_pkg, sig_offset, secret_key);
    memcpy(signed_pkg + sig_offset, signature, 64);

    *out_signed = signed_pkg;
    *out_len = new_pkg_len;
    return 0;
}
```

### Signature Verification

To verify a signed package:

```bash
mbpf_sign verify -k public.key -i signed.mbpf
```

The verification process:

1. Parse package and find SIG section
2. Verify SIG section is last and exactly 64 bytes
3. Compute Ed25519 signature verification over bytes `[0, sig_section.offset)`
4. Compare computed signature with stored signature

#### Programmatic Verification

```c
#include "mbpf_package.h"

int verify_package(const uint8_t *pkg, size_t pkg_len,
                   const uint8_t *public_key) {
    mbpf_sig_verify_opts_t opts = {
        .public_key = public_key,      // 32-byte Ed25519 public key
        .allow_unsigned = 0,           // Reject unsigned packages
        .production_mode = 1,          // Enforce signature requirement
    };

    return mbpf_package_verify_signature(pkg, pkg_len, &opts);
}
```

#### Verification Policy

| Mode | Unsigned Package | Invalid Signature |
|------|------------------|-------------------|
| Development | Allowed (if `allow_unsigned`) | Rejected |
| Production | Rejected | Rejected |

---

## Assembly Procedure

To create a `.mbpf` package from components:

### Step 1: Compile JavaScript to Bytecode

```bash
mqjs --no-column -o prog.qjbc prog.js

# For 32-bit targets on a 64-bit host:
mqjs --no-column -m32 -o prog.qjbc prog.js
```

### Step 2: Create Manifest

Prepare a manifest structure with all required fields:

```c
mbpf_manifest_t manifest;
mbpf_manifest_init_defaults(&manifest);

strcpy(manifest.program_name, "my_filter");
strcpy(manifest.program_version, "1.0.0");
manifest.hook_type = MBPF_HOOK_NET_RX;
manifest.heap_size = 16384;
manifest.budgets.max_steps = 10000;
manifest.budgets.max_helpers = 100;
manifest.capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ;
// ... set other fields ...

// Generate CBOR
size_t cbor_len = mbpf_manifest_cbor_size(&manifest);
uint8_t *cbor_data = malloc(cbor_len);
mbpf_manifest_generate_cbor(&manifest, cbor_data, &cbor_len);
```

### Step 3: Assemble Package

```c
mbpf_section_input_t sections[] = {
    { .type = MBPF_SEC_MANIFEST, .data = manifest_data, .len = manifest_len },
    { .type = MBPF_SEC_BYTECODE, .data = bytecode_data, .len = bytecode_len },
};

mbpf_assemble_opts_t opts = {
    .compute_file_crc = 1,
    .compute_section_crcs = 1,
    .flags = 0,  // MBPF_FLAG_DEBUG or MBPF_FLAG_SIGNED (when applicable)
};

size_t pkg_size = mbpf_package_size(sections, 2);
uint8_t *pkg = malloc(pkg_size);
size_t out_len = pkg_size;

mbpf_package_assemble(sections, 2, &opts, pkg, &out_len);
```

#### Assembly and Validation (Tooling Example)

The `mbpf_assemble` CLI wires assembly options directly:

```bash
# Assemble with CRCs enabled (sets file_crc32 and per-section CRCs).
mbpf_assemble -m manifest.json -b prog.qjbc --crc -o prog.mbpf

# Optionally add debug info and set the header DEBUG flag.
mbpf_assemble -m manifest.json -b prog.qjbc -d debug.bin --debug -o prog.mbpf

# Sign and verify (mbpf_sign adds MBPF_FLAG_SIGNED and a SIG section).
mbpf_sign sign -k keypair.key -i prog.mbpf -o prog.signed.mbpf
mbpf_sign verify -k public.key -i prog.signed.mbpf
```

When CRCs are present, loaders call `mbpf_package_validate_crc()` and
`mbpf_package_validate_section_crc()` to enforce them. When a signature is
present, loaders call `mbpf_package_verify_signature()` to enforce the
signature rules above.

### Step 4: Sign Package (Optional)

```bash
mbpf_sign sign -k keypair.key -i unsigned.mbpf -o signed.mbpf
```

---

## Tooling Reference

### mbpf_sign

Command-line tool for package signing:

```
Usage: mbpf_sign <command> [options]

Commands:
  keygen   Generate Ed25519 keypair
  pubkey   Extract public key from keypair
  sign     Sign a .mbpf package
  verify   Verify package signature

Options:
  -k FILE  Key file (keypair for sign, public for verify)
  -i FILE  Input .mbpf package
  -o FILE  Output file
  -h       Show help
```

### mbpf_assemble

Command-line tool for package assembly:

```
Usage: mbpf_assemble [options] -o output.mbpf

Options:
  -m FILE    Manifest file (CBOR or JSON)
  -b FILE    Bytecode file
  -d FILE    Debug section file (optional)
  --crc      Compute CRC32 checksums
  -o FILE    Output .mbpf file
```

### C API

| Function | Description |
|----------|-------------|
| `mbpf_package_parse_header()` | Parse file header |
| `mbpf_package_parse_section_table()` | Parse section table |
| `mbpf_package_get_section()` | Get section by type |
| `mbpf_package_parse_manifest()` | Parse manifest |
| `mbpf_package_assemble()` | Assemble package from sections |
| `mbpf_package_verify_signature()` | Verify Ed25519 signature |
| `mbpf_crc32()` | Compute CRC32 |
| `mbpf_manifest_generate_cbor()` | Generate CBOR manifest |
| `mbpf_manifest_generate_json()` | Generate JSON manifest |

---

## Examples

### Minimal Package (Hex Dump)

A minimal unsigned package with MANIFEST and BYTECODE:

```
00000000: 4650 424d 0100 3400 0000 0000 0200 0000  FPBM..4.........
00000010: 0000 0000 0100 0000 3400 0000 xxxx xxxx  ........4.......
00000020: 0000 0000 0200 0000 yyyy yyyy zzzz zzzz  ................
00000030: 0000 0000 [manifest data...]
```

Field breakdown:
- `0x00`: Magic `0x4D425046` ("MBPF" little-endian)
- `0x04`: Format version 1
- `0x06`: Header size 0x34 (52 bytes = 20 + 2×16)
- `0x08`: Flags 0
- `0x0C`: Section count 2
- `0x10`: File CRC32 (0 = unused)
- `0x14`: Section 1 (MANIFEST): type=1, offset=0x34, length=xxx, crc=0
- `0x24`: Section 2 (BYTECODE): type=2, offset=yyy, length=zzz, crc=0
- `0x34`: Section data begins

### Complete Workflow

```bash
# 1. Write JavaScript program
cat > filter.js << 'EOF'
function mbpf_prog(ctx) {
    if (ctx.pkt_len < 1) return 0;
    if (ctx.readU8(0) === 0xFF) return 1;  // DROP
    return 0;  // PASS
}
EOF

# 2. Compile to bytecode
mqjs --no-column -o filter.qjbc filter.js

# 3. Create manifest
cat > manifest.json << 'EOF'
{
  "program_name": "drop_ff",
  "program_version": "1.0.0",
  "hook_type": 3,
  "hook_ctx_abi_version": 1,
  "mquickjs_bytecode_version": 2,
  "target": {"word_size": 64, "endianness": "little"},
  "mbpf_api_version": 1,
  "heap_size": 8192,
  "budgets": {"max_steps": 1000, "max_helpers": 10},
  "capabilities": []
}
EOF

# 4. Assemble package
mbpf_assemble -m manifest.json -b filter.qjbc --crc -o filter.mbpf

# 5. Sign package
mbpf_sign keygen -o dev.key
mbpf_sign sign -k dev.key -i filter.mbpf -o filter_signed.mbpf

# 6. Verify signature
mbpf_sign verify -k dev.key -i filter_signed.mbpf
```

---

## See Also

- [SPEC.md](../SPEC.md) - Full technical specification
- [C_API_REFERENCE.md](C_API_REFERENCE.md) - C API reference
- [JS_API_REFERENCE.md](JS_API_REFERENCE.md) - JavaScript API reference
- [mbpf_package.h](../include/mbpf_package.h) - Package format C header
