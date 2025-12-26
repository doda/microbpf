# microBPF C API Reference

This document provides a comprehensive reference for embedding microBPF in C applications. It covers all public APIs defined in `mbpf.h`, `mbpf_package.h`, and `mbpf_manifest_gen.h`.

## Table of Contents

- [Overview](#overview)
- [Version Information](#version-information)
- [Error Codes](#error-codes)
- [Types and Structures](#types-and-structures)
  - [Runtime Configuration](#runtime-configuration)
  - [Load Options](#load-options)
  - [Update Options](#update-options)
  - [Statistics](#statistics)
  - [Hook Types](#hook-types)
  - [Context Structures](#context-structures)
  - [Map Types](#map-types)
  - [Capabilities](#capabilities)
  - [Package and Manifest Structures](#package-and-manifest-structures)
- [Core API Functions](#core-api-functions)
  - [Runtime Lifecycle](#runtime-lifecycle)
  - [Program Lifecycle](#program-lifecycle)
  - [Program Execution](#program-execution)
  - [Program Information](#program-information)
- [Map Access API](#map-access-api)
  - [Lock-Free Map Reads](#lock-free-map-reads)
  - [Locked Map Updates](#locked-map-updates)
- [Ring Buffer API](#ring-buffer-api)
- [Event Emit API](#event-emit-api)
- [Deferred Execution API](#deferred-execution-api)
- [Debug Info API](#debug-info-api)
- [Package API](#package-api)
  - [Package Parsing](#package-parsing)
  - [Package Assembly](#package-assembly)
  - [Signature Verification](#signature-verification)
  - [Bytecode Operations](#bytecode-operations)
- [Manifest Generation API](#manifest-generation-api)
- [Code Examples](#code-examples)
  - [Basic Usage](#basic-usage)
  - [Network Packet Filter](#network-packet-filter)
  - [Timer Hook](#timer-hook)
  - [Map Access](#map-access)
  - [Deferred Execution](#deferred-execution)

---

## Overview

microBPF is a sandboxed, event-driven programmability system for constrained kernels. It uses MQuickJS as its JavaScript execution engine and provides:

- Safe execution with bounded CPU and memory usage
- Multiple hook types (network, tracepoint, timer, security, custom)
- Persistent key/value maps for state management
- Optional Ed25519 package signing

### Header Files

```c
#include "mbpf.h"              // Core runtime API
#include "mbpf_package.h"      // Package parsing and assembly
#include "mbpf_manifest_gen.h" // Manifest generation (optional, for tooling)
```

### Linking

Link against `libmbpf.a` and ensure MQuickJS is available.

---

## Version Information

### Macros

```c
#define MBPF_VERSION_MAJOR 0
#define MBPF_VERSION_MINOR 1
#define MBPF_VERSION_PATCH 0

#define MBPF_API_VERSION ((MBPF_VERSION_MAJOR << 16) | MBPF_VERSION_MINOR)
```

### Functions

#### mbpf_version_string

```c
const char *mbpf_version_string(void);
```

Returns a human-readable version string (e.g., "0.1.0").

#### mbpf_api_version

```c
uint32_t mbpf_api_version(void);
```

Returns the API version as `(major << 16) | minor`.

#### mbpf_runtime_word_size

```c
uint8_t mbpf_runtime_word_size(void);
```

Returns the target word size: 32 or 64.

#### mbpf_runtime_endianness

```c
uint8_t mbpf_runtime_endianness(void);
```

Returns the target endianness: 0 (little) or 1 (big).

---

## Error Codes

All functions return `int` error codes where `MBPF_OK` (0) indicates success.

| Error Code | Value | Description |
|------------|-------|-------------|
| `MBPF_OK` | 0 | Success |
| `MBPF_ERR_INVALID_ARG` | -1 | Invalid argument |
| `MBPF_ERR_NO_MEM` | -2 | Memory allocation failure |
| `MBPF_ERR_INVALID_PACKAGE` | -3 | Invalid package format |
| `MBPF_ERR_INVALID_MAGIC` | -4 | Invalid magic bytes |
| `MBPF_ERR_UNSUPPORTED_VER` | -5 | Unsupported format version |
| `MBPF_ERR_MISSING_SECTION` | -6 | Required section missing |
| `MBPF_ERR_INVALID_BYTECODE` | -7 | Invalid bytecode |
| `MBPF_ERR_HOOK_MISMATCH` | -8 | Hook type mismatch |
| `MBPF_ERR_CAPABILITY_DENIED` | -9 | Capability not granted |
| `MBPF_ERR_BUDGET_EXCEEDED` | -10 | Execution budget exceeded |
| `MBPF_ERR_ALREADY_ATTACHED` | -11 | Program already attached |
| `MBPF_ERR_NOT_ATTACHED` | -12 | Program not attached |
| `MBPF_ERR_NESTED_EXEC` | -13 | Nested execution detected |
| `MBPF_ERR_SIGNATURE` | -14 | Signature verification failed |
| `MBPF_ERR_SECTION_BOUNDS` | -15 | Section bounds invalid |
| `MBPF_ERR_SECTION_OVERLAP` | -16 | Sections overlap |
| `MBPF_ERR_CRC_MISMATCH` | -17 | CRC validation failed |
| `MBPF_ERR_HEAP_TOO_SMALL` | -18 | Heap size below minimum |
| `MBPF_ERR_ALREADY_UNLOADED` | -19 | Program already unloaded |
| `MBPF_ERR_ABI_MISMATCH` | -20 | Context ABI version mismatch |
| `MBPF_ERR_MISSING_ENTRY` | -21 | Entry function missing |
| `MBPF_ERR_INIT_FAILED` | -22 | Initialization failed |
| `MBPF_ERR_MAP_INCOMPATIBLE` | -23 | Map schema incompatible |
| `MBPF_ERR_STILL_ATTACHED` | -24 | Cannot update attached program |
| `MBPF_ERR_API_VERSION` | -25 | API version incompatible |
| `MBPF_ERR_HELPER_VERSION` | -26 | Helper version incompatible |
| `MBPF_ERR_TARGET_MISMATCH` | -27 | Target architecture mismatch |

#### mbpf_error_string

```c
const char *mbpf_error_string(mbpf_error_t err);
```

Returns a human-readable description of an error code.

---

## Types and Structures

### Runtime Configuration

```c
typedef struct mbpf_runtime_config {
    size_t default_heap_size;           // Default heap per program (bytes)
    uint32_t default_max_steps;         // Default step budget
    uint32_t default_max_helpers;       // Default helper call limit
    uint32_t allowed_capabilities;      // Bitmask of allowed capabilities
    bool require_signatures;            // Require signed packages
    bool debug_mode;                    // Enable debug features
    void (*log_fn)(int level, const char *msg);  // Custom log handler
    mbpf_instance_mode_t instance_mode; // Instance creation mode
    uint32_t instance_count;            // Explicit instance count (if mode == COUNT)
    mbpf_exception_default_fn exception_default_fn;  // Custom exception default
    uint32_t circuit_breaker_threshold; // Failures before tripping (0 = disabled)
    uint32_t circuit_breaker_cooldown_us; // Cooldown in microseconds
    bool trace_enabled;                 // Enable trace logging
    uint32_t trace_rate_limit_per_sec;  // Rate limit (0 = unlimited)
} mbpf_runtime_config_t;
```

#### Instance Modes

```c
typedef enum {
    MBPF_INSTANCE_SINGLE = 0,   // Single instance (default)
    MBPF_INSTANCE_PER_CPU = 1,  // Per-CPU instances
    MBPF_INSTANCE_COUNT = 2,    // Explicit instance count
} mbpf_instance_mode_t;
```

### Load Options

```c
typedef struct mbpf_load_opts {
    uint32_t override_capabilities;  // Override manifest capabilities
    size_t override_heap_size;       // Override manifest heap size
    bool allow_unsigned;             // Allow unsigned packages
} mbpf_load_opts_t;
```

### Update Options

```c
typedef struct mbpf_update_opts {
    uint32_t override_capabilities;
    size_t override_heap_size;
    bool allow_unsigned;
    uint32_t map_policy;  // MBPF_MAP_POLICY_PRESERVE or MBPF_MAP_POLICY_DESTROY
} mbpf_update_opts_t;

#define MBPF_MAP_POLICY_PRESERVE  0  // Preserve compatible maps
#define MBPF_MAP_POLICY_DESTROY   1  // Destroy and recreate maps
```

### Statistics

```c
typedef struct mbpf_stats {
    uint64_t invocations;           // Total invocations
    uint64_t successes;             // Successful completions
    uint64_t exceptions;            // JavaScript exceptions
    uint64_t oom_errors;            // Out-of-memory errors
    uint64_t budget_exceeded;       // Budget violations
    uint64_t nested_dropped;        // Dropped due to nested execution
    uint64_t deferred_dropped;      // Dropped due to full queue
    uint64_t circuit_breaker_trips; // Circuit breaker trips
    uint64_t circuit_breaker_skipped; // Skipped due to open circuit
} mbpf_stats_t;
```

### Hook Types

```c
typedef enum {
    MBPF_HOOK_TRACEPOINT = 1,  // Tracepoint/observability hook
    MBPF_HOOK_TIMER      = 2,  // Timer/periodic execution
    MBPF_HOOK_NET_RX     = 3,  // Network receive path
    MBPF_HOOK_NET_TX     = 4,  // Network transmit path
    MBPF_HOOK_SECURITY   = 5,  // Security authorization
    MBPF_HOOK_CUSTOM     = 6,  // Platform-defined custom hook
} mbpf_hook_type_t;

typedef uint32_t mbpf_hook_id_t;
```

#### Return Codes

Network hooks:
```c
#define MBPF_NET_PASS  0   // Allow packet
#define MBPF_NET_DROP  1   // Drop packet
#define MBPF_NET_ABORT 2   // Abort (program error)
```

Security hooks:
```c
#define MBPF_SEC_ALLOW 0   // Allow operation
#define MBPF_SEC_DENY  1   // Deny operation
#define MBPF_SEC_ABORT 2   // Abort (fall through)
```

### Context Structures

All context structures include an `abi_version` field (always 1 for current version).

#### NET_RX Context (v1)

```c
typedef struct mbpf_ctx_net_rx_v1 {
    uint32_t abi_version;    // = 1
    uint32_t ifindex;        // Interface index
    uint32_t pkt_len;        // Full packet length
    uint32_t data_len;       // Available data length
    uint16_t l2_proto;       // Layer 2 protocol
    uint16_t flags;          // Context flags
    const uint8_t *data;     // Packet data pointer
    mbpf_read_bytes_fn read_fn;  // Optional scatter-gather reader
} mbpf_ctx_net_rx_v1_t;
```

#### NET_TX Context (v1)

```c
typedef struct mbpf_ctx_net_tx_v1 {
    uint32_t abi_version;    // = 1
    uint32_t ifindex;
    uint32_t pkt_len;
    uint32_t data_len;
    uint16_t l2_proto;
    uint16_t flags;
    const uint8_t *data;
    mbpf_read_bytes_fn read_fn;
} mbpf_ctx_net_tx_v1_t;
```

#### TRACEPOINT Context (v1)

```c
typedef struct mbpf_ctx_tracepoint_v1 {
    uint32_t abi_version;     // = 1
    uint32_t tracepoint_id;   // Tracepoint identifier
    uint64_t timestamp;       // Event timestamp (ns)
    uint32_t cpu;             // CPU number
    uint32_t pid;             // Process ID
    uint32_t data_len;        // Optional data length
    uint16_t flags;           // Context flags
    uint16_t reserved;
    const uint8_t *data;      // Optional data
    mbpf_read_bytes_fn read_fn;
} mbpf_ctx_tracepoint_v1_t;
```

#### TIMER Context (v1)

```c
typedef struct mbpf_ctx_timer_v1 {
    uint32_t abi_version;       // = 1
    uint32_t timer_id;          // Timer identifier
    uint32_t period_us;         // Period in microseconds
    uint16_t flags;             // Context flags
    uint16_t reserved;
    uint64_t invocation_count;  // Times timer has fired
    uint64_t timestamp;         // Current timestamp (ns)
} mbpf_ctx_timer_v1_t;
```

#### SECURITY Context (v1)

```c
typedef struct mbpf_ctx_security_v1 {
    uint32_t abi_version;   // = 1
    uint32_t subject_id;    // Subject (process, user)
    uint32_t object_id;     // Object (resource)
    uint32_t action;        // Requested action
    uint16_t flags;
    uint16_t reserved;
    uint32_t data_len;
    const uint8_t *data;
    mbpf_read_bytes_fn read_fn;
} mbpf_ctx_security_v1_t;
```

#### CUSTOM Context (v1)

```c
typedef struct mbpf_ctx_custom_v1 {
    uint32_t abi_version;       // = 1
    uint32_t custom_hook_id;    // Platform hook ID
    uint32_t schema_version;    // Schema version
    uint16_t flags;
    uint16_t reserved;
    uint32_t field_count;       // Number of custom fields
    uint32_t data_len;
    const uint8_t *data;
    mbpf_read_bytes_fn read_fn;
    const struct mbpf_custom_field *fields;  // Field descriptors
} mbpf_ctx_custom_v1_t;

typedef struct mbpf_custom_field {
    const char *name;        // Field name
    uint32_t offset;         // Byte offset in data
    uint32_t length;         // Length (for BYTES type)
    mbpf_field_type_t type;  // Field type
} mbpf_custom_field_t;
```

#### Context Flags

```c
#define MBPF_CTX_F_TRUNCATED (1u << 0)  // Data was truncated
```

### Map Types

```c
typedef enum {
    MBPF_MAP_TYPE_ARRAY   = 1,  // Fixed-size array
    MBPF_MAP_TYPE_HASH    = 2,  // Hash table
    MBPF_MAP_TYPE_LRU     = 3,  // LRU hash map
    MBPF_MAP_TYPE_PERCPU  = 4,  // (Reserved)
    MBPF_MAP_TYPE_RING    = 5,  // Ring buffer
    MBPF_MAP_TYPE_COUNTER = 6,  // Atomic counter
    MBPF_MAP_TYPE_PERCPU_ARRAY = 7,  // Per-CPU array
    MBPF_MAP_TYPE_PERCPU_HASH  = 8,  // Per-CPU hash
} mbpf_map_type_t;

#define MBPF_MAP_FLAG_PERCPU (1 << 0)  // Per-CPU variant
```

### Capabilities

Capabilities control which helpers a program can use:

```c
#define MBPF_CAP_LOG          (1 << 0)  // mbpf.log()
#define MBPF_CAP_MAP_READ     (1 << 1)  // Map lookup
#define MBPF_CAP_MAP_WRITE    (1 << 2)  // Map update/delete
#define MBPF_CAP_MAP_ITERATE  (1 << 3)  // Map iteration (nextKey)
#define MBPF_CAP_EMIT         (1 << 4)  // mbpf.emit()
#define MBPF_CAP_TIME         (1 << 5)  // mbpf.nowNs()
#define MBPF_CAP_STATS        (1 << 6)  // mbpf.stats()
```

### Package and Manifest Structures

```c
#define MBPF_MAGIC 0x4D425046
#define MBPF_FORMAT_VERSION 1

#define MBPF_FLAG_SIGNED (1 << 0)
#define MBPF_FLAG_DEBUG  (1 << 1)

typedef enum {
    MBPF_SEC_MANIFEST  = 1,  // Metadata (CBOR or JSON)
    MBPF_SEC_BYTECODE  = 2,  // MQuickJS bytecode
    MBPF_SEC_MAPS      = 3,  // Map definitions (optional)
    MBPF_SEC_DEBUG     = 4,  // Debug symbols (optional)
    MBPF_SEC_SIG       = 5,  // Ed25519 signature
} mbpf_section_type_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;          // MBPF_MAGIC
    uint16_t format_version;
    uint16_t header_size;    // Includes section table
    uint32_t flags;
    uint32_t section_count;
    uint32_t file_crc32;     // Optional, 0 if unused
} mbpf_file_header_t;

typedef struct __attribute__((packed)) {
    uint32_t type;
    uint32_t offset;
    uint32_t length;
    uint32_t crc32;
} mbpf_section_desc_t;

typedef struct {
    char name[32];
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
} mbpf_map_def_t;

typedef struct {
    char name[32];
    uint32_t version;  // major<<16 | minor
} mbpf_helper_version_t;

typedef struct {
    uint32_t max_steps;
    uint32_t max_helpers;
    uint32_t max_wall_time_us;  // Optional, 0 if unused
} mbpf_budgets_t;

typedef struct {
    uint8_t word_size;   // 32 or 64
    uint8_t endianness;  // 0 = little, 1 = big
} mbpf_target_t;

typedef struct {
    char program_name[64];
    char program_version[32];
    uint32_t hook_type;
    uint32_t hook_ctx_abi_version;
    char entry_symbol[64];
    uint32_t mquickjs_bytecode_version;
    mbpf_target_t target;
    uint32_t mbpf_api_version;
    uint32_t heap_size;
    mbpf_budgets_t budgets;
    uint32_t capabilities;
    mbpf_map_def_t *maps;
    uint32_t map_count;
    mbpf_helper_version_t *helper_versions;
    uint32_t helper_version_count;
} mbpf_manifest_t;

#define MBPF_DEBUG_FLAG_HAS_SOURCE_HASH  (1 << 0)
#define MBPF_DEBUG_MAX_SYMBOL_LEN 128

typedef struct {
    uint32_t flags;
    uint8_t source_hash[32];
    char entry_symbol[MBPF_DEBUG_MAX_SYMBOL_LEN];
    char hook_name[MBPF_DEBUG_MAX_SYMBOL_LEN];
    char (*map_names)[MBPF_DEBUG_MAX_SYMBOL_LEN];
    uint32_t map_count;
} mbpf_debug_info_t;

#define MBPF_ED25519_PUBLIC_KEY_SIZE 32
#define MBPF_ED25519_SIGNATURE_SIZE  64

typedef struct __attribute__((packed)) {
    uint8_t signature[64];
} mbpf_signature_section_t;

typedef struct {
    const uint8_t *public_key;  // 32-byte Ed25519 public key
    int allow_unsigned;
    int production_mode;
} mbpf_sig_verify_opts_t;

typedef struct {
    uint16_t bytecode_version;  // Version from JSBytecodeHeader
    int is_valid;
    int relocation_result;
} mbpf_bytecode_info_t;

#define MBPF_MAX_SECTIONS 8

typedef struct {
    mbpf_section_type_t type;
    const void *data;
    size_t len;
} mbpf_section_input_t;

typedef struct {
    int compute_file_crc;
    int compute_section_crcs;
    uint32_t flags;  // MBPF_FLAG_SIGNED, MBPF_FLAG_DEBUG
} mbpf_assemble_opts_t;
```

---

## Core API Functions

### Runtime Lifecycle

#### mbpf_runtime_init

```c
mbpf_runtime_t *mbpf_runtime_init(const mbpf_runtime_config_t *cfg);
```

Initializes a new microBPF runtime.

**Parameters:**
- `cfg`: Configuration structure (may be NULL for defaults)

**Returns:**
- Pointer to runtime on success
- NULL on failure

**Example:**
```c
mbpf_runtime_config_t cfg = {
    .default_heap_size = 16384,
    .default_max_steps = 10000,
    .default_max_helpers = 100,
    .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    .debug_mode = true,
};

mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
if (!rt) {
    fprintf(stderr, "Failed to initialize runtime\n");
    return -1;
}
```

#### mbpf_runtime_shutdown

```c
void mbpf_runtime_shutdown(mbpf_runtime_t *rt);
```

Shuts down the runtime and frees all resources. All loaded programs are unloaded.

**Parameters:**
- `rt`: Runtime to shut down (may be NULL, which is a no-op)

### Program Lifecycle

#### mbpf_program_load

```c
int mbpf_program_load(mbpf_runtime_t *rt, const void *pkg, size_t pkg_len,
                      const mbpf_load_opts_t *opts, mbpf_program_t **out_prog);
```

Loads a program from a .mbpf package.

**Parameters:**
- `rt`: Runtime instance
- `pkg`: Package data
- `pkg_len`: Package length in bytes
- `opts`: Load options (may be NULL)
- `out_prog`: Receives pointer to loaded program

**Returns:**
- `MBPF_OK` on success
- Error code on failure

**Example:**
```c
mbpf_program_t *prog;
int err = mbpf_program_load(rt, package_data, package_len, NULL, &prog);
if (err != MBPF_OK) {
    fprintf(stderr, "Load failed: %s\n", mbpf_error_string(err));
    return err;
}
```

#### mbpf_program_unload

```c
int mbpf_program_unload(mbpf_runtime_t *rt, mbpf_program_t *prog);
```

Unloads a program and frees its resources. Calls `mbpf_fini()` if defined.

**Parameters:**
- `rt`: Runtime instance
- `prog`: Program to unload

**Returns:**
- `MBPF_OK` on success
- Error code on failure

#### mbpf_program_update

```c
int mbpf_program_update(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        const void *pkg, size_t pkg_len,
                        const mbpf_update_opts_t *opts);
```

Updates a program to a new version (hot swap). The program must be detached first.

**Parameters:**
- `rt`: Runtime instance
- `prog`: Program to update
- `pkg`: New package data
- `pkg_len`: New package length
- `opts`: Update options (may be NULL)

**Returns:**
- `MBPF_OK` on success
- `MBPF_ERR_STILL_ATTACHED` if program is attached
- `MBPF_ERR_MAP_INCOMPATIBLE` if maps cannot be preserved

#### mbpf_program_attach

```c
int mbpf_program_attach(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        mbpf_hook_id_t hook);
```

Attaches a program to a hook point.

**Parameters:**
- `rt`: Runtime instance
- `prog`: Program to attach
- `hook`: Hook identifier

**Returns:**
- `MBPF_OK` on success
- `MBPF_ERR_HOOK_MISMATCH` if hook type doesn't match program
- `MBPF_ERR_ABI_MISMATCH` if context ABI version is incompatible
- `MBPF_ERR_ALREADY_ATTACHED` if already attached

#### mbpf_program_detach

```c
int mbpf_program_detach(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        mbpf_hook_id_t hook);
```

Detaches a program from a hook point.

**Parameters:**
- `rt`: Runtime instance
- `prog`: Program to detach
- `hook`: Hook identifier

**Returns:**
- `MBPF_OK` on success
- `MBPF_ERR_NOT_ATTACHED` if not attached

### Program Execution

#### mbpf_run

```c
int mbpf_run(mbpf_runtime_t *rt, mbpf_hook_id_t hook,
             const void *ctx_blob, size_t ctx_len,
             int32_t *out_rc);
```

Executes all programs attached to a hook.

**Parameters:**
- `rt`: Runtime instance
- `hook`: Hook identifier
- `ctx_blob`: Context structure (type depends on hook type)
- `ctx_len`: Context size in bytes
- `out_rc`: Receives the program's return code

**Returns:**
- `MBPF_OK` on success
- `MBPF_ERR_BUDGET_EXCEEDED` if budget was exceeded (default returned)
- `MBPF_ERR_NESTED_EXEC` if already executing on this instance

**Example:**
```c
mbpf_ctx_net_rx_v1_t ctx = {
    .abi_version = 1,
    .ifindex = 1,
    .pkt_len = packet_len,
    .data_len = packet_len,
    .l2_proto = 0x0800,  // IPv4
    .data = packet_data,
};

int32_t action;
int err = mbpf_run(rt, hook_id, &ctx, sizeof(ctx), &action);
if (err == MBPF_OK && action == MBPF_NET_DROP) {
    // Drop the packet
}
```

### Program Information

#### mbpf_program_stats

```c
int mbpf_program_stats(mbpf_program_t *prog, mbpf_stats_t *out_stats);
```

Gets execution statistics for a program.

#### mbpf_program_instance_count

```c
uint32_t mbpf_program_instance_count(mbpf_program_t *prog);
```

Returns the number of instances for a program.

#### mbpf_program_instance_heap_size

```c
size_t mbpf_program_instance_heap_size(mbpf_program_t *prog, uint32_t idx);
```

Returns the heap size of a specific instance.

#### mbpf_program_get_instance

```c
mbpf_instance_t *mbpf_program_get_instance(mbpf_program_t *prog, uint32_t idx);
```

Gets a specific instance by index.

#### mbpf_program_circuit_open

```c
bool mbpf_program_circuit_open(mbpf_program_t *prog);
```

Checks if the program's circuit breaker is open (disabled).

#### mbpf_program_circuit_reset

```c
int mbpf_program_circuit_reset(mbpf_program_t *prog);
```

Manually resets the circuit breaker.

#### mbpf_hook_abi_version

```c
uint32_t mbpf_hook_abi_version(mbpf_hook_type_t hook_type);
```

Returns the current ABI version for a hook type.

#### mbpf_hook_exception_default

```c
int32_t mbpf_hook_exception_default(mbpf_hook_type_t hook_type);
```

Returns the default return value when a program throws an exception.

---

## Map Access API

### Lock-Free Map Reads

These functions provide lock-free reads using a seqlock pattern.

#### mbpf_program_find_map

```c
int mbpf_program_find_map(mbpf_program_t *prog, const char *name);
```

Finds a map by name.

**Returns:** Map index (0-based) or -1 if not found.

#### mbpf_map_get_type

```c
int mbpf_map_get_type(mbpf_program_t *prog, int map_idx);
```

Gets the type of a map.

**Returns:** Map type or -1 on error.

#### mbpf_array_map_lookup_lockfree

```c
int mbpf_array_map_lookup_lockfree(mbpf_program_t *prog, int map_idx,
                                    uint32_t index, void *out_value, size_t max_len);
```

Lock-free array map lookup.

**Returns:**
- 1: Entry found
- 0: Entry not found
- -1: Error

#### mbpf_hash_map_lookup_lockfree

```c
int mbpf_hash_map_lookup_lockfree(mbpf_program_t *prog, int map_idx,
                                   const void *key, size_t key_len,
                                   void *out_value, size_t max_len);
```

Lock-free hash map lookup.

#### mbpf_lru_map_lookup_lockfree

```c
int mbpf_lru_map_lookup_lockfree(mbpf_program_t *prog, int map_idx,
                                  const void *key, size_t key_len,
                                  void *out_value, size_t max_len);
```

Lock-free LRU map lookup. Note: Does not update LRU order.

### Locked Map Updates

#### mbpf_array_map_update_locked

```c
int mbpf_array_map_update_locked(mbpf_program_t *prog, int map_idx,
                                  uint32_t index, const void *value, size_t value_len);
```

Update an array map entry with seqlock protection.

#### mbpf_hash_map_update_locked

```c
int mbpf_hash_map_update_locked(mbpf_program_t *prog, int map_idx,
                                 const void *key, size_t key_len,
                                 const void *value, size_t value_len);
```

Update a hash map entry with seqlock protection.

#### mbpf_hash_map_delete_locked

```c
int mbpf_hash_map_delete_locked(mbpf_program_t *prog, int map_idx,
                                 const void *key, size_t key_len);
```

Delete a hash map entry with seqlock protection.

**Returns:** 0 (deleted), 1 (not found), -1 (error).

---

## Ring Buffer API

#### mbpf_program_find_ring_map

```c
int mbpf_program_find_ring_map(mbpf_program_t *prog, const char *name);
```

Finds a ring buffer map by name.

#### mbpf_ring_read

```c
int mbpf_ring_read(mbpf_program_t *prog, int map_idx,
                   void *out_data, size_t max_len);
```

Reads and consumes the next event from a ring buffer.

**Returns:** Event length, 0 if empty, -1 on error.

#### mbpf_ring_peek

```c
int mbpf_ring_peek(mbpf_program_t *prog, int map_idx,
                   void *out_data, size_t max_len);
```

Peeks at the next event without consuming it.

#### mbpf_ring_count

```c
int mbpf_ring_count(mbpf_program_t *prog, int map_idx);
```

Returns the number of events in the ring buffer.

#### mbpf_ring_dropped

```c
int mbpf_ring_dropped(mbpf_program_t *prog, int map_idx);
```

Returns the number of dropped events due to overflow.

---

## Event Emit API

Programs with `CAP_EMIT` can emit events using `mbpf.emit()`.

#### mbpf_emit_read

```c
int mbpf_emit_read(mbpf_program_t *prog, uint32_t *out_event_id,
                   void *out_data, size_t max_len);
```

Reads and consumes the next emitted event.

**Parameters:**
- `out_event_id`: Receives the event ID (may be NULL)
- `out_data`: Buffer for event data
- `max_len`: Buffer size

**Returns:** Data length, 0 if empty, -1 on error.

#### mbpf_emit_peek

```c
int mbpf_emit_peek(mbpf_program_t *prog, uint32_t *out_event_id,
                   void *out_data, size_t max_len);
```

Peeks at the next event without consuming.

#### mbpf_emit_count

```c
int mbpf_emit_count(mbpf_program_t *prog);
```

Returns the number of pending events.

#### mbpf_emit_dropped

```c
int mbpf_emit_dropped(mbpf_program_t *prog);
```

Returns the number of dropped events.

---

## Deferred Execution API

Observer hooks (TRACEPOINT, TIMER) can run in deferred mode.

### Configuration

```c
typedef struct mbpf_deferred_config {
    uint32_t max_entries;           // Maximum queue depth
    uint32_t max_snapshot_bytes;    // Max bytes to snapshot per invocation
} mbpf_deferred_config_t;
```

### Functions

#### mbpf_deferred_queue_create

```c
mbpf_deferred_queue_t *mbpf_deferred_queue_create(const mbpf_deferred_config_t *cfg);
```

Creates a deferred execution queue.

#### mbpf_deferred_queue_destroy

```c
void mbpf_deferred_queue_destroy(mbpf_deferred_queue_t *queue);
```

Destroys a deferred queue.

#### mbpf_queue_invocation

```c
int mbpf_queue_invocation(mbpf_deferred_queue_t *queue,
                          mbpf_runtime_t *rt,
                          mbpf_hook_id_t hook,
                          mbpf_hook_type_t hook_type,
                          const void *ctx_blob, size_t ctx_len);
```

Queues an invocation for deferred execution.

**Returns:**
- `MBPF_OK`: Queued
- `MBPF_ERR_NO_MEM`: Queue full (dropped)
- `MBPF_ERR_INVALID_ARG`: Invalid hook type

#### mbpf_drain_deferred

```c
int mbpf_drain_deferred(mbpf_deferred_queue_t *queue);
```

Executes all pending invocations.

**Returns:** Number executed, or -1 on error.

#### mbpf_deferred_pending

```c
uint32_t mbpf_deferred_pending(const mbpf_deferred_queue_t *queue);
```

Returns the number of pending invocations.

#### mbpf_deferred_dropped

```c
uint64_t mbpf_deferred_dropped(const mbpf_deferred_queue_t *queue);
```

Returns the number of dropped invocations.

#### mbpf_hook_can_defer

```c
bool mbpf_hook_can_defer(mbpf_hook_type_t hook_type);
```

Checks if a hook type supports deferred execution.

---

## Debug Info API

#### mbpf_program_has_debug_info

```c
bool mbpf_program_has_debug_info(mbpf_program_t *prog);
```

Checks if debug info is available.

#### mbpf_program_debug_entry_symbol

```c
const char *mbpf_program_debug_entry_symbol(mbpf_program_t *prog);
```

Returns the entry symbol name.

#### mbpf_program_debug_hook_name

```c
const char *mbpf_program_debug_hook_name(mbpf_program_t *prog);
```

Returns the hook name.

#### mbpf_program_debug_source_hash

```c
int mbpf_program_debug_source_hash(mbpf_program_t *prog, uint8_t out_hash[32]);
```

Gets the source hash for provenance tracking.

#### mbpf_program_debug_map_count

```c
uint32_t mbpf_program_debug_map_count(mbpf_program_t *prog);
```

Returns the number of map names in debug info.

#### mbpf_program_debug_map_name

```c
const char *mbpf_program_debug_map_name(mbpf_program_t *prog, uint32_t index);
```

Gets a map name by index.

---

## Package API

### Package Parsing

#### mbpf_package_parse_header

```c
int mbpf_package_parse_header(const void *data, size_t len,
                               mbpf_file_header_t *out_header);
```

Parses the file header.

#### mbpf_package_parse_section_table

```c
int mbpf_package_parse_section_table(const void *data, size_t len,
                                      mbpf_section_desc_t *out_sections,
                                      uint32_t max_sections,
                                      uint32_t *out_count);
```

Parses the section table.

#### mbpf_package_get_section

```c
int mbpf_package_get_section(const void *data, size_t len,
                              mbpf_section_type_t type,
                              const void **out_data, size_t *out_len);
```

Gets a specific section by type.

#### mbpf_package_parse_manifest

```c
int mbpf_package_parse_manifest(const void *manifest_data, size_t len,
                                 mbpf_manifest_t *out_manifest);
```

Parses a manifest section.

#### mbpf_manifest_free

```c
void mbpf_manifest_free(mbpf_manifest_t *manifest);
```

Frees manifest resources.

### CRC Validation

#### mbpf_crc32

```c
uint32_t mbpf_crc32(const void *data, size_t len);
```

Computes CRC32 checksum.

#### mbpf_package_validate_crc

```c
int mbpf_package_validate_crc(const void *data, size_t len);
```

Validates the file-level CRC.

#### mbpf_package_validate_section_crc

```c
int mbpf_package_validate_section_crc(const void *data, size_t len,
                                       const mbpf_section_desc_t *section);
```

Validates a section's CRC.

### Debug Section Parsing

#### mbpf_debug_info_parse

```c
int mbpf_debug_info_parse(const void *debug_data, size_t debug_len,
                          mbpf_debug_info_t *out_debug);
```

Parses a DEBUG section.

**Parameters:**
- `debug_data`: Pointer to DEBUG section data
- `debug_len`: Length of DEBUG section
- `out_debug`: Receives parsed debug info

**Returns:**
- `MBPF_OK` on success
- `MBPF_ERR_INVALID_ARG` if arguments are NULL
- `MBPF_ERR_INVALID_PACKAGE` if section format is invalid

Caller must call `mbpf_debug_info_free()` to release allocated memory.

#### mbpf_debug_info_free

```c
void mbpf_debug_info_free(mbpf_debug_info_t *debug);
```

Frees memory allocated by `mbpf_debug_info_parse()`. Safe to call with zeroed structure.

#### mbpf_package_has_debug

```c
int mbpf_package_has_debug(const void *data, size_t len, int *out_has_debug);
```

Checks if a package has a DEBUG section.

**Parameters:**
- `data`: Package data
- `len`: Package length
- `out_has_debug`: Receives 1 if has debug section, 0 otherwise

#### mbpf_package_get_debug_info

```c
int mbpf_package_get_debug_info(const void *data, size_t len,
                                 mbpf_debug_info_t *out_debug);
```

Gets debug info from a package (convenience wrapper).

**Returns:**
- `MBPF_OK` on success
- `MBPF_ERR_MISSING_SECTION` if no DEBUG section

### Package Assembly

#### mbpf_package_size

```c
size_t mbpf_package_size(const mbpf_section_input_t *sections,
                          uint32_t section_count);
```

Calculates the assembled package size.

#### mbpf_package_assemble

```c
int mbpf_package_assemble(const mbpf_section_input_t *sections,
                           uint32_t section_count,
                           const mbpf_assemble_opts_t *opts,
                           uint8_t *out_data, size_t *out_len);
```

Assembles a package from sections.

### Signature Verification

#### mbpf_package_verify_signature

```c
int mbpf_package_verify_signature(const void *data, size_t len,
                                   const mbpf_sig_verify_opts_t *opts);
```

Verifies the package signature.

#### mbpf_package_is_signed

```c
int mbpf_package_is_signed(const void *data, size_t len, int *out_signed);
```

Checks if a package has a signature section.

#### mbpf_package_get_signature

```c
int mbpf_package_get_signature(const void *data, size_t len,
                                const uint8_t **out_sig,
                                size_t *out_data_len);
```

Gets the signature bytes.

### Bytecode Operations

#### mbpf_bytecode_load

```c
int mbpf_bytecode_load(struct JSContext *ctx,
                       uint8_t *bytecode, size_t bytecode_len,
                       mbpf_bytecode_info_t *out_info,
                       void *out_main_func);
```

Loads bytecode into a JS context.

#### mbpf_bytecode_check

```c
int mbpf_bytecode_check(const uint8_t *bytecode, size_t bytecode_len,
                        mbpf_bytecode_info_t *out_info);
```

Validates bytecode without loading.

#### mbpf_bytecode_version

```c
uint16_t mbpf_bytecode_version(void);
```

Returns the expected bytecode version.

---

## Manifest Generation API

#### mbpf_manifest_generate_cbor

```c
int mbpf_manifest_generate_cbor(const mbpf_manifest_t *manifest,
                                 uint8_t *out_data, size_t *out_len);
```

Generates CBOR-encoded manifest.

#### mbpf_manifest_generate_json

```c
int mbpf_manifest_generate_json(const mbpf_manifest_t *manifest,
                                 char *out_data, size_t *out_len);
```

Generates JSON-encoded manifest.

#### mbpf_manifest_cbor_size

```c
size_t mbpf_manifest_cbor_size(const mbpf_manifest_t *manifest);
```

Calculates required CBOR buffer size.

#### mbpf_manifest_json_size

```c
size_t mbpf_manifest_json_size(const mbpf_manifest_t *manifest);
```

Calculates required JSON buffer size.

#### mbpf_manifest_validate

```c
int mbpf_manifest_validate(const mbpf_manifest_t *manifest);
```

Validates a manifest has all required fields.

#### mbpf_manifest_init_defaults

```c
void mbpf_manifest_init_defaults(mbpf_manifest_t *manifest);
```

Initializes a manifest with default values.

---

## Code Examples

### Basic Usage

```c
#include "mbpf.h"
#include <stdio.h>

int main(void) {
    // Initialize runtime with configuration
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 16384,
        .default_max_steps = 10000,
        .default_max_helpers = 100,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .debug_mode = true,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    if (!rt) {
        fprintf(stderr, "Failed to initialize runtime\n");
        return 1;
    }

    // Load program from .mbpf package
    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, package_data, package_len, NULL, &prog);
    if (err != MBPF_OK) {
        fprintf(stderr, "Load failed: %s\n", mbpf_error_string(err));
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    // Attach to hook
    mbpf_hook_id_t hook = 1;  // Platform-defined hook ID
    err = mbpf_program_attach(rt, prog, hook);
    if (err != MBPF_OK) {
        fprintf(stderr, "Attach failed: %s\n", mbpf_error_string(err));
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    // ... program runs when hook fires ...

    // Cleanup
    mbpf_program_detach(rt, prog, hook);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}
```

### Network Packet Filter

```c
#include "mbpf.h"

// Called from network stack
int filter_packet(mbpf_runtime_t *rt, mbpf_hook_id_t hook,
                  const uint8_t *pkt, size_t len, uint32_t ifindex) {
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = ifindex,
        .pkt_len = (uint32_t)len,
        .data_len = (uint32_t)len,
        .l2_proto = 0x0800,  // IPv4
        .flags = 0,
        .data = pkt,
        .read_fn = NULL,  // Direct data access
    };

    int32_t action;
    int err = mbpf_run(rt, hook, &ctx, sizeof(ctx), &action);

    if (err != MBPF_OK) {
        // On error, default to passing the packet
        return MBPF_NET_PASS;
    }

    return action;  // MBPF_NET_PASS, MBPF_NET_DROP, or MBPF_NET_ABORT
}
```

### Timer Hook

```c
#include "mbpf.h"
#include <time.h>

static uint64_t invocation_count = 0;

void timer_callback(mbpf_runtime_t *rt, mbpf_hook_id_t hook,
                    uint32_t timer_id, uint32_t period_us) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = timer_id,
        .period_us = period_us,
        .flags = 0,
        .invocation_count = ++invocation_count,
        .timestamp = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec,
    };

    int32_t rc;
    mbpf_run(rt, hook, &ctx, sizeof(ctx), &rc);
}
```

### Map Access

```c
#include "mbpf.h"
#include <string.h>

void access_program_maps(mbpf_program_t *prog) {
    // Find a hash map by name
    int map_idx = mbpf_program_find_map(prog, "counters");
    if (map_idx < 0) {
        fprintf(stderr, "Map 'counters' not found\n");
        return;
    }

    // Verify it's a hash map
    int map_type = mbpf_map_get_type(prog, map_idx);
    if (map_type != MBPF_MAP_TYPE_HASH) {
        fprintf(stderr, "Expected hash map\n");
        return;
    }

    // Lock-free lookup
    uint8_t key[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint32_t value;

    int found = mbpf_hash_map_lookup_lockfree(prog, map_idx,
                                               key, sizeof(key),
                                               &value, sizeof(value));
    if (found == 1) {
        printf("Value: %u\n", value);
    } else if (found == 0) {
        printf("Key not found\n");
    } else {
        fprintf(stderr, "Lookup error\n");
    }

    // Locked update
    value = 42;
    int err = mbpf_hash_map_update_locked(prog, map_idx,
                                           key, sizeof(key),
                                           &value, sizeof(value));
    if (err == 0) {
        printf("Value updated\n");
    }
}
```

### Deferred Execution

```c
#include "mbpf.h"
#include <pthread.h>

static mbpf_deferred_queue_t *g_queue;
static pthread_t g_worker;
static volatile int g_running = 1;

void *worker_thread(void *arg) {
    while (g_running) {
        int count = mbpf_drain_deferred(g_queue);
        if (count == 0) {
            // Sleep briefly if nothing to do
            usleep(1000);
        }
    }
    return NULL;
}

int setup_deferred_execution(void) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 256,
        .max_snapshot_bytes = 1024,
    };

    g_queue = mbpf_deferred_queue_create(&cfg);
    if (!g_queue) {
        return -1;
    }

    pthread_create(&g_worker, NULL, worker_thread, NULL);
    return 0;
}

// Called from interrupt context
void tracepoint_handler(mbpf_runtime_t *rt, mbpf_hook_id_t hook,
                        const mbpf_ctx_tracepoint_v1_t *ctx) {
    // Queue for deferred execution instead of running immediately
    int err = mbpf_queue_invocation(g_queue, rt, hook,
                                    MBPF_HOOK_TRACEPOINT,
                                    ctx, sizeof(*ctx));
    if (err == MBPF_ERR_NO_MEM) {
        // Queue full, invocation dropped
        // Counter already incremented internally
    }
}

void cleanup_deferred_execution(void) {
    g_running = 0;
    pthread_join(g_worker, NULL);

    printf("Dropped invocations: %lu\n",
           (unsigned long)mbpf_deferred_dropped(g_queue));

    mbpf_deferred_queue_destroy(g_queue);
}
```

---

## Platform Minimum Requirements

| Requirement | Value | Notes |
|-------------|-------|-------|
| Minimum heap size | 8192 bytes | Per MBPF_MIN_HEAP_SIZE |
| Word size | 32 or 64 bit | Must match bytecode |
| Endianness | Little or Big | Must match bytecode |

---

## Thread Safety

- `mbpf_runtime_t` is not thread-safe for configuration changes
- `mbpf_run()` is safe to call from multiple threads if using per-CPU instances
- Lock-free map reads are safe for concurrent access
- Locked map updates serialize with concurrent reads
- Deferred queue operations are thread-safe

---

## Memory Management

- Programs allocate from a fixed-size heap (no dynamic allocation from host)
- Maps have bounded maximum entries
- Ring buffers drop oldest events on overflow
- Context snapshots are bounded by `max_snapshot_bytes`

---

## See Also

- [SPEC.md](../SPEC.md) - Full technical specification
- [mbpf.h](../include/mbpf.h) - Core API header
- [mbpf_package.h](../include/mbpf_package.h) - Package format header
- [mbpf_manifest_gen.h](../include/mbpf_manifest_gen.h) - Manifest generation header
