/*
 * microBPF - Sandboxed in-kernel programmability for constrained kernels
 *
 * Copyright (c) 2024 microBPF Authors
 * Released under MIT License
 */

#ifndef MBPF_H
#define MBPF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version info */
#define MBPF_VERSION_MAJOR 0
#define MBPF_VERSION_MINOR 1
#define MBPF_VERSION_PATCH 0

#define MBPF_API_VERSION ((MBPF_VERSION_MAJOR << 16) | MBPF_VERSION_MINOR)

/*
 * Platform minimum heap size: 8192 bytes (8KB)
 *
 * This minimum is required because MQuickJS needs sufficient space for:
 * - Standard library initialization
 * - Basic JS heap operations and object allocation
 * - Runtime context objects
 * - Program bytecode loading
 *
 * Programs with heap_size < MBPF_MIN_HEAP_SIZE will fail to load
 * with error code MBPF_ERR_HEAP_TOO_SMALL (-18).
 */
#define MBPF_MIN_HEAP_SIZE 8192

/* Forward declarations */
typedef struct mbpf_runtime mbpf_runtime_t;
typedef struct mbpf_program mbpf_program_t;
typedef struct mbpf_instance mbpf_instance_t;

/* Hook types */
typedef enum {
    MBPF_HOOK_TRACEPOINT = 1,
    MBPF_HOOK_TIMER      = 2,
    MBPF_HOOK_NET_RX     = 3,
    MBPF_HOOK_NET_TX     = 4,
    MBPF_HOOK_SECURITY   = 5,
    MBPF_HOOK_CUSTOM     = 6,
} mbpf_hook_type_t;

typedef uint32_t mbpf_hook_id_t;

/* Return codes for network hooks */
#define MBPF_NET_PASS  0
#define MBPF_NET_DROP  1
#define MBPF_NET_ABORT 2

/* Return codes for security hooks */
#define MBPF_SEC_ALLOW 0   /* Allow the operation */
#define MBPF_SEC_DENY  1   /* Deny the operation */
#define MBPF_SEC_ABORT 2   /* Abort (program error, fall through to default) */

/* Map types */
typedef enum {
    MBPF_MAP_TYPE_ARRAY   = 1,
    MBPF_MAP_TYPE_HASH    = 2,
    MBPF_MAP_TYPE_LRU     = 3,
    MBPF_MAP_TYPE_PERCPU  = 4,  /* Reserved for backward compatibility */
    MBPF_MAP_TYPE_RING    = 5,
    MBPF_MAP_TYPE_COUNTER = 6,
    MBPF_MAP_TYPE_PERCPU_ARRAY = 7,  /* Per-CPU array map */
    MBPF_MAP_TYPE_PERCPU_HASH  = 8,  /* Per-CPU hash map */
} mbpf_map_type_t;

/* Map flags */
#define MBPF_MAP_FLAG_PERCPU  (1 << 0)  /* Per-CPU variant of map type */

/* Error codes */
typedef enum {
    MBPF_OK                     = 0,
    MBPF_ERR_INVALID_ARG        = -1,
    MBPF_ERR_NO_MEM             = -2,
    MBPF_ERR_INVALID_PACKAGE    = -3,
    MBPF_ERR_INVALID_MAGIC      = -4,
    MBPF_ERR_UNSUPPORTED_VER    = -5,
    MBPF_ERR_MISSING_SECTION    = -6,
    MBPF_ERR_INVALID_BYTECODE   = -7,
    MBPF_ERR_HOOK_MISMATCH      = -8,
    MBPF_ERR_CAPABILITY_DENIED  = -9,
    MBPF_ERR_BUDGET_EXCEEDED    = -10,
    MBPF_ERR_ALREADY_ATTACHED   = -11,
    MBPF_ERR_NOT_ATTACHED       = -12,
    MBPF_ERR_NESTED_EXEC        = -13,
    MBPF_ERR_SIGNATURE          = -14,
    MBPF_ERR_SECTION_BOUNDS     = -15,
    MBPF_ERR_SECTION_OVERLAP    = -16,
    MBPF_ERR_CRC_MISMATCH       = -17,
    MBPF_ERR_HEAP_TOO_SMALL     = -18,
    MBPF_ERR_ALREADY_UNLOADED   = -19,
    MBPF_ERR_ABI_MISMATCH       = -20,
    MBPF_ERR_MISSING_ENTRY      = -21,
    MBPF_ERR_INIT_FAILED        = -22,
    MBPF_ERR_MAP_INCOMPATIBLE   = -23,  /* Map schema changed and policy requires preservation */
    MBPF_ERR_STILL_ATTACHED     = -24,  /* Program still attached, cannot update */
    MBPF_ERR_API_VERSION        = -25,  /* Helper API version incompatible */
} mbpf_error_t;

/* Capabilities */
#define MBPF_CAP_LOG          (1 << 0)
#define MBPF_CAP_MAP_READ     (1 << 1)
#define MBPF_CAP_MAP_WRITE    (1 << 2)
#define MBPF_CAP_MAP_ITERATE  (1 << 3)
#define MBPF_CAP_EMIT         (1 << 4)
#define MBPF_CAP_TIME         (1 << 5)
#define MBPF_CAP_STATS        (1 << 6)

/* Instance mode */
typedef enum {
    MBPF_INSTANCE_SINGLE = 0,   /* Single instance (default) */
    MBPF_INSTANCE_PER_CPU = 1,  /* Per-CPU instances */
    MBPF_INSTANCE_COUNT = 2,    /* Use explicit instance_count */
} mbpf_instance_mode_t;

/*
 * Exception default callback type.
 * Returns the default return code when a program throws an exception.
 * If NULL, built-in defaults are used:
 *   - NET_RX, NET_TX: MBPF_NET_PASS (0)
 *   - SECURITY: MBPF_SEC_DENY (1)
 *   - Others: 0
 */
typedef int32_t (*mbpf_exception_default_fn)(mbpf_hook_type_t hook_type);

/* Runtime configuration */
typedef struct mbpf_runtime_config {
    size_t default_heap_size;
    uint32_t default_max_steps;
    uint32_t default_max_helpers;
    uint32_t allowed_capabilities;
    bool require_signatures;
    bool debug_mode;
    void (*log_fn)(int level, const char *msg);
    mbpf_instance_mode_t instance_mode;
    uint32_t instance_count;    /* Used when instance_mode == MBPF_INSTANCE_COUNT */
    mbpf_exception_default_fn exception_default_fn; /* Optional per-hook default */
    /* Circuit breaker configuration (optional, 0 = disabled) */
    uint32_t circuit_breaker_threshold;   /* Consecutive failures before tripping (0 = disabled) */
    uint32_t circuit_breaker_cooldown_us; /* Cooldown period in microseconds before retry */
} mbpf_runtime_config_t;

/* Load options */
typedef struct mbpf_load_opts {
    uint32_t override_capabilities;
    size_t override_heap_size;
    bool allow_unsigned;
} mbpf_load_opts_t;

/* Map policy flags for program updates */
#define MBPF_MAP_POLICY_PRESERVE   0  /* Preserve maps if compatible (default) */
#define MBPF_MAP_POLICY_DESTROY    1  /* Always destroy maps on update */

/* Update options for hot swap */
typedef struct mbpf_update_opts {
    uint32_t override_capabilities;
    size_t override_heap_size;
    bool allow_unsigned;
    uint32_t map_policy;  /* MBPF_MAP_POLICY_* */
} mbpf_update_opts_t;

/* Per-program statistics */
typedef struct mbpf_stats {
    uint64_t invocations;
    uint64_t successes;
    uint64_t exceptions;
    uint64_t oom_errors;
    uint64_t budget_exceeded;
    uint64_t nested_dropped;
    uint64_t circuit_breaker_trips;   /* Times circuit breaker was tripped */
    uint64_t circuit_breaker_skipped; /* Invocations skipped due to open circuit */
} mbpf_stats_t;

/* Context flags */
#define MBPF_CTX_F_TRUNCATED (1u << 0)

/* Read bytes function type for scatter-gather contexts */
typedef int (*mbpf_read_bytes_fn)(const void *ctx_blob,
                                  uint32_t off, uint32_t len, uint8_t *dst);

/* NET_RX context (v1) */
typedef struct mbpf_ctx_net_rx_v1 {
    uint32_t abi_version;   /* = 1 */
    uint32_t ifindex;
    uint32_t pkt_len;
    uint32_t data_len;
    uint16_t l2_proto;
    uint16_t flags;
    const uint8_t *data;
    mbpf_read_bytes_fn read_fn;
} mbpf_ctx_net_rx_v1_t;

/* TRACEPOINT context (v1) */
typedef struct mbpf_ctx_tracepoint_v1 {
    uint32_t abi_version;   /* = 1 */
    uint32_t tracepoint_id; /* Tracepoint identifier */
    uint64_t timestamp;     /* Event timestamp (ns since boot or epoch) */
    uint32_t cpu;           /* CPU on which event occurred */
    uint32_t pid;           /* Process ID (0 if not applicable) */
    uint32_t data_len;      /* Length of optional data */
    uint16_t flags;         /* Context flags */
    uint16_t reserved;      /* Padding for alignment */
    const uint8_t *data;    /* Optional event-specific data */
    mbpf_read_bytes_fn read_fn; /* Optional scatter-gather reader */
} mbpf_ctx_tracepoint_v1_t;

/* TIMER context (v1) */
typedef struct mbpf_ctx_timer_v1 {
    uint32_t abi_version;       /* = 1 */
    uint32_t timer_id;          /* Timer identifier */
    uint32_t period_us;         /* Timer period in microseconds */
    uint16_t flags;             /* Context flags */
    uint16_t reserved;          /* Padding for alignment */
    uint64_t invocation_count;  /* Number of times timer has fired */
    uint64_t timestamp;         /* Current timestamp (ns since boot or epoch) */
} mbpf_ctx_timer_v1_t;

/* NET_TX context (v1) - same structure as NET_RX for transmit path */
typedef struct mbpf_ctx_net_tx_v1 {
    uint32_t abi_version;   /* = 1 */
    uint32_t ifindex;
    uint32_t pkt_len;
    uint32_t data_len;
    uint16_t l2_proto;
    uint16_t flags;
    const uint8_t *data;
    mbpf_read_bytes_fn read_fn;
} mbpf_ctx_net_tx_v1_t;

/* SECURITY context (v1) - for authorization decisions */
typedef struct mbpf_ctx_security_v1 {
    uint32_t abi_version;   /* = 1 */
    uint32_t subject_id;    /* ID of the subject (e.g., process, user, or principal) */
    uint32_t object_id;     /* ID of the object (e.g., resource, file, or target) */
    uint32_t action;        /* Action/operation being requested */
    uint16_t flags;         /* Context flags */
    uint16_t reserved;      /* Padding for alignment */
    uint32_t data_len;      /* Length of optional context data */
    const uint8_t *data;    /* Optional context-specific data */
    mbpf_read_bytes_fn read_fn; /* Optional scatter-gather reader */
} mbpf_ctx_security_v1_t;

/* CUSTOM context (v1) - for platform-defined hooks with versioned schema */
typedef struct mbpf_ctx_custom_v1 {
    uint32_t abi_version;       /* = 1 */
    uint32_t custom_hook_id;    /* Platform-defined hook identifier */
    uint32_t schema_version;    /* Platform-defined schema version for this hook */
    uint16_t flags;             /* Context flags */
    uint16_t reserved;          /* Padding for alignment */
    uint32_t field_count;       /* Number of custom fields in the schema */
    uint32_t data_len;          /* Length of custom context data */
    const uint8_t *data;        /* Custom context-specific data */
    mbpf_read_bytes_fn read_fn; /* Optional scatter-gather reader */

    /* Platform-provided field descriptors for dynamic field access.
     * Each field is described by name (null-terminated), offset, and type.
     * This allows JS code to access fields by name or index. */
    const struct mbpf_custom_field *fields;  /* Array of field_count descriptors */
} mbpf_ctx_custom_v1_t;

/* Custom field type enumeration for MBPF_HOOK_CUSTOM */
typedef enum {
    MBPF_FIELD_U8     = 1,
    MBPF_FIELD_U16    = 2,
    MBPF_FIELD_U32    = 3,
    MBPF_FIELD_U64    = 4,
    MBPF_FIELD_I8     = 5,
    MBPF_FIELD_I16    = 6,
    MBPF_FIELD_I32    = 7,
    MBPF_FIELD_I64    = 8,
    MBPF_FIELD_BYTES  = 9,   /* raw byte array */
} mbpf_field_type_t;

/* Custom field descriptor for MBPF_HOOK_CUSTOM */
typedef struct mbpf_custom_field {
    const char *name;           /* Field name (null-terminated) */
    uint32_t offset;            /* Byte offset in data buffer */
    uint32_t length;            /* Length in bytes (for BYTES type) */
    mbpf_field_type_t type;     /* Field type */
} mbpf_custom_field_t;

/* Core API */
mbpf_runtime_t *mbpf_runtime_init(const mbpf_runtime_config_t *cfg);
void mbpf_runtime_shutdown(mbpf_runtime_t *rt);

int mbpf_program_load(mbpf_runtime_t *rt, const void *pkg, size_t pkg_len,
                      const mbpf_load_opts_t *opts, mbpf_program_t **out_prog);
int mbpf_program_unload(mbpf_runtime_t *rt, mbpf_program_t *prog);

/* Update a program to a new version (hot swap).
 * By default, maps are preserved if the new program's map definitions are
 * compatible with the old program's maps (same name, type, key_size, value_size).
 * If maps are incompatible or map_policy is MBPF_MAP_POLICY_DESTROY, maps are
 * recreated fresh. The program must be detached before update.
 * Returns MBPF_OK on success, or an error code. */
int mbpf_program_update(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        const void *pkg, size_t pkg_len,
                        const mbpf_update_opts_t *opts);

int mbpf_program_attach(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        mbpf_hook_id_t hook);
int mbpf_program_detach(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        mbpf_hook_id_t hook);

int mbpf_run(mbpf_runtime_t *rt, mbpf_hook_id_t hook,
             const void *ctx_blob, size_t ctx_len,
             int32_t *out_rc);

/* Stats access */
int mbpf_program_stats(mbpf_program_t *prog, mbpf_stats_t *out_stats);

/* Instance access */
uint32_t mbpf_program_instance_count(mbpf_program_t *prog);
size_t mbpf_program_instance_heap_size(mbpf_program_t *prog, uint32_t idx);
mbpf_instance_t *mbpf_program_get_instance(mbpf_program_t *prog, uint32_t idx);

/* Version info */
const char *mbpf_version_string(void);
uint32_t mbpf_api_version(void);

/* Hook ABI version query */
uint32_t mbpf_hook_abi_version(mbpf_hook_type_t hook_type);

/* Hook exception default query - returns the default return code on exception */
int32_t mbpf_hook_exception_default(mbpf_hook_type_t hook_type);

/* Ring buffer map access (host-side API) */

/* Find a ring buffer map by name in a program.
 * Returns the map index (0-based) or -1 if not found.
 * The map must be of type MBPF_MAP_TYPE_RING. */
int mbpf_program_find_ring_map(mbpf_program_t *prog, const char *name);

/* Read the next event from a ring buffer map.
 * Returns the event length on success, 0 if buffer is empty, or -1 on error.
 * Event data is copied to out_data (up to max_len bytes).
 * If the event is larger than max_len, it is truncated but still consumed. */
int mbpf_ring_read(mbpf_program_t *prog, int map_idx,
                   void *out_data, size_t max_len);

/* Peek at the next event without consuming it.
 * Returns the event length on success, 0 if buffer is empty, or -1 on error.
 * Event data is copied to out_data (up to max_len bytes). */
int mbpf_ring_peek(mbpf_program_t *prog, int map_idx,
                   void *out_data, size_t max_len);

/* Get the number of events currently in the ring buffer.
 * Returns -1 on error. */
int mbpf_ring_count(mbpf_program_t *prog, int map_idx);

/* Get the number of events that have been dropped due to overflow.
 * Returns -1 on error. */
int mbpf_ring_dropped(mbpf_program_t *prog, int map_idx);

/* Emit event buffer access (host-side API for mbpf.emit events)
 *
 * Programs with CAP_EMIT can use mbpf.emit(eventId, bytes) to emit events.
 * Events are stored in a per-program ring buffer with format:
 *   [4 bytes: eventId][4 bytes: data_len][data: variable length]
 * The host can read events using these APIs after mbpf_run() returns.
 */

/* Read the next emitted event from the program's emit buffer.
 * Returns the event data length on success (excludes eventId header),
 * 0 if buffer is empty, or -1 on error.
 * Event data is copied to out_data (up to max_len bytes).
 * If out_event_id is not NULL, the event ID is written there.
 * If the data is larger than max_len, it is truncated but still consumed. */
int mbpf_emit_read(mbpf_program_t *prog, uint32_t *out_event_id,
                   void *out_data, size_t max_len);

/* Peek at the next emitted event without consuming it.
 * Same return semantics as mbpf_emit_read. */
int mbpf_emit_peek(mbpf_program_t *prog, uint32_t *out_event_id,
                   void *out_data, size_t max_len);

/* Get the number of events currently in the emit buffer.
 * Returns -1 on error. */
int mbpf_emit_count(mbpf_program_t *prog);

/* Get the number of events that have been dropped due to overflow.
 * Returns -1 on error. */
int mbpf_emit_dropped(mbpf_program_t *prog);

/* Circuit breaker API */

/* Check if a program's circuit breaker is currently open (disabled).
 * Returns true if the program is temporarily disabled, false otherwise.
 * Always returns false if circuit breaker is not configured. */
bool mbpf_program_circuit_open(mbpf_program_t *prog);

/* Manually reset a program's circuit breaker, closing the circuit
 * and allowing the program to run again. Returns MBPF_OK on success. */
int mbpf_program_circuit_reset(mbpf_program_t *prog);

#ifdef __cplusplus
}
#endif

#endif /* MBPF_H */
