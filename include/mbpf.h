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

/* Platform minimum heap size (8KB) - MQuickJS needs space for stdlib and basic operations */
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
    MBPF_MAP_TYPE_PERCPU  = 4,
    MBPF_MAP_TYPE_RING    = 5,
    MBPF_MAP_TYPE_COUNTER = 6,
} mbpf_map_type_t;

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
} mbpf_runtime_config_t;

/* Load options */
typedef struct mbpf_load_opts {
    uint32_t override_capabilities;
    size_t override_heap_size;
    bool allow_unsigned;
} mbpf_load_opts_t;

/* Per-program statistics */
typedef struct mbpf_stats {
    uint64_t invocations;
    uint64_t successes;
    uint64_t exceptions;
    uint64_t oom_errors;
    uint64_t budget_exceeded;
    uint64_t nested_dropped;
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

#ifdef __cplusplus
}
#endif

#endif /* MBPF_H */
