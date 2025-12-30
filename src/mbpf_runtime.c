/*
 * microBPF Runtime Implementation
 *
 * Core runtime for executing microBPF programs using MQuickJS.
 */

#define _GNU_SOURCE
#include "mbpf.h"
#include "mbpf_package.h"
#include "mquickjs.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <sched.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>
#include <pthread.h>

/*
 * Maximum size for ring buffer JS sync operations.
 * Limits JS string generation to prevent excessive memory allocation.
 * Sync uses chunked updates for buffers larger than this.
 */
#define MBPF_RING_SYNC_MAX_CHUNK  (64 * 1024)  /* 64KB max per sync chunk */

/*
 * Sequence lock for lock-free map reads.
 *
 * This implements a seqlock pattern that allows:
 * - Writers to acquire exclusive access (increment sequence before/after)
 * - Readers to detect torn reads by checking sequence stability
 *
 * The sequence counter is always even when no write is in progress.
 * Writers increment to odd (write-in-progress) then back to even.
 * Readers retry if they see an odd sequence or if sequence changed.
 */
typedef struct mbpf_seqlock {
    _Atomic uint32_t sequence;
} mbpf_seqlock_t;

/* Initialize a seqlock */
static inline void seqlock_init(mbpf_seqlock_t *lock) {
    atomic_store_explicit(&lock->sequence, 0, memory_order_relaxed);
}

/* Begin a write operation (acquires exclusive access) */
static inline void seqlock_write_begin(mbpf_seqlock_t *lock) {
    uint32_t seq = atomic_load_explicit(&lock->sequence, memory_order_relaxed);
    atomic_store_explicit(&lock->sequence, seq + 1, memory_order_release);
    atomic_thread_fence(memory_order_seq_cst);
}

/* End a write operation */
static inline void seqlock_write_end(mbpf_seqlock_t *lock) {
    atomic_thread_fence(memory_order_seq_cst);
    uint32_t seq = atomic_load_explicit(&lock->sequence, memory_order_relaxed);
    atomic_store_explicit(&lock->sequence, seq + 1, memory_order_release);
}

/* Begin a read operation (returns sequence for validation) */
static inline uint32_t seqlock_read_begin(mbpf_seqlock_t *lock) {
    uint32_t seq;
    do {
        seq = atomic_load_explicit(&lock->sequence, memory_order_acquire);
    } while (seq & 1);  /* Wait if write in progress (odd sequence) */
    return seq;
}

/* Validate a read operation (returns true if read was consistent) */
static inline bool seqlock_read_validate(mbpf_seqlock_t *lock, uint32_t seq) {
    atomic_thread_fence(memory_order_acquire);
    return atomic_load_explicit(&lock->sequence, memory_order_relaxed) == seq;
}

/*
 * Overflow-safe multiplication for size_t.
 * Returns true if the multiplication a * b can be performed without overflow.
 * If safe, stores the result in *out. If overflow would occur, returns false.
 */
static inline bool safe_size_mul(size_t a, size_t b, size_t *out) {
    if (a == 0 || b == 0) {
        *out = 0;
        return true;
    }
    if (a > SIZE_MAX / b) {
        return false;
    }
    *out = a * b;
    return true;
}

/*
 * Overflow-safe addition for size_t.
 * Returns true if the addition a + b can be performed without overflow.
 * If safe, stores the result in *out. If overflow would occur, returns false.
 */
static inline bool safe_size_add(size_t a, size_t b, size_t *out) {
    if (a > SIZE_MAX - b) {
        return false;
    }
    *out = a + b;
    return true;
}

/*
 * Safe string builder for JS code generation.
 *
 * Handles:
 * - Proper snprintf return value checking (detects truncation)
 * - Dynamic buffer growth when capacity is exceeded
 * - Prevention of underflow in remaining space tracking
 *
 * Usage:
 *   mbpf_strbuf_t sb;
 *   if (!strbuf_init(&sb, initial_size)) return -1;
 *   strbuf_printf(&sb, "format %d", value);
 *   ...
 *   if (sb.error) { strbuf_free(&sb); return -1; }
 *   // Use sb.buf with strlen(sb.buf)
 *   strbuf_free(&sb);
 */
typedef struct mbpf_strbuf {
    char *buf;         /* Buffer */
    size_t capacity;   /* Total capacity */
    size_t len;        /* Current string length (excluding NUL) */
    bool error;        /* Set on allocation failure */
} mbpf_strbuf_t;

/* Initialize a string builder with the given initial capacity */
static bool strbuf_init(mbpf_strbuf_t *sb, size_t initial_capacity) {
    sb->buf = malloc(initial_capacity);
    if (!sb->buf) {
        sb->capacity = 0;
        sb->len = 0;
        sb->error = true;
        return false;
    }
    sb->buf[0] = '\0';
    sb->capacity = initial_capacity;
    sb->len = 0;
    sb->error = false;
    return true;
}

/* Free the string builder's buffer */
static void strbuf_free(mbpf_strbuf_t *sb) {
    if (sb->buf) {
        free(sb->buf);
        sb->buf = NULL;
    }
    sb->capacity = 0;
    sb->len = 0;
}

/* Ensure the buffer has at least min_capacity bytes total */
static bool strbuf_grow(mbpf_strbuf_t *sb, size_t min_capacity) {
    if (sb->error) return false;
    if (sb->capacity >= min_capacity) return true;

    /* Grow by at least 2x or to min_capacity, whichever is larger */
    size_t new_capacity = sb->capacity * 2;
    if (new_capacity < min_capacity) {
        new_capacity = min_capacity;
    }
    /* Add some headroom to avoid repeated small growth */
    if (new_capacity < min_capacity + 4096) {
        new_capacity = min_capacity + 4096;
    }

    char *new_buf = realloc(sb->buf, new_capacity);
    if (!new_buf) {
        sb->error = true;
        return false;
    }
    sb->buf = new_buf;
    sb->capacity = new_capacity;
    return true;
}

/* Printf-style append to the string builder */
static void strbuf_printf(mbpf_strbuf_t *sb, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void strbuf_printf(mbpf_strbuf_t *sb, const char *fmt, ...) {
    if (sb->error) return;

    va_list args;
    size_t remaining = sb->capacity - sb->len;

    /* First attempt with current buffer */
    va_start(args, fmt);
    int written = vsnprintf(sb->buf + sb->len, remaining, fmt, args);
    va_end(args);

    if (written < 0) {
        sb->error = true;
        return;
    }

    /* Check if truncation occurred */
    if ((size_t)written >= remaining) {
        /* Need to grow: we need len + written + 1 bytes total */
        size_t needed = sb->len + (size_t)written + 1;
        if (!strbuf_grow(sb, needed)) {
            return;  /* error flag already set */
        }

        /* Retry with grown buffer */
        remaining = sb->capacity - sb->len;
        va_start(args, fmt);
        written = vsnprintf(sb->buf + sb->len, remaining, fmt, args);
        va_end(args);

        if (written < 0 || (size_t)written >= remaining) {
            sb->error = true;
            return;
        }
    }

    sb->len += (size_t)written;
}

/* Append a single character */
static void strbuf_putc(mbpf_strbuf_t *sb, char c) {
    if (sb->error) return;

    /* Need space for char + NUL */
    if (sb->len + 2 > sb->capacity) {
        if (!strbuf_grow(sb, sb->len + 2)) {
            return;
        }
    }
    sb->buf[sb->len++] = c;
    sb->buf[sb->len] = '\0';
}

/* Append a string */
static void strbuf_puts(mbpf_strbuf_t *sb, const char *s) {
    if (sb->error) return;

    size_t slen = strlen(s);
    size_t needed = sb->len + slen + 1;
    if (needed > sb->capacity) {
        if (!strbuf_grow(sb, needed)) {
            return;
        }
    }
    memcpy(sb->buf + sb->len, s, slen + 1);
    sb->len += slen;
}

/*
 * Append a JS string literal with proper escaping for embedded strings.
 * Escapes: single quotes, double quotes, backslashes, and control characters.
 * The string is surrounded by single quotes.
 */
static void strbuf_append_js_string(mbpf_strbuf_t *sb, const char *s) {
    if (sb->error) return;

    strbuf_putc(sb, '\'');

    while (*s) {
        unsigned char c = (unsigned char)*s++;
        switch (c) {
            case '\'':
                strbuf_puts(sb, "\\'");
                break;
            case '"':
                strbuf_puts(sb, "\\\"");
                break;
            case '\\':
                strbuf_puts(sb, "\\\\");
                break;
            case '\n':
                strbuf_puts(sb, "\\n");
                break;
            case '\r':
                strbuf_puts(sb, "\\r");
                break;
            case '\t':
                strbuf_puts(sb, "\\t");
                break;
            case '\0':
                strbuf_puts(sb, "\\0");
                break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    /* Escape other control characters as \xHH */
                    char hex[5];
                    snprintf(hex, sizeof(hex), "\\x%02x", c);
                    strbuf_puts(sb, hex);
                } else {
                    strbuf_putc(sb, (char)c);
                }
                break;
        }
    }

    strbuf_putc(sb, '\'');
}

/* Get the JS stdlib (defined in mbpf_stdlib.c) */
extern const JSSTDLibraryDef *mbpf_get_js_stdlib(void);

/* Log context functions (defined in mbpf_stdlib.c) */
extern void mbpf_set_log_context(void *log_fn, int debug_mode);
extern void mbpf_clear_log_context(void);

/*
 * Per-helper version registry.
 * Each helper has its own version (major<<16 | minor) for fine-grained
 * versioning when evolving individual helpers independently.
 * Programs can specify required helper versions in the manifest's
 * helper_versions map. The loader enforces: major must match exactly,
 * runtime minor must be >= program's required minor.
 */
typedef struct {
    const char *name;
    uint32_t version;  /* major<<16 | minor */
} mbpf_helper_version_entry_t;

/* Current helper versions - all helpers start at 0.1 */
#define MBPF_HELPER_VERSION_0_1 ((0 << 16) | 1)

static const mbpf_helper_version_entry_t mbpf_helper_versions[] = {
    { "log",         MBPF_HELPER_VERSION_0_1 },
    { "u64LoadLE",   MBPF_HELPER_VERSION_0_1 },
    { "u64StoreLE",  MBPF_HELPER_VERSION_0_1 },
    { "nowNs",       MBPF_HELPER_VERSION_0_1 },
    { "emit",        MBPF_HELPER_VERSION_0_1 },
    { "stats",       MBPF_HELPER_VERSION_0_1 },
    { "mapLookup",   MBPF_HELPER_VERSION_0_1 },
    { "mapUpdate",   MBPF_HELPER_VERSION_0_1 },
    { "mapDelete",   MBPF_HELPER_VERSION_0_1 },
    { NULL, 0 }  /* Sentinel */
};

/*
 * Look up the runtime version of a helper by name.
 * Returns the version (major<<16 | minor) or 0 if not found.
 */
static uint32_t get_helper_version(const char *name) {
    for (const mbpf_helper_version_entry_t *e = mbpf_helper_versions; e->name; e++) {
        if (strcmp(e->name, name) == 0) {
            return e->version;
        }
    }
    return 0;  /* Unknown helper */
}

/*
 * Check if a program's helper_versions are compatible with the runtime.
 * Returns 0 if compatible, -1 if incompatible.
 *
 * Rules (same as API version):
 * - Major versions must match exactly
 * - Runtime minor must be >= program's required minor
 * - Unknown helpers in the manifest cause rejection
 */
static int check_helper_versions(const mbpf_manifest_t *manifest) {
    for (uint32_t i = 0; i < manifest->helper_version_count; i++) {
        const char *name = manifest->helper_versions[i].name;
        uint32_t prog_ver = manifest->helper_versions[i].version;

        uint32_t runtime_ver = get_helper_version(name);
        if (runtime_ver == 0) {
            /* Unknown helper - reject */
            return -1;
        }

        uint16_t prog_major = (uint16_t)(prog_ver >> 16);
        uint16_t prog_minor = (uint16_t)(prog_ver & 0xFFFF);
        uint16_t runtime_major = (uint16_t)(runtime_ver >> 16);
        uint16_t runtime_minor = (uint16_t)(runtime_ver & 0xFFFF);

        if (prog_major != runtime_major) {
            return -1;
        }
        if (prog_minor > runtime_minor) {
            return -1;
        }
    }
    return 0;
}

/* Forward declarations for static functions used across the file */
struct mbpf_instance;
static void call_mbpf_fini_on_instance(struct mbpf_instance *inst);

/*
 * Runtime array map storage.
 * For array maps, values are stored in a flat array.
 * A bitmap tracks which entries have been set.
 *
 * Lock-free reads are supported via a seqlock. Readers check the sequence
 * before and after reading; if it changed or is odd, they retry.
 *
 * Writers are serialized via a mutex to prevent concurrent write races.
 * The write path acquires the mutex, then uses seqlock_write_begin/end
 * to signal to readers that a write is in progress.
 */
typedef struct mbpf_array_map {
    uint32_t max_entries;       /* Maximum number of entries */
    uint32_t value_size;        /* Size of each value in bytes */
    uint8_t *values;            /* Flat array: max_entries * value_size bytes */
    uint8_t *valid;             /* Bitmap: (max_entries + 7) / 8 bytes */
    mbpf_seqlock_t seqlock;     /* Seqlock for lock-free reads */
    pthread_mutex_t writer_lock; /* Mutex to serialize writers */
} mbpf_array_map_t;

/*
 * Runtime hash map storage.
 * Uses open addressing with linear probing.
 * Each bucket stores: valid flag, key bytes, value bytes.
 *
 * Lock-free reads are supported via a seqlock. Readers check the sequence
 * before and after reading; if it changed or is odd, they retry.
 *
 * Writers are serialized via a mutex to prevent concurrent write races.
 */
typedef struct mbpf_hash_map {
    uint32_t max_entries;       /* Maximum number of entries */
    uint32_t key_size;          /* Size of each key in bytes */
    uint32_t value_size;        /* Size of each value in bytes */
    uint32_t count;             /* Current number of entries */
    uint8_t *buckets;           /* Bucket array: max_entries * (1 + key_size + value_size) bytes */
                                /* Each bucket: [valid:1][key:key_size][value:value_size] */
    mbpf_seqlock_t seqlock;     /* Seqlock for lock-free reads */
    pthread_mutex_t writer_lock; /* Mutex to serialize writers */
} mbpf_hash_map_t;

/*
 * Runtime LRU hash map storage.
 * Uses open addressing with linear probing like hash map, but adds
 * LRU tracking via a doubly-linked list threaded through entries.
 * When at capacity, the least recently used entry is evicted on insert.
 *
 * Bucket layout: [valid:1][prev:4][next:4][key:key_size][value:value_size]
 * - valid: 0=empty, 1=valid, 2=deleted (tombstone)
 * - prev/next: 4-byte indices for LRU doubly-linked list (0xFFFFFFFF = null)
 *
 * The LRU list has head (most recently used) and tail (least recently used).
 *
 * Lock-free reads are supported via a seqlock. Readers check the sequence
 * before and after reading; if it changed or is odd, they retry.
 *
 * Writers are serialized via a mutex to prevent concurrent write races.
 */
typedef struct mbpf_lru_hash_map {
    uint32_t max_entries;       /* Maximum number of entries */
    uint32_t key_size;          /* Size of each key in bytes */
    uint32_t value_size;        /* Size of each value in bytes */
    uint32_t count;             /* Current number of entries */
    uint32_t lru_head;          /* Index of most recently used (head of list) */
    uint32_t lru_tail;          /* Index of least recently used (tail of list) */
    uint8_t *buckets;           /* Bucket array: max_entries * (1 + 4 + 4 + key_size + value_size) bytes */
    mbpf_seqlock_t seqlock;     /* Seqlock for lock-free reads */
    pthread_mutex_t writer_lock; /* Mutex to serialize writers */
} mbpf_lru_hash_map_t;

/*
 * Per-CPU array map storage.
 * Each CPU/instance has its own independent array map.
 * This allows lock-free concurrent access from different CPUs.
 */
typedef struct mbpf_percpu_array_map {
    uint32_t max_entries;       /* Maximum number of entries per CPU */
    uint32_t value_size;        /* Size of each value in bytes */
    uint32_t num_cpus;          /* Number of CPU instances */
    uint8_t **values;           /* Array of per-CPU value arrays */
    uint8_t **valid;            /* Array of per-CPU validity bitmaps */
} mbpf_percpu_array_map_t;

/*
 * Per-CPU hash map storage.
 * Each CPU/instance has its own independent hash map.
 */
typedef struct mbpf_percpu_hash_map {
    uint32_t max_entries;       /* Maximum number of entries per CPU */
    uint32_t key_size;          /* Size of each key in bytes */
    uint32_t value_size;        /* Size of each value in bytes */
    uint32_t num_cpus;          /* Number of CPU instances */
    uint32_t *counts;           /* Array of per-CPU entry counts */
    uint8_t **buckets;          /* Array of per-CPU bucket arrays */
} mbpf_percpu_hash_map_t;

/*
 * Ring buffer map storage for event output.
 * Uses a circular buffer with head/tail pointers.
 * Each event is stored as: [length:4][data:length] (variable length records).
 * When buffer is full, oldest events are dropped to make room for new ones.
 */
typedef struct mbpf_ring_buffer_map {
    uint32_t buffer_size;       /* Total buffer size in bytes */
    uint32_t max_event_size;    /* Maximum event size (from manifest value_size) */
    uint32_t head;              /* Write position (next write offset) */
    uint32_t tail;              /* Read position (next read offset) */
    uint32_t dropped;           /* Count of dropped events due to overflow */
    uint32_t event_count;       /* Number of events currently in buffer */
    uint8_t *buffer;            /* Circular buffer storage */
} mbpf_ring_buffer_map_t;

/*
 * Emit event buffer for mbpf.emit() helper.
 * Uses a circular buffer with head/tail pointers.
 * Each event is stored as: [eventId:4][length:4][data:length] (variable length records).
 * When buffer is full, oldest events are dropped to make room for new ones.
 */
typedef struct mbpf_emit_buffer {
    uint32_t buffer_size;       /* Total buffer size in bytes (default 4KB) */
    uint32_t max_event_size;    /* Maximum event data size (default 256 bytes) */
    uint32_t head;              /* Write position (next write offset) */
    uint32_t tail;              /* Read position (next read offset) */
    uint32_t dropped;           /* Count of dropped events due to overflow */
    uint32_t event_count;       /* Number of events currently in buffer */
    uint8_t *buffer;            /* Circular buffer storage */
} mbpf_emit_buffer_t;

/*
 * Counter map storage for atomic 64-bit counters.
 * Provides atomic add/get operations on an array of 64-bit counters.
 * Optimized for counting use cases (stats, metrics, etc.).
 */
typedef struct mbpf_counter_map {
    uint32_t max_entries;       /* Maximum number of counters */
    int64_t *counters;          /* Array of 64-bit counters */
} mbpf_counter_map_t;

/*
 * Generic map storage container.
 */
typedef struct mbpf_map_storage {
    char name[32];              /* Map name from manifest */
    uint32_t type;              /* Map type (MBPF_MAP_TYPE_*) */
    union {
        mbpf_array_map_t array;
        mbpf_hash_map_t hash;
        mbpf_lru_hash_map_t lru_hash;
        mbpf_percpu_array_map_t percpu_array;
        mbpf_percpu_hash_map_t percpu_hash;
        mbpf_ring_buffer_map_t ring;
        mbpf_counter_map_t counter;
    } u;
} mbpf_map_storage_t;

/* Per-CPU or per-thread execution instance */
struct mbpf_instance {
    void *js_heap;              /* Heap memory for JS context */
    size_t heap_size;           /* Size of allocated heap */
    void *bytecode;             /* Instance's bytecode copy (kept for JS runtime) */
    size_t bytecode_len;        /* Length of bytecode */
    JSContext *js_ctx;          /* MQuickJS context */
    JSValue main_func;          /* Loaded main function */
    bool js_initialized;        /* Whether JS context is set up */
    volatile int in_use;        /* Nested execution prevention flag */
    uint32_t index;             /* Instance index (for debugging) */
    struct mbpf_program *program; /* Back pointer to owning program */
    /* Step budget tracking for max_steps enforcement */
    uint32_t max_steps;         /* Maximum steps allowed per invocation */
    volatile uint32_t steps_remaining; /* Steps remaining in current invocation */
    volatile int budget_exceeded; /* Flag set when budget is exceeded */
    /* Helper budget tracking for max_helpers enforcement */
    uint32_t max_helpers;       /* Maximum helper calls allowed per invocation */
    /* Wall time budget tracking for max_wall_time_us enforcement */
    uint32_t max_wall_time_us;  /* Maximum wall time allowed per invocation in microseconds */
    struct timespec start_time; /* Start time of current invocation */
    /*
     * GC-protected references for persistent values that must survive
     * compacting GC. MQuickJS uses a compacting GC that can relocate objects,
     * so any values held across potential GC points must use JSGCRef.
     */
    JSGCRef entry_func_ref;     /* GC-protected reference to entry function (e.g., mbpf_prog) */
    JSGCRef maps_obj_ref;       /* GC-protected reference to maps global object */
    bool has_entry_func_ref;    /* Whether entry_func_ref is valid (was registered) */
    bool has_maps_obj_ref;      /* Whether maps_obj_ref is valid (was registered) */
    /*
     * Reusable context object for performance optimization.
     * The ctx object is created once per instance and reused across invocations.
     * The underlying data is stored in global JS variables that are updated
     * at each invocation, avoiding per-invocation object allocation.
     */
    JSGCRef ctx_obj_ref;        /* GC-protected reference to reusable ctx object */
    bool has_ctx_obj_ref;       /* Whether ctx_obj_ref is valid (was registered) */
    bool ctx_initialized;       /* Whether reusable ctx infrastructure is set up */
};

/* Internal structures */
struct mbpf_runtime {
    mbpf_runtime_config_t config;
    mbpf_program_t *programs;
    size_t program_count;
    uint32_t num_instances;     /* Number of instances per program */
    bool initialized;
    /* Trace logging rate limiter state */
    uint64_t trace_count_current_sec;  /* Messages emitted in current second */
    struct timespec trace_window_start; /* Start of current rate limit window */
};

struct mbpf_program {
    mbpf_runtime_t *runtime;
    mbpf_manifest_t manifest;
    void *bytecode;
    size_t bytecode_len;
    mbpf_stats_t stats;
    mbpf_hook_id_t attached_hook;
    bool attached;
    bool unloaded;              /* Track if already unloaded (for double-unload protection) */
    struct mbpf_program *next;
    mbpf_bytecode_info_t bc_info; /* Bytecode info from loading */

    /* Instance array */
    mbpf_instance_t *instances;
    uint32_t instance_count;

    /* Map storage - shared across all instances */
    mbpf_map_storage_t *maps;
    uint32_t map_count;

    /* Emit event buffer for mbpf.emit() - shared across all instances */
    mbpf_emit_buffer_t *emit_buffer;
    bool has_emit_cap;          /* Whether program has CAP_EMIT */

    /* Circuit breaker state */
    uint32_t consecutive_failures; /* Count of consecutive failures */
    bool circuit_open;             /* True if circuit breaker is tripped */
    struct timespec circuit_open_time; /* Time when circuit was opened */

    /* Debug info (optional, from MBPF_SEC_DEBUG section) */
    mbpf_debug_info_t debug_info;
    bool has_debug_info;
};

/* Default log handler */
static void default_log_fn(int level, const char *msg) {
    const char *level_str = "INFO";
    switch (level) {
        case 0: level_str = "DEBUG"; break;
        case 1: level_str = "INFO"; break;
        case 2: level_str = "WARN"; break;
        case 3: level_str = "ERROR"; break;
    }
    fprintf(stderr, "[mbpf %s] %s\n", level_str, msg);
}

/*
 * Trace logging with rate limiting.
 * Emits trace messages through the configured log_fn when trace_enabled is true.
 * Rate limiting is enforced per second if trace_rate_limit_per_sec > 0.
 * Returns true if the message was emitted, false if rate-limited.
 */
static bool mbpf_trace_log(mbpf_runtime_t *rt, const char *fmt, ...) {
    if (!rt || !rt->config.trace_enabled || !rt->config.log_fn) {
        return false;
    }

    /* Check rate limiting if configured */
    if (rt->config.trace_rate_limit_per_sec > 0) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        /* Check if we're in a new second window */
        if (now.tv_sec != rt->trace_window_start.tv_sec) {
            /* New window - reset counter */
            rt->trace_window_start = now;
            rt->trace_count_current_sec = 0;
        }

        /* Check if we've exceeded the rate limit */
        if (rt->trace_count_current_sec >= rt->config.trace_rate_limit_per_sec) {
            return false;  /* Rate limited */
        }

        rt->trace_count_current_sec++;
    }

    /* Format and emit the trace message */
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    /* Emit as DEBUG level (0) with TRACE prefix */
    char trace_buf[544];
    snprintf(trace_buf, sizeof(trace_buf), "[TRACE] %s", buf);
    rt->config.log_fn(0, trace_buf);

    return true;
}

/*
 * Interrupt handler for step and wall time budget enforcement.
 * Called by MQuickJS periodically during execution.
 * Returns non-zero to abort execution when budget is exceeded.
 */
static int mbpf_interrupt_handler(JSContext *ctx, void *opaque) {
    (void)ctx;  /* Unused parameter */
    mbpf_instance_t *inst = (mbpf_instance_t *)opaque;
    if (!inst) {
        return 0;  /* No instance context, continue execution */
    }

    /* Check step budget */
    if (inst->max_steps > 0) {
        if (inst->steps_remaining > 0) {
            inst->steps_remaining--;
        } else {
            /* Step budget exceeded - set flag and abort */
            inst->budget_exceeded = 1;
            return 1;
        }
    }

    /* Check wall time budget */
    if (inst->max_wall_time_us > 0) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        /* Calculate elapsed time in microseconds with borrow handling */
        int64_t sec = (int64_t)now.tv_sec - (int64_t)inst->start_time.tv_sec;
        int64_t nsec = (int64_t)now.tv_nsec - (int64_t)inst->start_time.tv_nsec;
        if (nsec < 0) {
            sec--;
            nsec += 1000000000LL;
        }
        if (sec < 0) {
            sec = 0;
            nsec = 0;
        }
        uint64_t elapsed_us =
            (uint64_t)sec * 1000000ULL + (uint64_t)(nsec / 1000LL);

        if (elapsed_us >= inst->max_wall_time_us) {
            /* Wall time budget exceeded - set flag and abort */
            inst->budget_exceeded = 1;
            return 1;
        }
    }

    return 0;  /* Continue execution */
}

/*
 * Create map storage from manifest definitions.
 * For per-CPU maps, num_instances copies are allocated.
 * Returns 0 on success, -1 on error.
 */
static int create_maps_from_manifest(mbpf_program_t *prog, uint32_t num_instances) {
    if (!prog->manifest.maps || prog->manifest.map_count == 0) {
        prog->maps = NULL;
        prog->map_count = 0;
        return 0;
    }

    prog->map_count = prog->manifest.map_count;
    prog->maps = calloc(prog->map_count, sizeof(mbpf_map_storage_t));
    if (!prog->maps) {
        prog->map_count = 0;
        return -1;
    }

    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_def_t *def = &prog->manifest.maps[i];
        mbpf_map_storage_t *storage = &prog->maps[i];

        strncpy(storage->name, def->name, sizeof(storage->name) - 1);
        storage->name[sizeof(storage->name) - 1] = '\0';

        /* Determine effective map type based on type and flags.
         * ARRAY or HASH maps with MBPF_MAP_FLAG_PERCPU become per-CPU variants. */
        uint32_t effective_type = def->type;
        if (def->flags & MBPF_MAP_FLAG_PERCPU) {
            if (def->type == MBPF_MAP_TYPE_ARRAY) {
                effective_type = MBPF_MAP_TYPE_PERCPU_ARRAY;
            } else if (def->type == MBPF_MAP_TYPE_HASH) {
                effective_type = MBPF_MAP_TYPE_PERCPU_HASH;
            }
        }
        storage->type = effective_type;

        if (effective_type == MBPF_MAP_TYPE_ARRAY) {
            mbpf_array_map_t *arr = &storage->u.array;
            arr->max_entries = def->max_entries;
            arr->value_size = def->value_size;

            /* Validate allocation size against overflow */
            size_t values_size;
            if (!safe_size_mul((size_t)arr->max_entries, (size_t)arr->value_size, &values_size)) {
                goto cleanup;
            }

            arr->values = calloc(values_size, 1);
            if (!arr->values) {
                goto cleanup;
            }

            /* Allocate validity bitmap: one bit per entry */
            size_t bitmap_size = (arr->max_entries + 7) / 8;
            arr->valid = calloc(bitmap_size, 1);
            if (!arr->valid) {
                free(arr->values);
                arr->values = NULL;
                goto cleanup;
            }

            /* Initialize seqlock for lock-free reads */
            seqlock_init(&arr->seqlock);
            /* Initialize writer lock for serializing concurrent writers */
            pthread_mutex_init(&arr->writer_lock, NULL);
        } else if (effective_type == MBPF_MAP_TYPE_HASH) {
            mbpf_hash_map_t *hash = &storage->u.hash;
            hash->max_entries = def->max_entries;
            hash->key_size = def->key_size;
            hash->value_size = def->value_size;
            hash->count = 0;

            /* Allocate bucket storage: each bucket is [valid:1][key][value]
             * Validate bucket_size and total allocation against overflow */
            size_t bucket_size, buckets_size;
            if (!safe_size_add(1, (size_t)hash->key_size, &bucket_size) ||
                !safe_size_add(bucket_size, (size_t)hash->value_size, &bucket_size) ||
                !safe_size_mul((size_t)hash->max_entries, bucket_size, &buckets_size)) {
                goto cleanup;
            }
            hash->buckets = calloc(buckets_size, 1);
            if (!hash->buckets) {
                goto cleanup;
            }

            /* Initialize seqlock for lock-free reads */
            seqlock_init(&hash->seqlock);
            /* Initialize writer lock for serializing concurrent writers */
            pthread_mutex_init(&hash->writer_lock, NULL);
        } else if (effective_type == MBPF_MAP_TYPE_LRU) {
            mbpf_lru_hash_map_t *lru = &storage->u.lru_hash;
            lru->max_entries = def->max_entries;
            lru->key_size = def->key_size;
            lru->value_size = def->value_size;
            lru->count = 0;
            lru->lru_head = 0xFFFFFFFF;  /* null */
            lru->lru_tail = 0xFFFFFFFF;  /* null */

            /* Allocate bucket storage: each bucket is [valid:1][prev:4][next:4][key][value]
             * Validate bucket_size and total allocation against overflow */
            size_t bucket_size, buckets_size;
            if (!safe_size_add(9, (size_t)lru->key_size, &bucket_size) ||  /* 1 + 4 + 4 = 9 */
                !safe_size_add(bucket_size, (size_t)lru->value_size, &bucket_size) ||
                !safe_size_mul((size_t)lru->max_entries, bucket_size, &buckets_size)) {
                goto cleanup;
            }
            lru->buckets = calloc(buckets_size, 1);
            if (!lru->buckets) {
                goto cleanup;
            }

            /* Initialize seqlock for lock-free reads */
            seqlock_init(&lru->seqlock);
            /* Initialize writer lock for serializing concurrent writers */
            pthread_mutex_init(&lru->writer_lock, NULL);
        } else if (effective_type == MBPF_MAP_TYPE_PERCPU_ARRAY) {
            /* Per-CPU array: allocate separate storage for each CPU */
            mbpf_percpu_array_map_t *pca = &storage->u.percpu_array;
            pca->max_entries = def->max_entries;
            pca->value_size = def->value_size;
            pca->num_cpus = num_instances;

            /* Validate per-CPU value array size against overflow before allocation */
            size_t values_size;
            if (!safe_size_mul((size_t)pca->max_entries, (size_t)pca->value_size, &values_size)) {
                goto cleanup;
            }

            /* Allocate arrays of pointers for per-CPU storage */
            pca->values = calloc(num_instances, sizeof(uint8_t *));
            pca->valid = calloc(num_instances, sizeof(uint8_t *));
            if (!pca->values || !pca->valid) {
                free(pca->values);
                free(pca->valid);
                pca->values = NULL;
                pca->valid = NULL;
                goto cleanup;
            }

            /* Allocate per-CPU value arrays and validity bitmaps */
            size_t bitmap_size = pca->max_entries;  /* One byte per entry for simplicity */
            for (uint32_t cpu = 0; cpu < num_instances; cpu++) {
                pca->values[cpu] = calloc(values_size, 1);
                pca->valid[cpu] = calloc(bitmap_size, 1);
                if (!pca->values[cpu] || !pca->valid[cpu]) {
                    /* Clean up already allocated CPU storage */
                    for (uint32_t c = 0; c <= cpu; c++) {
                        free(pca->values[c]);
                        free(pca->valid[c]);
                    }
                    free(pca->values);
                    free(pca->valid);
                    pca->values = NULL;
                    pca->valid = NULL;
                    goto cleanup;
                }
            }
        } else if (effective_type == MBPF_MAP_TYPE_PERCPU_HASH) {
            /* Per-CPU hash: allocate separate storage for each CPU */
            mbpf_percpu_hash_map_t *pch = &storage->u.percpu_hash;
            pch->max_entries = def->max_entries;
            pch->key_size = def->key_size;
            pch->value_size = def->value_size;
            pch->num_cpus = num_instances;

            /* Validate bucket size against overflow before allocation */
            size_t bucket_size, buckets_size;
            if (!safe_size_add(1, (size_t)pch->key_size, &bucket_size) ||
                !safe_size_add(bucket_size, (size_t)pch->value_size, &bucket_size) ||
                !safe_size_mul((size_t)pch->max_entries, bucket_size, &buckets_size)) {
                goto cleanup;
            }

            /* Allocate arrays for per-CPU storage */
            pch->buckets = calloc(num_instances, sizeof(uint8_t *));
            pch->counts = calloc(num_instances, sizeof(uint32_t));
            if (!pch->buckets || !pch->counts) {
                free(pch->buckets);
                free(pch->counts);
                pch->buckets = NULL;
                pch->counts = NULL;
                goto cleanup;
            }

            /* Allocate per-CPU bucket arrays */
            for (uint32_t cpu = 0; cpu < num_instances; cpu++) {
                pch->buckets[cpu] = calloc(buckets_size, 1);
                if (!pch->buckets[cpu]) {
                    /* Clean up already allocated CPU storage */
                    for (uint32_t c = 0; c < cpu; c++) {
                        free(pch->buckets[c]);
                    }
                    free(pch->buckets);
                    free(pch->counts);
                    pch->buckets = NULL;
                    pch->counts = NULL;
                    goto cleanup;
                }
                pch->counts[cpu] = 0;
            }
        } else if (effective_type == MBPF_MAP_TYPE_RING) {
            /* Ring buffer: allocate circular buffer storage.
             * For ring buffers, max_entries * value_size gives total buffer size.
             * value_size represents the maximum event size.
             * Validate buffer size against overflow before allocation */
            mbpf_ring_buffer_map_t *ring = &storage->u.ring;
            size_t buffer_size;
            if (!safe_size_mul((size_t)def->max_entries, (size_t)def->value_size, &buffer_size)) {
                goto cleanup;
            }
            if (buffer_size > UINT32_MAX) {
                goto cleanup;
            }
            ring->buffer_size = (uint32_t)buffer_size;
            if (ring->buffer_size < 64) {
                ring->buffer_size = 64;  /* Minimum 64 bytes */
            }
            ring->max_event_size = def->value_size;
            ring->head = 0;
            ring->tail = 0;
            ring->dropped = 0;
            ring->event_count = 0;

            ring->buffer = calloc(ring->buffer_size, 1);
            if (!ring->buffer) {
                goto cleanup;
            }
        } else if (effective_type == MBPF_MAP_TYPE_COUNTER) {
            /* Counter map: allocate array of 64-bit counters.
             * max_entries specifies number of counters.
             * Validate allocation size against overflow */
            mbpf_counter_map_t *ctr = &storage->u.counter;
            ctr->max_entries = def->max_entries;
            size_t counters_size;
            if (!safe_size_mul((size_t)ctr->max_entries, sizeof(int64_t), &counters_size)) {
                goto cleanup;
            }
            ctr->counters = calloc(counters_size, 1);
            if (!ctr->counters) {
                goto cleanup;
            }
        }
    }

    return 0;

cleanup:
    /* Free any partially allocated maps */
    for (uint32_t j = 0; j < prog->map_count; j++) {
        mbpf_map_storage_t *storage = &prog->maps[j];
        if (storage->type == MBPF_MAP_TYPE_ARRAY) {
            if (storage->u.array.values || storage->u.array.valid) {
                pthread_mutex_destroy(&storage->u.array.writer_lock);
            }
            free(storage->u.array.values);
            free(storage->u.array.valid);
        } else if (storage->type == MBPF_MAP_TYPE_HASH) {
            if (storage->u.hash.buckets) {
                pthread_mutex_destroy(&storage->u.hash.writer_lock);
            }
            free(storage->u.hash.buckets);
        } else if (storage->type == MBPF_MAP_TYPE_LRU) {
            if (storage->u.lru_hash.buckets) {
                pthread_mutex_destroy(&storage->u.lru_hash.writer_lock);
            }
            free(storage->u.lru_hash.buckets);
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_ARRAY) {
            mbpf_percpu_array_map_t *pca = &storage->u.percpu_array;
            if (pca->values && pca->valid) {
                for (uint32_t c = 0; c < pca->num_cpus; c++) {
                    free(pca->values[c]);
                    free(pca->valid[c]);
                }
            }
            free(pca->values);
            free(pca->valid);
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_HASH) {
            mbpf_percpu_hash_map_t *pch = &storage->u.percpu_hash;
            if (pch->buckets) {
                for (uint32_t c = 0; c < pch->num_cpus; c++) {
                    free(pch->buckets[c]);
                }
            }
            free(pch->buckets);
            free(pch->counts);
        } else if (storage->type == MBPF_MAP_TYPE_RING) {
            free(storage->u.ring.buffer);
        } else if (storage->type == MBPF_MAP_TYPE_COUNTER) {
            free(storage->u.counter.counters);
        }
    }
    free(prog->maps);
    prog->maps = NULL;
    prog->map_count = 0;
    return -1;
}

/*
 * Free map storage.
 */
static void free_maps(mbpf_program_t *prog) {
    if (!prog->maps) return;

    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];
        if (storage->type == MBPF_MAP_TYPE_ARRAY) {
            pthread_mutex_destroy(&storage->u.array.writer_lock);
            free(storage->u.array.values);
            free(storage->u.array.valid);
        } else if (storage->type == MBPF_MAP_TYPE_HASH) {
            pthread_mutex_destroy(&storage->u.hash.writer_lock);
            free(storage->u.hash.buckets);
        } else if (storage->type == MBPF_MAP_TYPE_LRU) {
            pthread_mutex_destroy(&storage->u.lru_hash.writer_lock);
            free(storage->u.lru_hash.buckets);
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_ARRAY) {
            mbpf_percpu_array_map_t *pca = &storage->u.percpu_array;
            if (pca->values && pca->valid) {
                for (uint32_t c = 0; c < pca->num_cpus; c++) {
                    free(pca->values[c]);
                    free(pca->valid[c]);
                }
            }
            free(pca->values);
            free(pca->valid);
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_HASH) {
            mbpf_percpu_hash_map_t *pch = &storage->u.percpu_hash;
            if (pch->buckets) {
                for (uint32_t c = 0; c < pch->num_cpus; c++) {
                    free(pch->buckets[c]);
                }
            }
            free(pch->buckets);
            free(pch->counts);
        } else if (storage->type == MBPF_MAP_TYPE_RING) {
            free(storage->u.ring.buffer);
        } else if (storage->type == MBPF_MAP_TYPE_COUNTER) {
            free(storage->u.counter.counters);
        }
    }
    free(prog->maps);
    prog->maps = NULL;
    prog->map_count = 0;
}

/* Default emit buffer size (4KB) and max event size (256 bytes) */
#define MBPF_EMIT_BUFFER_SIZE 4096
#define MBPF_EMIT_MAX_EVENT_SIZE 256

/*
 * Create emit buffer for programs with CAP_EMIT capability.
 * Returns 0 on success, -1 on error.
 */
static int create_emit_buffer(mbpf_program_t *prog) {
    /* Check if CAP_EMIT is granted */
    if (!(prog->manifest.capabilities & MBPF_CAP_EMIT)) {
        prog->emit_buffer = NULL;
        prog->has_emit_cap = false;
        return 0;
    }

    prog->has_emit_cap = true;
    prog->emit_buffer = calloc(1, sizeof(mbpf_emit_buffer_t));
    if (!prog->emit_buffer) {
        return -1;
    }

    prog->emit_buffer->buffer_size = MBPF_EMIT_BUFFER_SIZE;
    prog->emit_buffer->max_event_size = MBPF_EMIT_MAX_EVENT_SIZE;
    prog->emit_buffer->head = 0;
    prog->emit_buffer->tail = 0;
    prog->emit_buffer->dropped = 0;
    prog->emit_buffer->event_count = 0;

    prog->emit_buffer->buffer = calloc(1, MBPF_EMIT_BUFFER_SIZE);
    if (!prog->emit_buffer->buffer) {
        free(prog->emit_buffer);
        prog->emit_buffer = NULL;
        return -1;
    }

    return 0;
}

/*
 * Free emit buffer.
 */
static void free_emit_buffer(mbpf_program_t *prog) {
    if (prog->emit_buffer) {
        free(prog->emit_buffer->buffer);
        free(prog->emit_buffer);
        prog->emit_buffer = NULL;
    }
    prog->has_emit_cap = false;
}

/*
 * Create the 'mbpf' global object for a JS context.
 * This object provides helper functions and properties:
 * - apiVersion: Runtime API version encoded as (major << 16) | minor
 * - log(level, msg): Logging helper that maps to runtime log callback
 * - u64LoadLE/u64StoreLE: 64-bit value helpers
 * - nowNs(out): Monotonic time in nanoseconds (requires CAP_TIME)
 * - emit(eventId, bytes): Emit an event to the event buffer (requires CAP_EMIT)
 *
 * Log levels: 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
 * The log function uses print internally but adds level prefix.
 */
static int setup_mbpf_object(JSContext *ctx, uint32_t capabilities) {
    /* Build JS code to create mbpf object with apiVersion, log, u64 helpers,
     * and optionally nowNs if CAP_TIME is granted, emit if CAP_EMIT is granted,
     * stats if CAP_STATS is granted.
     * The log function prepends the level prefix and calls print,
     * which maps to js_print in mbpf_stdlib.c where the actual logging happens.
     * u64LoadLE/u64StoreLE handle 64-bit values as [lo, hi] pairs in LE format.
     * nowNs reads from _mbpf_time_ns which is updated by the runtime before each run.
     * emit writes events to _mbpf_emit_buf which is synced to C after each run.
     * stats reads from _mbpf_stats which is updated by the runtime before each run. */
    char code[6144];
    uint32_t api_version = MBPF_API_VERSION;
    int has_cap_log = (capabilities & MBPF_CAP_LOG) != 0;
    int has_cap_time = (capabilities & MBPF_CAP_TIME) != 0;
    int has_cap_emit = (capabilities & MBPF_CAP_EMIT) != 0;
    int has_cap_stats = (capabilities & MBPF_CAP_STATS) != 0;

    snprintf(code, sizeof(code),
        "(function(){"
        "%s"  /* CAP_LOG: create levelNames for log helper */
        "%s"  /* CAP_TIME: create _mbpf_time_ns array */
        "%s"  /* CAP_EMIT: create _mbpf_emit_* state */
        "%s"  /* CAP_STATS: create _mbpf_stats object */
        "var ch=function(){if(typeof _checkHelper==='function')_checkHelper();};"
        "globalThis.mbpf={"
        "apiVersion:%u,"
        "%s"  /* CAP_LOG: log helper (includes trailing comma if present) */
        "u64LoadLE:function(bytes,offset,out){"
            "ch();"
            "if(!(bytes instanceof Uint8Array))throw new TypeError('bytes must be Uint8Array');"
            "if(typeof offset!=='number')throw new TypeError('offset must be number');"
            "if(!Array.isArray(out)||out.length<2)throw new TypeError('out must be array of length 2');"
            "if(offset<0||offset+8>bytes.length)throw new RangeError('offset out of bounds');"
            "var lo=(bytes[offset]|(bytes[offset+1]<<8)|(bytes[offset+2]<<16)|(bytes[offset+3]<<24))>>>0;"
            "var hi=(bytes[offset+4]|(bytes[offset+5]<<8)|(bytes[offset+6]<<16)|(bytes[offset+7]<<24))>>>0;"
            "out[0]=lo;out[1]=hi;"
        "},"
        "u64StoreLE:function(bytes,offset,value){"
            "ch();"
            "if(!(bytes instanceof Uint8Array))throw new TypeError('bytes must be Uint8Array');"
            "if(typeof offset!=='number')throw new TypeError('offset must be number');"
            "if(!Array.isArray(value)||value.length<2)throw new TypeError('value must be array of length 2');"
            "if(offset<0||offset+8>bytes.length)throw new RangeError('offset out of bounds');"
            "var lo=value[0]>>>0,hi=value[1]>>>0;"
            "bytes[offset]=lo&0xFF;bytes[offset+1]=(lo>>8)&0xFF;"
            "bytes[offset+2]=(lo>>16)&0xFF;bytes[offset+3]=(lo>>24)&0xFF;"
            "bytes[offset+4]=hi&0xFF;bytes[offset+5]=(hi>>8)&0xFF;"
            "bytes[offset+6]=(hi>>16)&0xFF;bytes[offset+7]=(hi>>24)&0xFF;"
        "}%s%s%s"
        "};"
        "})()",
        has_cap_log ? "var levelNames=['DEBUG','INFO','WARN','ERROR'];" : "",
        has_cap_time ? "globalThis._mbpf_time_ns=[0,0];" : "",
        has_cap_emit ?
            /* Create emit buffer state:
             * _mbpf_emit_buf: Uint8Array holding the event data
             * _mbpf_emit_meta: {head, tail, dropped, eventCount, bufSize, maxEventSize}
             * Format in buffer: [eventId:4][dataLen:4][data:dataLen] per event */
            "globalThis._mbpf_emit_buf=new Uint8Array(4096);"
            "globalThis._mbpf_emit_meta={head:0,tail:0,dropped:0,eventCount:0,bufSize:4096,maxEventSize:256};"
            : "",
        has_cap_stats ?
            /* Create stats object:
             * Each stat value is stored as a [lo, hi] pair for 64-bit representation.
             * The runtime updates this object before each program invocation. */
            "globalThis._mbpf_stats={"
                "invocations:[0,0],"
                "successes:[0,0],"
                "exceptions:[0,0],"
                "oom_errors:[0,0],"
                "budget_exceeded:[0,0],"
                "nested_dropped:[0,0],"
                "deferred_dropped:[0,0]"
            "};"
            : "",
        api_version,
        has_cap_log ?
            "log:function(level,msg){"
                "ch();"
                "if(typeof level!=='number')level=1;"
                "if(level<0)level=0;"
                "if(level>3)level=3;"
                "if(msg===undefined)msg='';"
                "print('['+levelNames[level]+'] '+String(msg));"
            "},"
            : "",
        has_cap_time ?
            ","
            "nowNs:function(out){"
                "ch();"
                "if(!Array.isArray(out)||out.length<2)throw new TypeError('out must be array of length 2');"
                "out[0]=_mbpf_time_ns[0];out[1]=_mbpf_time_ns[1];"
            "}"
            : "",
        has_cap_emit ?
            ","
            "emit:function(eventId,bytes){"
                "ch();"
                "if(typeof eventId!=='number')throw new TypeError('eventId must be a number');"
                "if(!(bytes instanceof Uint8Array))throw new TypeError('bytes must be Uint8Array');"
                "var dataLen=bytes.length;"
                "if(dataLen>_mbpf_emit_meta.maxEventSize)return false;"  /* Event too large */
                "var recordLen=8+dataLen;"  /* eventId(4) + dataLen(4) + data */
                "var m=_mbpf_emit_meta,b=_mbpf_emit_buf,bs=m.bufSize;"
                /* Calculate used space */
                "var used=(m.head>=m.tail)?(m.head-m.tail):(bs-m.tail+m.head);"
                "var free=bs-used-1;"  /* Leave 1 byte to distinguish full from empty */
                /* Drop oldest events until we have space */
                "while(free<recordLen&&m.eventCount>0){"
                    /* Read length of oldest event at tail */
                    "var oldLen=(b[(m.tail+4)%bs]|(b[(m.tail+5)%bs]<<8)|(b[(m.tail+6)%bs]<<16)|(b[(m.tail+7)%bs]<<24))>>>0;"
                    "var oldRecLen=8+oldLen;"
                    "m.tail=(m.tail+oldRecLen)%bs;"
                    "m.eventCount--;"
                    "m.dropped++;"
                    "free+=oldRecLen;"
                "}"
                "if(free<recordLen)return false;"  /* Still not enough space (shouldn't happen) */
                /* Write eventId (4 bytes LE) */
                "var eid=eventId>>>0;"
                "b[m.head]=eid&0xFF;b[(m.head+1)%bs]=(eid>>8)&0xFF;"
                "b[(m.head+2)%bs]=(eid>>16)&0xFF;b[(m.head+3)%bs]=(eid>>24)&0xFF;"
                /* Write dataLen (4 bytes LE) */
                "b[(m.head+4)%bs]=dataLen&0xFF;b[(m.head+5)%bs]=(dataLen>>8)&0xFF;"
                "b[(m.head+6)%bs]=(dataLen>>16)&0xFF;b[(m.head+7)%bs]=(dataLen>>24)&0xFF;"
                /* Write data bytes */
                "for(var i=0;i<dataLen;i++)b[(m.head+8+i)%bs]=bytes[i];"
                "m.head=(m.head+recordLen)%bs;"
                "m.eventCount++;"
                "return true;"
            "}"
            : "",
        has_cap_stats ?
            ","
            "stats:function(out){"
                "ch();"
                /* Writes current stats into a preallocated output object.
                 * out must be an object with arrays for each stat field.
                 * This is allocation-free on the success path per §7.5.3. */
                "if(typeof out!=='object'||out===null)throw new TypeError('out must be an object');"
                "var s=_mbpf_stats;"
                "if(!Array.isArray(out.invocations)||out.invocations.length<2)"
                    "throw new TypeError('out.invocations must be array of length 2');"
                "if(!Array.isArray(out.successes)||out.successes.length<2)"
                    "throw new TypeError('out.successes must be array of length 2');"
                "if(!Array.isArray(out.exceptions)||out.exceptions.length<2)"
                    "throw new TypeError('out.exceptions must be array of length 2');"
                "if(!Array.isArray(out.oom_errors)||out.oom_errors.length<2)"
                    "throw new TypeError('out.oom_errors must be array of length 2');"
                "if(!Array.isArray(out.budget_exceeded)||out.budget_exceeded.length<2)"
                    "throw new TypeError('out.budget_exceeded must be array of length 2');"
                "if(!Array.isArray(out.nested_dropped)||out.nested_dropped.length<2)"
                    "throw new TypeError('out.nested_dropped must be array of length 2');"
                "if(!Array.isArray(out.deferred_dropped)||out.deferred_dropped.length<2)"
                    "throw new TypeError('out.deferred_dropped must be array of length 2');"
                "out.invocations[0]=s.invocations[0];out.invocations[1]=s.invocations[1];"
                "out.successes[0]=s.successes[0];out.successes[1]=s.successes[1];"
                "out.exceptions[0]=s.exceptions[0];out.exceptions[1]=s.exceptions[1];"
                "out.oom_errors[0]=s.oom_errors[0];out.oom_errors[1]=s.oom_errors[1];"
                "out.budget_exceeded[0]=s.budget_exceeded[0];out.budget_exceeded[1]=s.budget_exceeded[1];"
                "out.nested_dropped[0]=s.nested_dropped[0];out.nested_dropped[1]=s.nested_dropped[1];"
                "out.deferred_dropped[0]=s.deferred_dropped[0];out.deferred_dropped[1]=s.deferred_dropped[1];"
            "}"
            : "");

    JSValue result = JS_Eval(ctx, code, strlen(code), "<mbpf>", JS_EVAL_RETVAL);
    if (JS_IsException(result)) {
        JS_GetException(ctx);
        return -1;
    }

    return 0;
}

/*
 * Set up helper budget tracking globals in the JS context.
 * Creates _helperCount, _maxHelpers, and _checkHelper() function.
 * _checkHelper() should be called at the start of each helper function;
 * it increments the count and throws if the budget is exceeded.
 * The instance pointer is stored in the context opaque for the check function.
 */
static int setup_helper_tracking(JSContext *ctx, uint32_t max_helpers) {
    /* If max_helpers is 0, don't enforce limit */
    if (max_helpers == 0) {
        return 0;
    }

    char code[512];
    snprintf(code, sizeof(code),
        "(function(){"
        "globalThis._helperCount=0;"
        "globalThis._maxHelpers=%u;"
        "globalThis._helperBudgetExceeded=false;"
        "globalThis._checkHelper=function(){"
            "if(++_helperCount>_maxHelpers){"
                "_helperBudgetExceeded=true;"
                "throw new Error('helper budget exceeded');"
            "}"
        "};"
        "})()",
        max_helpers);

    JSValue result = JS_Eval(ctx, code, strlen(code), "<helper_tracking>", JS_EVAL_RETVAL);
    if (JS_IsException(result)) {
        JS_GetException(ctx);
        return -1;
    }

    return 0;
}

/*
 * Create the 'maps' global object for a JS context.
 * Each map is exposed as a property with lookup/update methods.
 * For per-CPU maps, instance_idx selects the CPU-local storage.
 * Methods are gated by capabilities:
 *   - CAP_MAP_READ: lookup
 *   - CAP_MAP_WRITE: update, delete
 *   - CAP_MAP_ITERATE: nextKey
 */
static int setup_maps_object(JSContext *ctx, mbpf_program_t *prog, uint32_t instance_idx) {
    if (!prog->maps || prog->map_count == 0) {
        return 0;  /* No maps to set up */
    }

    uint32_t caps = prog->manifest.capabilities;
    int has_cap_read = (caps & MBPF_CAP_MAP_READ) != 0;
    int has_cap_write = (caps & MBPF_CAP_MAP_WRITE) != 0;
    int has_cap_iterate = (caps & MBPF_CAP_MAP_ITERATE) != 0;

    /* Build JS code to create maps object using safe string builder.
     * We generate JS code that creates the maps object with closures
     * that reference internal data arrays by index.
     *
     * The string builder handles dynamic growth if estimates are wrong
     * and prevents underflow from snprintf truncation. */

    /* Estimate initial buffer size - will grow if needed */
    size_t initial_size = 4096;  /* Base size for boilerplate */
    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];
        /* Add extra for map name (up to 256 chars) */
        size_t name_len = strlen(storage->name);
        if (storage->type == MBPF_MAP_TYPE_LRU) {
            initial_size += 8192 + name_len;  /* LRU hash maps need ~8KB for LRU list methods */
        } else if (storage->type == MBPF_MAP_TYPE_RING) {
            initial_size += 4096 + name_len;  /* Ring buffer maps need ~4KB for circular buffer methods */
        } else {
            initial_size += 4096 + name_len;  /* ~4KB per map for methods (hash maps need more) */
        }
    }

    mbpf_strbuf_t sb;
    if (!strbuf_init(&sb, initial_size)) {
        return -1;
    }

    /* Start the setup IIFE with capability check functions */
    strbuf_printf(&sb,
        "(function(){"
        "var ch=function(){if(typeof _checkHelper==='function')_checkHelper();};"
        "var chR=function(){%s};"  /* CAP_MAP_READ check */
        "var chW=function(){%s};"  /* CAP_MAP_WRITE check */
        "var chI=function(){%s};"  /* CAP_MAP_ITERATE check */
        "var maps={};"
        "var _mapData=[];"  /* Will hold arrays for each map */
        "var _mapValid=[];",  /* Will hold validity arrays */
        has_cap_read ? "" : "throw new Error('CAP_MAP_READ required');",
        has_cap_write ? "" : "throw new Error('CAP_MAP_WRITE required');",
        has_cap_iterate ? "" : "throw new Error('CAP_MAP_ITERATE required');");

    /* For each map, add an entry in _mapData and methods */
    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];

        if (storage->type == MBPF_MAP_TYPE_ARRAY) {
            mbpf_array_map_t *arr = &storage->u.array;

            /* Create data array - initially all zeros */
            size_t total_bytes = (size_t)arr->max_entries * arr->value_size;
            strbuf_printf(&sb,
                "_mapData[%u]=new Uint8Array(%zu);"
                "_mapValid[%u]=new Uint8Array(%u);",
                i, total_bytes, i, arr->max_entries);

            /* Create map object with lookup and update methods */
            strbuf_puts(&sb, "maps[");
            strbuf_append_js_string(&sb, storage->name);
            strbuf_printf(&sb,
                "]={"
                "lookup:function(idx,outBuf){"
                    "ch();chR();"
                    "if(typeof idx!=='number')throw new TypeError('index must be a number');"
                    "if(idx<0||idx>=%u)throw new RangeError('index out of bounds');"
                    "if(!(outBuf instanceof Uint8Array))throw new TypeError('outBuffer must be Uint8Array');"
                    "if(outBuf.length<%u)throw new RangeError('outBuffer too small');"
                    "if(!_mapValid[%u][idx])return false;"
                    "var off=idx*%u;"
                    "for(var i=0;i<%u;i++)outBuf[i]=_mapData[%u][off+i];"
                    "return true;"
                "},"
                "update:function(idx,valueBuf){"
                    "ch();chW();"
                    "if(typeof idx!=='number')throw new TypeError('index must be a number');"
                    "if(idx<0||idx>=%u)throw new RangeError('index out of bounds');"
                    "if(!(valueBuf instanceof Uint8Array))throw new TypeError('valueBuffer must be Uint8Array');"
                    "if(valueBuf.length<%u)throw new RangeError('valueBuffer too small');"
                    "var off=idx*%u;"
                    "for(var i=0;i<%u;i++)_mapData[%u][off+i]=valueBuf[i];"
                    "_mapValid[%u][idx]=1;"
                    "return true;"
                "}"
                "};",
                arr->max_entries, arr->value_size,
                i, arr->value_size, arr->value_size, i,
                arr->max_entries, arr->value_size,
                arr->value_size, arr->value_size, i,
                i);
        } else if (storage->type == MBPF_MAP_TYPE_HASH) {
            mbpf_hash_map_t *hash = &storage->u.hash;

            /* Create bucket storage: each bucket is [valid:1][key:key_size][value:value_size]
             * We allocate max_entries buckets and use open addressing with linear probing. */
            size_t bucket_size = 1 + hash->key_size + hash->value_size;
            size_t total_bytes = (size_t)hash->max_entries * bucket_size;

            strbuf_printf(&sb,
                "_mapData[%u]=new Uint8Array(%zu);"
                "_mapValid[%u]={count:0};",  /* Use object to track entry count */
                i, total_bytes, i);

            /* Create hash map object with lookup, update, and delete methods.
             * We implement a simple hash function using FNV-1a and linear probing. */
            strbuf_puts(&sb, "maps[");
            strbuf_append_js_string(&sb, storage->name);
            strbuf_printf(&sb,
                "]=(function(){"
                "var d=_mapData[%u];"
                "var m=_mapValid[%u];"
                "var maxE=%u;"
                "var kS=%u;"
                "var vS=%u;"
                "var bS=%u;"  /* bucket_size = 1 + key_size + value_size */
                /* FNV-1a hash function for Uint8Array keys */
                "function fnv(k){"
                    "var h=2166136261>>>0;"
                    "for(var i=0;i<kS;i++){"
                        "h^=k[i];"
                        "h=Math.imul(h,16777619)>>>0;"
                    "}"
                    "return h;"
                "}"
                /* Compare two keys */
                "function keq(off,k){"
                    "for(var i=0;i<kS;i++){"
                        "if(d[off+1+i]!==k[i])return false;"
                    "}"
                    "return true;"
                "}"
                "return{"
                /* lookup(keyBuffer, outBuffer) - returns true if found, copies value to outBuffer */
                "lookup:function(keyBuf,outBuf){"
                    "ch();chR();"
                    "if(!(keyBuf instanceof Uint8Array))throw new TypeError('key must be Uint8Array');"
                    "if(keyBuf.length<kS)throw new RangeError('key too small');"
                    "if(!(outBuf instanceof Uint8Array))throw new TypeError('outBuffer must be Uint8Array');"
                    "if(outBuf.length<vS)throw new RangeError('outBuffer too small');"
                    "var h=fnv(keyBuf)%%maxE;"
                    "for(var i=0;i<maxE;i++){"
                        "var idx=(h+i)%%maxE;"
                        "var off=idx*bS;"
                        "if(d[off]===0)return false;"  /* Empty slot - not found */
                        "if(d[off]===1&&keq(off,keyBuf)){"  /* Valid entry with matching key */
                            "for(var j=0;j<vS;j++)outBuf[j]=d[off+1+kS+j];"
                            "return true;"
                        "}"
                        /* d[off]===2 means deleted, keep probing */
                    "}"
                    "return false;"
                "},"
                /* update(keyBuffer, valueBuffer) - inserts or updates, returns true on success */
                "update:function(keyBuf,valueBuf){"
                    "ch();chW();"
                    "if(!(keyBuf instanceof Uint8Array))throw new TypeError('key must be Uint8Array');"
                    "if(keyBuf.length<kS)throw new RangeError('key too small');"
                    "if(!(valueBuf instanceof Uint8Array))throw new TypeError('value must be Uint8Array');"
                    "if(valueBuf.length<vS)throw new RangeError('value too small');"
                    "var h=fnv(keyBuf)%%maxE;"
                    "var firstDel=-1;"
                    "for(var i=0;i<maxE;i++){"
                        "var idx=(h+i)%%maxE;"
                        "var off=idx*bS;"
                        "if(d[off]===0){"  /* Empty slot - insert here or at first deleted */
                            "if(firstDel>=0)off=firstDel;"
                            "d[off]=1;"  /* Mark valid */
                            "for(var j=0;j<kS;j++)d[off+1+j]=keyBuf[j];"
                            "for(var j=0;j<vS;j++)d[off+1+kS+j]=valueBuf[j];"
                            "m.count++;"
                            "return true;"
                        "}"
                        "if(d[off]===2&&firstDel<0)firstDel=off;"  /* Remember first deleted slot */
                        "if(d[off]===1&&keq(off,keyBuf)){"  /* Existing key - update value */
                            "for(var j=0;j<vS;j++)d[off+1+kS+j]=valueBuf[j];"
                            "return true;"
                        "}"
                    "}"
                    /* Table full, try using firstDel if available */
                    "if(firstDel>=0){"
                        "d[firstDel]=1;"
                        "for(var j=0;j<kS;j++)d[firstDel+1+j]=keyBuf[j];"
                        "for(var j=0;j<vS;j++)d[firstDel+1+kS+j]=valueBuf[j];"
                        "m.count++;"
                        "return true;"
                    "}"
                    "return false;"  /* Table full */
                "},"
                /* delete(keyBuffer) - removes entry, returns true if found */
                "delete:function(keyBuf){"
                    "ch();chW();"
                    "if(!(keyBuf instanceof Uint8Array))throw new TypeError('key must be Uint8Array');"
                    "if(keyBuf.length<kS)throw new RangeError('key too small');"
                    "var h=fnv(keyBuf)%%maxE;"
                    "for(var i=0;i<maxE;i++){"
                        "var idx=(h+i)%%maxE;"
                        "var off=idx*bS;"
                        "if(d[off]===0)return false;"  /* Empty slot - not found */
                        "if(d[off]===1&&keq(off,keyBuf)){"  /* Found it */
                            "d[off]=2;"  /* Mark as deleted (tombstone) */
                            "m.count--;"
                            "return true;"
                        "}"
                    "}"
                    "return false;"
                "},"
                /* nextKey(prevKey, outKey) - returns next key after prevKey, false if no more */
                "nextKey:function(prevKey,outKey){"
                    "ch();chI();"
                    "if(!(outKey instanceof Uint8Array))throw new TypeError('outKey must be Uint8Array');"
                    "if(outKey.length<kS)throw new RangeError('outKey too small');"
                    "var start=0;"
                    "if(prevKey!==null&&prevKey!==undefined){"
                        "if(!(prevKey instanceof Uint8Array))throw new TypeError('prevKey must be null or Uint8Array');"
                        "if(prevKey.length<kS)throw new RangeError('prevKey too small');"
                        /* Find prevKey's bucket, then start scanning from the next bucket */
                        "var h=fnv(prevKey)%%maxE;"
                        "for(var i=0;i<maxE;i++){"
                            "var idx=(h+i)%%maxE;"
                            "var off=idx*bS;"
                            "if(d[off]===0)break;"  /* prevKey not found (empty slot) */
                            "if(d[off]===1&&keq(off,prevKey)){"
                                "start=idx+1;"  /* Start from bucket after prevKey */
                                "break;"
                            "}"
                        "}"
                    "}"
                    /* Scan from start for next valid entry */
                    "for(var i=start;i<maxE;i++){"
                        "var off=i*bS;"
                        "if(d[off]===1){"  /* Valid entry */
                            "for(var j=0;j<kS;j++)outKey[j]=d[off+1+j];"
                            "return true;"
                        "}"
                    "}"
                    "return false;"  /* No more keys */
                "}"
                "};"
                "})();",
                i, i,
                hash->max_entries,
                hash->key_size,
                hash->value_size,
                (uint32_t)bucket_size);
        } else if (storage->type == MBPF_MAP_TYPE_LRU) {
            mbpf_lru_hash_map_t *lru = &storage->u.lru_hash;

            /* LRU hash map bucket layout: [valid:1][prev:4][next:4][key][value]
             * prev/next are bucket indices for doubly-linked LRU list.
             * 0xFFFFFFFF (stored as 4 bytes) represents null pointer.
             * The list maintains MRU at head, LRU at tail.
             * On lookup: move accessed entry to head (refresh LRU).
             * On insert when full: evict tail (LRU entry), then insert new entry at head.
             */
            size_t bucket_size = 1 + 4 + 4 + lru->key_size + lru->value_size;
            size_t total_bytes = (size_t)lru->max_entries * bucket_size;

            strbuf_printf(&sb,
                "_mapData[%u]=new Uint8Array(%zu);"
                "_mapValid[%u]={count:0,head:0xFFFFFFFF,tail:0xFFFFFFFF};",
                i, total_bytes, i);

            /* Create LRU hash map object with lookup, update, and delete methods.
             * LRU functionality:
             * - lookup: finds entry and moves it to head (refreshes LRU order)
             * - update: inserts/updates entry and moves to head; evicts tail if at capacity
             * - delete: removes entry from hash table and LRU list
             */
            strbuf_puts(&sb, "maps[");
            strbuf_append_js_string(&sb, storage->name);
            strbuf_printf(&sb,
                "]=(function(){"
                "var d=_mapData[%u];"
                "var m=_mapValid[%u];"
                "var maxE=%u;"
                "var kS=%u;"
                "var vS=%u;"
                "var bS=%u;"  /* bucket_size = 1 + 4 + 4 + key_size + value_size */
                "var NULL_IDX=0xFFFFFFFF;"
                /* FNV-1a hash function for Uint8Array keys */
                "function fnv(k){"
                    "var h=2166136261>>>0;"
                    "for(var i=0;i<kS;i++){"
                        "h^=k[i];"
                        "h=Math.imul(h,16777619)>>>0;"
                    "}"
                    "return h;"
                "}"
                /* Read 4-byte little-endian uint32 at offset */
                "function r32(off){"
                    "return (d[off]|(d[off+1]<<8)|(d[off+2]<<16)|(d[off+3]<<24))>>>0;"
                "}"
                /* Write 4-byte little-endian uint32 at offset */
                "function w32(off,v){"
                    "d[off]=v&0xFF;"
                    "d[off+1]=(v>>8)&0xFF;"
                    "d[off+2]=(v>>16)&0xFF;"
                    "d[off+3]=(v>>24)&0xFF;"
                "}"
                /* Get prev index for bucket at off */
                "function gP(off){return r32(off+1);}"
                /* Get next index for bucket at off */
                "function gN(off){return r32(off+5);}"
                /* Set prev index for bucket at off */
                "function sP(off,v){w32(off+1,v);}"
                /* Set next index for bucket at off */
                "function sN(off,v){w32(off+5,v);}"
                /* Compare key at bucket offset with provided key */
                "function keq(off,k){"
                    "for(var i=0;i<kS;i++){"
                        "if(d[off+9+i]!==k[i])return false;"
                    "}"
                    "return true;"
                "}"
                /* Remove entry at bucket index from LRU list (does not clear valid flag) */
                "function lruRemove(idx){"
                    "var off=idx*bS;"
                    "var pr=gP(off);"
                    "var nx=gN(off);"
                    "if(pr!==NULL_IDX){sN(pr*bS,nx);}else{m.head=nx;}"
                    "if(nx!==NULL_IDX){sP(nx*bS,pr);}else{m.tail=pr;}"
                "}"
                /* Add entry at bucket index to head of LRU list */
                "function lruAddHead(idx){"
                    "var off=idx*bS;"
                    "sP(off,NULL_IDX);"
                    "sN(off,m.head);"
                    "if(m.head!==NULL_IDX){sP(m.head*bS,idx);}"
                    "m.head=idx;"
                    "if(m.tail===NULL_IDX){m.tail=idx;}"
                "}"
                /* Move entry at bucket index to head (refresh LRU) */
                "function lruTouch(idx){"
                    "if(m.head===idx)return;"
                    "lruRemove(idx);"
                    "lruAddHead(idx);"
                "}"
                /* Evict tail (LRU) entry, returns the bucket index */
                "function lruEvictTail(){"
                    "var idx=m.tail;"
                    "if(idx===NULL_IDX)return NULL_IDX;"
                    "lruRemove(idx);"
                    "var off=idx*bS;"
                    "d[off]=2;"  /* Mark as tombstone */
                    "m.count--;"
                    "return idx;"
                "}"
                "return{"
                /* lookup(keyBuffer, outBuffer) - returns true if found, copies value to outBuffer */
                "lookup:function(keyBuf,outBuf){"
                    "ch();chR();"
                    "if(!(keyBuf instanceof Uint8Array))throw new TypeError('key must be Uint8Array');"
                    "if(keyBuf.length<kS)throw new RangeError('key too small');"
                    "if(!(outBuf instanceof Uint8Array))throw new TypeError('outBuffer must be Uint8Array');"
                    "if(outBuf.length<vS)throw new RangeError('outBuffer too small');"
                    "var h=fnv(keyBuf)%%maxE;"
                    "for(var i=0;i<maxE;i++){"
                        "var idx=(h+i)%%maxE;"
                        "var off=idx*bS;"
                        "if(d[off]===0)return false;"  /* Empty slot - not found */
                        "if(d[off]===1&&keq(off,keyBuf)){"  /* Valid entry with matching key */
                            "for(var j=0;j<vS;j++)outBuf[j]=d[off+9+kS+j];"
                            "lruTouch(idx);"  /* Move to head (most recently used) */
                            "return true;"
                        "}"
                        /* d[off]===2 means deleted, keep probing */
                    "}"
                    "return false;"
                "},"
                /* update(keyBuffer, valueBuffer) - inserts or updates, returns true on success */
                "update:function(keyBuf,valueBuf){"
                    "ch();chW();"
                    "if(!(keyBuf instanceof Uint8Array))throw new TypeError('key must be Uint8Array');"
                    "if(keyBuf.length<kS)throw new RangeError('key too small');"
                    "if(!(valueBuf instanceof Uint8Array))throw new TypeError('value must be Uint8Array');"
                    "if(valueBuf.length<vS)throw new RangeError('value too small');"
                    "var h=fnv(keyBuf)%%maxE;"
                    "var firstDel=-1;"
                    /* Look for existing key, or empty/deleted slot to insert */
                    "for(var i=0;i<maxE;i++){"
                        "var idx=(h+i)%%maxE;"
                        "var off=idx*bS;"
                        "if(d[off]===0){"  /* Empty slot - insert here */
                            "if(firstDel>=0){off=firstDel;idx=Math.floor(firstDel/bS);}"
                            "d[off]=1;"  /* Mark valid */
                            "for(var j=0;j<kS;j++)d[off+9+j]=keyBuf[j];"
                            "for(var j=0;j<vS;j++)d[off+9+kS+j]=valueBuf[j];"
                            "m.count++;"
                            "lruAddHead(idx);"
                            "return true;"
                        "}"
                        "if(d[off]===2&&firstDel<0)firstDel=off;"  /* Remember first deleted slot */
                        "if(d[off]===1&&keq(off,keyBuf)){"  /* Existing key - update value */
                            "for(var j=0;j<vS;j++)d[off+9+kS+j]=valueBuf[j];"
                            "lruTouch(idx);"  /* Move to head */
                            "return true;"
                        "}"
                    "}"
                    /* Searched all slots. Use firstDel if found */
                    "if(firstDel>=0){"
                        "var idx=Math.floor(firstDel/bS);"
                        "d[firstDel]=1;"
                        "for(var j=0;j<kS;j++)d[firstDel+9+j]=keyBuf[j];"
                        "for(var j=0;j<vS;j++)d[firstDel+9+kS+j]=valueBuf[j];"
                        "m.count++;"
                        "lruAddHead(idx);"
                        "return true;"
                    "}"
                    /* Table full with no empty slots: evict LRU and reuse its slot */
                    "var evicted=lruEvictTail();"
                    "if(evicted===NULL_IDX)return false;"
                    "var off=evicted*bS;"
                    "d[off]=1;"
                    "for(var j=0;j<kS;j++)d[off+9+j]=keyBuf[j];"
                    "for(var j=0;j<vS;j++)d[off+9+kS+j]=valueBuf[j];"
                    "m.count++;"
                    "lruAddHead(evicted);"
                    "return true;"
                "},"
                /* delete(keyBuffer) - removes entry, returns true if found */
                "delete:function(keyBuf){"
                    "ch();chW();"
                    "if(!(keyBuf instanceof Uint8Array))throw new TypeError('key must be Uint8Array');"
                    "if(keyBuf.length<kS)throw new RangeError('key too small');"
                    "var h=fnv(keyBuf)%%maxE;"
                    "for(var i=0;i<maxE;i++){"
                        "var idx=(h+i)%%maxE;"
                        "var off=idx*bS;"
                        "if(d[off]===0)return false;"  /* Empty slot - not found */
                        "if(d[off]===1&&keq(off,keyBuf)){"  /* Found it */
                            "lruRemove(idx);"  /* Remove from LRU list */
                            "d[off]=2;"  /* Mark as deleted (tombstone) */
                            "m.count--;"
                            "return true;"
                        "}"
                    "}"
                    "return false;"
                "},"
                /* nextKey(prevKey, outKey) - returns next key after prevKey, false if no more */
                "nextKey:function(prevKey,outKey){"
                    "ch();chI();"
                    "if(!(outKey instanceof Uint8Array))throw new TypeError('outKey must be Uint8Array');"
                    "if(outKey.length<kS)throw new RangeError('outKey too small');"
                    "var start=0;"
                    "if(prevKey!==null&&prevKey!==undefined){"
                        "if(!(prevKey instanceof Uint8Array))throw new TypeError('prevKey must be null or Uint8Array');"
                        "if(prevKey.length<kS)throw new RangeError('prevKey too small');"
                        /* Find prevKey's bucket, then start scanning from the next bucket */
                        "var h=fnv(prevKey)%%maxE;"
                        "for(var i=0;i<maxE;i++){"
                            "var idx=(h+i)%%maxE;"
                            "var off=idx*bS;"
                            "if(d[off]===0)break;"  /* prevKey not found (empty slot) */
                            "if(d[off]===1&&keq(off,prevKey)){"
                                "start=idx+1;"  /* Start from bucket after prevKey */
                                "break;"
                            "}"
                        "}"
                    "}"
                    /* Scan from start for next valid entry */
                    "for(var i=start;i<maxE;i++){"
                        "var off=i*bS;"
                        "if(d[off]===1){"  /* Valid entry */
                            "for(var j=0;j<kS;j++)outKey[j]=d[off+9+j];"  /* LRU key at offset 9 */
                            "return true;"
                        "}"
                    "}"
                    "return false;"  /* No more keys */
                "}"
                "};"
                "})();",
                i, i,
                lru->max_entries,
                lru->key_size,
                lru->value_size,
                (uint32_t)bucket_size);
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_ARRAY) {
            /* Per-CPU array map: each instance uses its own CPU-local storage */
            mbpf_percpu_array_map_t *pca = &storage->u.percpu_array;

            /* Create data array using this CPU's storage */
            size_t total_bytes = (size_t)pca->max_entries * pca->value_size;
            strbuf_printf(&sb,
                "_mapData[%u]=new Uint8Array(%zu);"
                "_mapValid[%u]=new Uint8Array(%u);",
                i, total_bytes, i, pca->max_entries);

            /* Create map object with lookup, update, and sumAll methods */
            strbuf_puts(&sb, "maps[");
            strbuf_append_js_string(&sb, storage->name);
            strbuf_printf(&sb,
                "]={"
                "lookup:function(idx,outBuf){"
                    "ch();"
                    "if(typeof idx!=='number')throw new TypeError('index must be a number');"
                    "if(idx<0||idx>=%u)throw new RangeError('index out of bounds');"
                    "if(!(outBuf instanceof Uint8Array))throw new TypeError('outBuffer must be Uint8Array');"
                    "if(outBuf.length<%u)throw new RangeError('outBuffer too small');"
                    "if(!_mapValid[%u][idx])return false;"
                    "var off=idx*%u;"
                    "for(var i=0;i<%u;i++)outBuf[i]=_mapData[%u][off+i];"
                    "return true;"
                "},"
                "update:function(idx,valueBuf){"
                    "ch();"
                    "if(typeof idx!=='number')throw new TypeError('index must be a number');"
                    "if(idx<0||idx>=%u)throw new RangeError('index out of bounds');"
                    "if(!(valueBuf instanceof Uint8Array))throw new TypeError('valueBuffer must be Uint8Array');"
                    "if(valueBuf.length<%u)throw new RangeError('valueBuffer too small');"
                    "var off=idx*%u;"
                    "for(var i=0;i<%u;i++)_mapData[%u][off+i]=valueBuf[i];"
                    "_mapValid[%u][idx]=1;"
                    "return true;"
                "},"
                "cpuId:function(){ch();return %u;}"  /* Returns this instance's CPU ID */
                "};",
                pca->max_entries, pca->value_size,
                i, pca->value_size, pca->value_size, i,
                pca->max_entries, pca->value_size,
                pca->value_size, pca->value_size, i,
                i,
                instance_idx);
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_HASH) {
            /* Per-CPU hash map: each instance uses its own CPU-local storage */
            mbpf_percpu_hash_map_t *pch = &storage->u.percpu_hash;

            size_t bucket_size = 1 + pch->key_size + pch->value_size;
            size_t total_bytes = (size_t)pch->max_entries * bucket_size;

            strbuf_printf(&sb,
                "_mapData[%u]=new Uint8Array(%zu);"
                "_mapValid[%u]={count:0};",
                i, total_bytes, i);

            /* Create hash map object with lookup, update, delete, and cpuId methods */
            strbuf_puts(&sb, "maps[");
            strbuf_append_js_string(&sb, storage->name);
            strbuf_printf(&sb,
                "]=(function(){"
                "var d=_mapData[%u];"
                "var m=_mapValid[%u];"
                "var maxE=%u;"
                "var kS=%u;"
                "var vS=%u;"
                "var bS=%u;"
                "function fnv(k){"
                    "var h=2166136261>>>0;"
                    "for(var i=0;i<kS;i++){"
                        "h^=k[i];"
                        "h=Math.imul(h,16777619)>>>0;"
                    "}"
                    "return h;"
                "}"
                "function keq(off,k){"
                    "for(var i=0;i<kS;i++){"
                        "if(d[off+1+i]!==k[i])return false;"
                    "}"
                    "return true;"
                "}"
                "return{"
                "lookup:function(keyBuf,outBuf){"
                    "ch();chR();"
                    "if(!(keyBuf instanceof Uint8Array))throw new TypeError('key must be Uint8Array');"
                    "if(keyBuf.length<kS)throw new RangeError('key too small');"
                    "if(!(outBuf instanceof Uint8Array))throw new TypeError('outBuffer must be Uint8Array');"
                    "if(outBuf.length<vS)throw new RangeError('outBuffer too small');"
                    "var h=fnv(keyBuf)%%maxE;"
                    "for(var i=0;i<maxE;i++){"
                        "var idx=(h+i)%%maxE;"
                        "var off=idx*bS;"
                        "if(d[off]===0)return false;"
                        "if(d[off]===1&&keq(off,keyBuf)){"
                            "for(var j=0;j<vS;j++)outBuf[j]=d[off+1+kS+j];"
                            "return true;"
                        "}"
                    "}"
                    "return false;"
                "},"
                "update:function(keyBuf,valueBuf){"
                    "ch();chW();"
                    "if(!(keyBuf instanceof Uint8Array))throw new TypeError('key must be Uint8Array');"
                    "if(keyBuf.length<kS)throw new RangeError('key too small');"
                    "if(!(valueBuf instanceof Uint8Array))throw new TypeError('value must be Uint8Array');"
                    "if(valueBuf.length<vS)throw new RangeError('value too small');"
                    "var h=fnv(keyBuf)%%maxE;"
                    "var firstDel=-1;"
                    "for(var i=0;i<maxE;i++){"
                        "var idx=(h+i)%%maxE;"
                        "var off=idx*bS;"
                        "if(d[off]===0){"
                            "if(firstDel>=0)off=firstDel;"
                            "d[off]=1;"
                            "for(var j=0;j<kS;j++)d[off+1+j]=keyBuf[j];"
                            "for(var j=0;j<vS;j++)d[off+1+kS+j]=valueBuf[j];"
                            "m.count++;"
                            "return true;"
                        "}"
                        "if(d[off]===2&&firstDel<0)firstDel=off;"
                        "if(d[off]===1&&keq(off,keyBuf)){"
                            "for(var j=0;j<vS;j++)d[off+1+kS+j]=valueBuf[j];"
                            "return true;"
                        "}"
                    "}"
                    "if(firstDel>=0){"
                        "d[firstDel]=1;"
                        "for(var j=0;j<kS;j++)d[firstDel+1+j]=keyBuf[j];"
                        "for(var j=0;j<vS;j++)d[firstDel+1+kS+j]=valueBuf[j];"
                        "m.count++;"
                        "return true;"
                    "}"
                    "return false;"
                "},"
                "delete:function(keyBuf){"
                    "ch();chW();"
                    "if(!(keyBuf instanceof Uint8Array))throw new TypeError('key must be Uint8Array');"
                    "if(keyBuf.length<kS)throw new RangeError('key too small');"
                    "var h=fnv(keyBuf)%%maxE;"
                    "for(var i=0;i<maxE;i++){"
                        "var idx=(h+i)%%maxE;"
                        "var off=idx*bS;"
                        "if(d[off]===0)return false;"
                        "if(d[off]===1&&keq(off,keyBuf)){"
                            "d[off]=2;"
                            "m.count--;"
                            "return true;"
                        "}"
                    "}"
                    "return false;"
                "},"
                /* nextKey(prevKey, outKey) - returns next key after prevKey, false if no more */
                "nextKey:function(prevKey,outKey){"
                    "ch();chI();"
                    "if(!(outKey instanceof Uint8Array))throw new TypeError('outKey must be Uint8Array');"
                    "if(outKey.length<kS)throw new RangeError('outKey too small');"
                    "var start=0;"
                    "if(prevKey!==null&&prevKey!==undefined){"
                        "if(!(prevKey instanceof Uint8Array))throw new TypeError('prevKey must be null or Uint8Array');"
                        "if(prevKey.length<kS)throw new RangeError('prevKey too small');"
                        "var h=fnv(prevKey)%%maxE;"
                        "for(var i=0;i<maxE;i++){"
                            "var idx=(h+i)%%maxE;"
                            "var off=idx*bS;"
                            "if(d[off]===0)break;"
                            "if(d[off]===1&&keq(off,prevKey)){"
                                "start=idx+1;"
                                "break;"
                            "}"
                        "}"
                    "}"
                    "for(var i=start;i<maxE;i++){"
                        "var off=i*bS;"
                        "if(d[off]===1){"
                            "for(var j=0;j<kS;j++)outKey[j]=d[off+1+j];"
                            "return true;"
                        "}"
                    "}"
                    "return false;"
                "},"
                "cpuId:function(){ch();return %u;}"
                "};"
                "})();",
                i, i,
                pch->max_entries,
                pch->key_size,
                pch->value_size,
                (uint32_t)bucket_size,
                instance_idx);
        } else if (storage->type == MBPF_MAP_TYPE_RING) {
            /* Ring buffer map for event output.
             * Provides submit() method to write events.
             * Events are stored as [length:4][data:length] records.
             * When buffer is full, oldest events are dropped. */
            mbpf_ring_buffer_map_t *ring = &storage->u.ring;

            /* Create ring buffer storage as a Uint8Array and metadata object */
            strbuf_printf(&sb,
                "_mapData[%u]=new Uint8Array(%u);"
                "_mapValid[%u]={head:0,tail:0,dropped:0,eventCount:0,bufSize:%u};",
                i, ring->buffer_size, i, ring->buffer_size);

            /* Create ring buffer object with submit method.
             * submit(eventData) writes an event to the ring buffer.
             * Returns true on success, false if event is too large.
             * On overflow, oldest events are dropped to make room. */
            strbuf_puts(&sb, "maps[");
            strbuf_append_js_string(&sb, storage->name);
            strbuf_printf(&sb,
                "]=(function(){"
                "var d=_mapData[%u];"
                "var m=_mapValid[%u];"
                "var bufSize=%u;"
                "var maxEventSize=%u;"
                /* Calculate bytes used in ring buffer */
                "function bytesUsed(){"
                    "if(m.head>=m.tail)return m.head-m.tail;"
                    "return bufSize-m.tail+m.head;"
                "}"
                /* Read 4-byte little-endian uint32 at offset with wrap-around */
                "function r32(off){"
                    "return (d[off%%bufSize]|(d[(off+1)%%bufSize]<<8)|(d[(off+2)%%bufSize]<<16)|(d[(off+3)%%bufSize]<<24))>>>0;"
                "}"
                /* Write 4-byte little-endian uint32 at offset with wrap-around */
                "function w32(off,v){"
                    "d[off%%bufSize]=v&0xFF;"
                    "d[(off+1)%%bufSize]=(v>>8)&0xFF;"
                    "d[(off+2)%%bufSize]=(v>>16)&0xFF;"
                    "d[(off+3)%%bufSize]=(v>>24)&0xFF;"
                "}"
                /* Drop oldest event from buffer */
                "function dropOldest(){"
                    "if(m.eventCount===0)return false;"
                    "var len=r32(m.tail);"
                    "var recordSize=4+len;"
                    "m.tail=(m.tail+recordSize)%%bufSize;"
                    "m.eventCount--;"
                    "m.dropped++;"
                    "return true;"
                "}"
                "return{"
                /* submit(eventData) - write event to ring buffer */
                "submit:function(eventData){"
                    "ch();chW();"
                    "if(!(eventData instanceof Uint8Array))throw new TypeError('eventData must be Uint8Array');"
                    "var len=eventData.length;"
                    /* Check if event exceeds max event size (manifest value_size) */
                    "if(len>maxEventSize)return false;"
                    "var recordSize=4+len;"  /* 4 bytes for length + data */
                    /* Check if record is too large for buffer (need recordSize+1 to fit) */
                    "if(recordSize+1>bufSize)return false;"
                    /* Drop oldest events until there's enough room */
                    "while(bufSize-bytesUsed()<recordSize+1){"
                        "if(!dropOldest())break;"
                    "}"
                    /* Write length header (4 bytes, little-endian) */
                    "w32(m.head,len);"
                    /* Write event data byte by byte with wrap-around */
                    "var dataStart=(m.head+4)%%bufSize;"
                    "for(var i=0;i<len;i++){"
                        "d[(dataStart+i)%%bufSize]=eventData[i];"
                    "}"
                    /* Update head pointer */
                    "m.head=(m.head+recordSize)%%bufSize;"
                    "m.eventCount++;"
                    "return true;"
                "},"
                /* count() - return number of events in buffer */
                "count:function(){ch();chR();return m.eventCount;},"
                /* dropped() - return number of dropped events */
                "dropped:function(){ch();chR();return m.dropped;},"
                /* peek(outBuffer) - read oldest event without removing */
                "peek:function(outBuf){"
                    "ch();chR();"
                    "if(!(outBuf instanceof Uint8Array))throw new TypeError('outBuffer must be Uint8Array');"
                    "if(m.eventCount===0)return 0;"
                    "var len=r32(m.tail);"
                    "var copyLen=len<outBuf.length?len:outBuf.length;"
                    "var dataStart=(m.tail+4)%%bufSize;"
                    "for(var i=0;i<copyLen;i++){"
                        "outBuf[i]=d[(dataStart+i)%%bufSize];"
                    "}"
                    "return len;"  /* Return actual event length */
                "},"
                /* consume() - remove oldest event */
                "consume:function(){"
                    "ch();chW();"
                    "if(m.eventCount===0)return false;"
                    "var len=r32(m.tail);"
                    "var recordSize=4+len;"
                    "m.tail=(m.tail+recordSize)%%bufSize;"
                    "m.eventCount--;"
                    "return true;"
                "}"
                "};"
                "})();",
                i, i,
                ring->buffer_size,
                ring->max_event_size);
        } else if (storage->type == MBPF_MAP_TYPE_COUNTER) {
            /* Counter map for 64-bit counters with atomic operations.
             * Uses two arrays:
             *   - hi[]: high 32 bits of each counter (as Int32Array)
             *   - lo[]: low 32 bits of each counter (as Uint32Array)
             *   - dhi[]/dlo[]: accumulated deltas to apply atomically after run
             *
             * The actual counter values are stored in C and synced before/after runs.
             * This ensures atomic operations when multiple instances access the same counter. */
            mbpf_counter_map_t *ctr = &storage->u.counter;

            /* Create counter storage with high/low arrays and delta tracking */
            strbuf_printf(&sb,
                "_mapData[%u]={hi:new Int32Array(%u),lo:new Uint32Array(%u),"
                "dhi:new Int32Array(%u),dlo:new Int32Array(%u),sets:[]};"
                "_mapValid[%u]=%u;",
                i, ctr->max_entries, ctr->max_entries,
                ctr->max_entries, ctr->max_entries,
                i, ctr->max_entries);

            /* Create counter map object with add, get, set methods.
             * add() accumulates delta for atomic application after run.
             * get() returns current value + accumulated delta.
             * set() records the new value for post-run assignment. */
            strbuf_puts(&sb, "maps[");
            strbuf_append_js_string(&sb, storage->name);
            strbuf_printf(&sb,
                "]=(function(){"
                "var d=_mapData[%u];"
                "var max=%u;"
                /* Helper: convert 64-bit to hi/lo parts */
                "function split64(v,hi,lo,idx){"
                    "if(v>=0){"
                        "hi[idx]=Math.floor(v/0x100000000)|0;"
                        "lo[idx]=(v-hi[idx]*0x100000000)|0;"
                    "}else{"
                        "hi[idx]=Math.ceil(v/0x100000000)-1|0;"
                        "lo[idx]=((v-hi[idx]*0x100000000)|0)>>>0;"
                    "}"
                "}"
                /* Helper: combine hi/lo to 64-bit value */
                "function combine64(hi,lo,idx){"
                    "return hi[idx]*0x100000000+(lo[idx]>>>0);"
                "}"
                "return{"
                /* add(idx, delta) - accumulate delta for atomic add after run */
                "add:function(idx,delta){"
                    "ch();chW();"
                    "if(typeof idx!=='number'||idx<0||idx>=max)throw new RangeError('index out of bounds');"
                    "idx=idx>>>0;"
                    /* Get current accumulated delta and add the new delta */
                    "var curDelta=combine64(d.dhi,d.dlo,idx);"
                    "var newDelta=curDelta+delta;"
                    /* Split back to hi/lo representation */
                    "split64(newDelta,d.dhi,d.dlo,idx);"
                    "return true;"
                "},"
                /* get(idx) - get current counter value (base + pending delta) */
                "get:function(idx){"
                    "ch();chR();"
                    "if(typeof idx!=='number'||idx<0||idx>=max)throw new RangeError('index out of bounds');"
                    "idx=idx>>>0;"
                    /* Combine base value with pending delta */
                    "var base=combine64(d.hi,d.lo,idx);"
                    "var delta=combine64(d.dhi,d.dlo,idx);"
                    "return base+delta;"
                "},"
                /* set(idx, value) - record value for post-run assignment */
                "set:function(idx,value){"
                    "ch();chW();"
                    "if(typeof idx!=='number'||idx<0||idx>=max)throw new RangeError('index out of bounds');"
                    "idx=idx>>>0;"
                    /* Record set operation (will be applied atomically) */
                    "d.sets.push({i:idx,v:value});"
                    /* Also update local view */
                    "split64(value,d.hi,d.lo,idx);"
                    /* Clear any pending delta for this index */
                    "d.dhi[idx]=0;"
                    "d.dlo[idx]=0;"
                    "return true;"
                "}"
                "};"
                "})();",
                i,
                ctr->max_entries);
        }
    }

    /* Set global maps object, map data and close IIFE.
     * Note: _mapData and _mapValid are exposed globally to allow host-side
     * access for ring buffer sync. */
    strbuf_printf(&sb,
        "globalThis.maps=maps;"
        "globalThis._mapData=_mapData;"
        "globalThis._mapValid=_mapValid;"
        "})()");

    /* Check for string builder errors */
    if (sb.error) {
        strbuf_free(&sb);
        return -1;
    }

    /* Evaluate the code to set up maps */
    JSValue result = JS_Eval(ctx, sb.buf, sb.len, "<maps>", JS_EVAL_RETVAL);
    strbuf_free(&sb);

    if (JS_IsException(result)) {
        JS_GetException(ctx);
        return -1;
    }

    return 0;
}

/*
 * Set up low-level map helper functions on the mbpf object.
 * Provides mbpf.mapLookup, mbpf.mapUpdate, mbpf.mapDelete as alternatives
 * to the maps object, allowing access by numeric map ID instead of name.
 *
 * Must be called after setup_maps_object since it relies on _mapData and _mapValid.
 */
static int setup_lowlevel_map_helpers(JSContext *ctx, mbpf_program_t *prog) {
    if (!prog->maps || prog->map_count == 0) {
        return 0;  /* No maps, no helpers needed */
    }

    /* Estimate initial code size - string builder will grow if needed.
     * ~8KB base for helper code + ~256 bytes per map for metadata */
    size_t initial_size = 12288 + prog->map_count * 256;

    mbpf_strbuf_t sb;
    if (!strbuf_init(&sb, initial_size)) {
        return -1;
    }

    /* Create _mapMeta array with metadata for each map.
     * Each entry: {type, keySize, valueSize, maxEntries, bucketSize}
     * - type: 1=array, 2=hash, 3=lru, 5=ring, 6=counter, 7=percpu_array, 8=percpu_hash
     * - keySize: for hash/lru, 0 for array
     * - valueSize: size of value in bytes
     * - maxEntries: maximum number of entries
     * - bucketSize: for hash/lru, total size of one bucket entry */
    strbuf_printf(&sb,
        "(function(){"
        "globalThis._mapMeta=[");

    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];
        uint32_t type = storage->type;
        uint32_t key_size = 0;
        uint32_t value_size = 0;
        uint32_t max_entries = 0;
        uint32_t bucket_size = 0;

        switch (storage->type) {
            case MBPF_MAP_TYPE_ARRAY:
                value_size = storage->u.array.value_size;
                max_entries = storage->u.array.max_entries;
                break;
            case MBPF_MAP_TYPE_HASH:
                key_size = storage->u.hash.key_size;
                value_size = storage->u.hash.value_size;
                max_entries = storage->u.hash.max_entries;
                bucket_size = 1 + key_size + value_size;
                break;
            case MBPF_MAP_TYPE_LRU:
                key_size = storage->u.lru_hash.key_size;
                value_size = storage->u.lru_hash.value_size;
                max_entries = storage->u.lru_hash.max_entries;
                bucket_size = 1 + 4 + 4 + key_size + value_size;  /* valid + prev + next + key + value */
                break;
            case MBPF_MAP_TYPE_PERCPU_ARRAY:
                value_size = storage->u.percpu_array.value_size;
                max_entries = storage->u.percpu_array.max_entries;
                break;
            case MBPF_MAP_TYPE_PERCPU_HASH:
                key_size = storage->u.percpu_hash.key_size;
                value_size = storage->u.percpu_hash.value_size;
                max_entries = storage->u.percpu_hash.max_entries;
                bucket_size = 1 + key_size + value_size;
                break;
            default:
                /* Ring buffer and counter maps don't support standard lookup/update/delete */
                break;
        }

        strbuf_printf(&sb, "%s{t:%u,kS:%u,vS:%u,mE:%u,bS:%u}",
            i > 0 ? "," : "", type, key_size, value_size, max_entries, bucket_size);
    }

    /* Close _mapMeta array and add helper functions to mbpf object */
    strbuf_printf(&sb,
        "];"
        /* FNV-1a hash function for Uint8Array keys */
        "function _fnv(k,kS){"
            "var h=2166136261>>>0;"
            "for(var i=0;i<kS;i++){h^=k[i];h=Math.imul(h,16777619)>>>0;}"
            "return h;"
        "}"
        /* Compare key in bucket data with key buffer */
        "function _keq(d,off,k,kS){"
            "for(var i=0;i<kS;i++)if(d[off+i]!==k[i])return false;"
            "return true;"
        "}"
        /* LRU helper: read 32-bit LE uint at offset */
        "function _r32(d,off){"
            "return (d[off]|(d[off+1]<<8)|(d[off+2]<<16)|(d[off+3]<<24))>>>0;"
        "}"
        /* LRU helper: write 32-bit LE uint at offset */
        "function _w32(d,off,val){"
            "d[off]=val&0xFF;"
            "d[off+1]=(val>>8)&0xFF;"
            "d[off+2]=(val>>16)&0xFF;"
            "d[off+3]=(val>>24)&0xFF;"
        "}"
        /* LRU helper: get prev index at bucket offset */
        "function _gP(d,off){return _r32(d,off+1);}"
        /* LRU helper: get next index at bucket offset */
        "function _gN(d,off){return _r32(d,off+5);}"
        /* LRU helper: set prev index at bucket offset */
        "function _sP(d,off,val){_w32(d,off+1,val);}"
        /* LRU helper: set next index at bucket offset */
        "function _sN(d,off,val){_w32(d,off+5,val);}"
        /* LRU helper: remove entry at bucket index from LRU list */
        "function _lruRemove(d,v,idx,bS){"
            "var NULL_IDX=0xFFFFFFFF;"
            "var off=idx*bS;"
            "var pr=_gP(d,off);"
            "var nx=_gN(d,off);"
            "if(pr!==NULL_IDX){_sN(d,pr*bS,nx);}else{v.head=nx;}"
            "if(nx!==NULL_IDX){_sP(d,nx*bS,pr);}else{v.tail=pr;}"
        "}"
        /* LRU helper: add entry at bucket index to head of LRU list */
        "function _lruAddHead(d,v,idx,bS){"
            "var NULL_IDX=0xFFFFFFFF;"
            "var off=idx*bS;"
            "_sP(d,off,NULL_IDX);"
            "_sN(d,off,v.head);"
            "if(v.head!==NULL_IDX){_sP(d,v.head*bS,idx);}"
            "v.head=idx;"
            "if(v.tail===NULL_IDX){v.tail=idx;}"
        "}"
        /* LRU helper: move entry at bucket index to head (refresh LRU) */
        "function _lruTouch(d,v,idx,bS){"
            "if(v.head===idx)return;"
            "_lruRemove(d,v,idx,bS);"
            "_lruAddHead(d,v,idx,bS);"
        "}"
        /* LRU helper: evict tail (LRU) entry, returns bucket index */
        "function _lruEvictTail(d,v,bS){"
            "var NULL_IDX=0xFFFFFFFF;"
            "var idx=v.tail;"
            "if(idx===NULL_IDX)return NULL_IDX;"
            "_lruRemove(d,v,idx,bS);"
            "var off=idx*bS;"
            "d[off]=2;"  /* Mark as tombstone */
            "v.count--;"
            "return idx;"
        "}"
        /* mapLookup(mapId, keyBytes, outValueBytes)
         * For array maps: keyBytes is ignored, use first element as index
         * For hash/lru maps: keyBytes is the key to look up */
        "mbpf.mapLookup=function(mapId,keyBytes,outValue){"
            "ch();chR();"
            "if(typeof mapId!=='number')throw new TypeError('mapId must be a number');"
            "if(mapId<0||mapId>=_mapMeta.length)throw new RangeError('mapId out of range');"
            "var m=_mapMeta[mapId],d=_mapData[mapId],v=_mapValid[mapId];"
            "if(!(outValue instanceof Uint8Array))throw new TypeError('outValue must be Uint8Array');"
            "if(outValue.length<m.vS)throw new RangeError('outValue too small');"
            /* Array map (type 1 or 7) */
            "if(m.t===1||m.t===7){"
                "if(typeof keyBytes!=='number')throw new TypeError('array map requires numeric index');"
                "var idx=keyBytes;"
                "if(idx<0||idx>=m.mE)throw new RangeError('index out of bounds');"
                "if(!v[idx])return false;"
                "var off=idx*m.vS;"
                "for(var i=0;i<m.vS;i++)outValue[i]=d[off+i];"
                "return true;"
            "}"
            /* Hash map (type 2 or 8) */
            "if(m.t===2||m.t===8){"
                "if(!(keyBytes instanceof Uint8Array))throw new TypeError('hash map requires Uint8Array key');"
                "if(keyBytes.length<m.kS)throw new RangeError('key too small');"
                "var h=_fnv(keyBytes,m.kS)%%m.mE;"
                "for(var i=0;i<m.mE;i++){"
                    "var idx=(h+i)%%m.mE,off=idx*m.bS;"
                    "if(d[off]===0)return false;"
                    "if(d[off]===1&&_keq(d,off+1,keyBytes,m.kS)){"
                        "for(var j=0;j<m.vS;j++)outValue[j]=d[off+1+m.kS+j];"
                        "return true;"
                    "}"
                "}"
                "return false;"
            "}"
            /* LRU hash map (type 3) - lookup also refreshes LRU */
            "if(m.t===3){"
                "if(!(keyBytes instanceof Uint8Array))throw new TypeError('lru map requires Uint8Array key');"
                "if(keyBytes.length<m.kS)throw new RangeError('key too small');"
                "var h=_fnv(keyBytes,m.kS)%%m.mE;"
                "for(var i=0;i<m.mE;i++){"
                    "var idx=(h+i)%%m.mE,off=idx*m.bS;"
                    "if(d[off]===0)return false;"
                    "if(d[off]===1&&_keq(d,off+9,keyBytes,m.kS)){"
                        "for(var j=0;j<m.vS;j++)outValue[j]=d[off+9+m.kS+j];"
                        "_lruTouch(d,v,idx,m.bS);"  /* Move to head (most recently used) */
                        "return true;"
                    "}"
                "}"
                "return false;"
            "}"
            "throw new Error('unsupported map type for mapLookup');"
        "};"
        /* mapUpdate(mapId, keyBytes, valueBytes, flags)
         * flags: 0=create or update, 1=create only, 2=update only */
        "mbpf.mapUpdate=function(mapId,keyBytes,valueBytes,flags){"
            "ch();chW();"
            "if(typeof mapId!=='number')throw new TypeError('mapId must be a number');"
            "if(mapId<0||mapId>=_mapMeta.length)throw new RangeError('mapId out of range');"
            "flags=flags||0;"
            "var m=_mapMeta[mapId],d=_mapData[mapId],v=_mapValid[mapId];"
            "if(!(valueBytes instanceof Uint8Array))throw new TypeError('valueBytes must be Uint8Array');"
            "if(valueBytes.length<m.vS)throw new RangeError('valueBytes too small');"
            /* Array map (type 1 or 7) */
            "if(m.t===1||m.t===7){"
                "if(typeof keyBytes!=='number')throw new TypeError('array map requires numeric index');"
                "var idx=keyBytes;"
                "if(idx<0||idx>=m.mE)throw new RangeError('index out of bounds');"
                "if(flags===1&&v[idx])return false;"  /* Create only but exists */
                "if(flags===2&&!v[idx])return false;"  /* Update only but doesn't exist */
                "var off=idx*m.vS;"
                "for(var i=0;i<m.vS;i++)d[off+i]=valueBytes[i];"
                "v[idx]=1;"
                "return true;"
            "}"
            /* Hash map (type 2 or 8) */
            "if(m.t===2||m.t===8){"
                "if(!(keyBytes instanceof Uint8Array))throw new TypeError('hash map requires Uint8Array key');"
                "if(keyBytes.length<m.kS)throw new RangeError('key too small');"
                "var h=_fnv(keyBytes,m.kS)%%m.mE,firstDel=-1;"
                "for(var i=0;i<m.mE;i++){"
                    "var idx=(h+i)%%m.mE,off=idx*m.bS;"
                    "if(d[off]===0){"  /* Empty slot */
                        "if(flags===2)return false;"  /* Update only */
                        "if(firstDel>=0)off=firstDel;"
                        "d[off]=1;"
                        "for(var j=0;j<m.kS;j++)d[off+1+j]=keyBytes[j];"
                        "for(var j=0;j<m.vS;j++)d[off+1+m.kS+j]=valueBytes[j];"
                        "v.count++;"
                        "return true;"
                    "}"
                    "if(d[off]===2&&firstDel<0)firstDel=off;"
                    "if(d[off]===1&&_keq(d,off+1,keyBytes,m.kS)){"
                        "if(flags===1)return false;"  /* Create only but exists */
                        "for(var j=0;j<m.vS;j++)d[off+1+m.kS+j]=valueBytes[j];"
                        "return true;"
                    "}"
                "}"
                "if(firstDel>=0&&flags!==2){"
                    "d[firstDel]=1;"
                    "for(var j=0;j<m.kS;j++)d[firstDel+1+j]=keyBytes[j];"
                    "for(var j=0;j<m.vS;j++)d[firstDel+1+m.kS+j]=valueBytes[j];"
                    "v.count++;"
                    "return true;"
                "}"
                "return false;"
            "}"
            /* LRU hash map (type 3) - full LRU list maintenance with eviction */
            "if(m.t===3){"
                "if(!(keyBytes instanceof Uint8Array))throw new TypeError('lru map requires Uint8Array key');"
                "if(keyBytes.length<m.kS)throw new RangeError('key too small');"
                "var h=_fnv(keyBytes,m.kS)%%m.mE,firstDel=-1;"
                "for(var i=0;i<m.mE;i++){"
                    "var idx=(h+i)%%m.mE,off=idx*m.bS;"
                    "if(d[off]===0){"  /* Empty slot - insert here */
                        "if(flags===2)return false;"  /* Update only */
                        "if(firstDel>=0){off=firstDel;idx=Math.floor(firstDel/m.bS);}"
                        "d[off]=1;"
                        "for(var j=0;j<m.kS;j++)d[off+9+j]=keyBytes[j];"
                        "for(var j=0;j<m.vS;j++)d[off+9+m.kS+j]=valueBytes[j];"
                        "v.count++;"
                        "_lruAddHead(d,v,idx,m.bS);"
                        "return true;"
                    "}"
                    "if(d[off]===2&&firstDel<0)firstDel=off;"
                    "if(d[off]===1&&_keq(d,off+9,keyBytes,m.kS)){"  /* Existing key - update */
                        "if(flags===1)return false;"  /* Create only but exists */
                        "for(var j=0;j<m.vS;j++)d[off+9+m.kS+j]=valueBytes[j];"
                        "_lruTouch(d,v,idx,m.bS);"  /* Move to head */
                        "return true;"
                    "}"
                "}"
                /* Searched all slots. Use firstDel if found */
                "if(firstDel>=0&&flags!==2){"
                    "var idx=Math.floor(firstDel/m.bS);"
                    "d[firstDel]=1;"
                    "for(var j=0;j<m.kS;j++)d[firstDel+9+j]=keyBytes[j];"
                    "for(var j=0;j<m.vS;j++)d[firstDel+9+m.kS+j]=valueBytes[j];"
                    "v.count++;"
                    "_lruAddHead(d,v,idx,m.bS);"
                    "return true;"
                "}"
                /* Table full with no empty/deleted slots: evict LRU and reuse */
                "if(flags===2)return false;"  /* Update only - can't evict */
                "var evicted=_lruEvictTail(d,v,m.bS);"
                "if(evicted===0xFFFFFFFF)return false;"
                "var off=evicted*m.bS;"
                "d[off]=1;"
                "for(var j=0;j<m.kS;j++)d[off+9+j]=keyBytes[j];"
                "for(var j=0;j<m.vS;j++)d[off+9+m.kS+j]=valueBytes[j];"
                "v.count++;"
                "_lruAddHead(d,v,evicted,m.bS);"
                "return true;"
            "}"
            "throw new Error('unsupported map type for mapUpdate');"
        "};"
        /* mapDelete(mapId, keyBytes)
         * For array maps: keyBytes is numeric index
         * For hash/lru maps: keyBytes is the key to delete */
        "mbpf.mapDelete=function(mapId,keyBytes){"
            "ch();chW();"
            "if(typeof mapId!=='number')throw new TypeError('mapId must be a number');"
            "if(mapId<0||mapId>=_mapMeta.length)throw new RangeError('mapId out of range');"
            "var m=_mapMeta[mapId],d=_mapData[mapId],v=_mapValid[mapId];"
            /* Array map (type 1 or 7) */
            "if(m.t===1||m.t===7){"
                "if(typeof keyBytes!=='number')throw new TypeError('array map requires numeric index');"
                "var idx=keyBytes;"
                "if(idx<0||idx>=m.mE)throw new RangeError('index out of bounds');"
                "if(!v[idx])return false;"
                "v[idx]=0;"
                "return true;"
            "}"
            /* Hash map (type 2 or 8) */
            "if(m.t===2||m.t===8){"
                "if(!(keyBytes instanceof Uint8Array))throw new TypeError('hash map requires Uint8Array key');"
                "if(keyBytes.length<m.kS)throw new RangeError('key too small');"
                "var h=_fnv(keyBytes,m.kS)%%m.mE;"
                "for(var i=0;i<m.mE;i++){"
                    "var idx=(h+i)%%m.mE,off=idx*m.bS;"
                    "if(d[off]===0)return false;"
                    "if(d[off]===1&&_keq(d,off+1,keyBytes,m.kS)){"
                        "d[off]=2;"  /* Mark as tombstone */
                        "v.count--;"
                        "return true;"
                    "}"
                "}"
                "return false;"
            "}"
            /* LRU hash map (type 3) - remove from LRU list before marking tombstone */
            "if(m.t===3){"
                "if(!(keyBytes instanceof Uint8Array))throw new TypeError('lru map requires Uint8Array key');"
                "if(keyBytes.length<m.kS)throw new RangeError('key too small');"
                "var h=_fnv(keyBytes,m.kS)%%m.mE;"
                "for(var i=0;i<m.mE;i++){"
                    "var idx=(h+i)%%m.mE,off=idx*m.bS;"
                    "if(d[off]===0)return false;"
                    "if(d[off]===1&&_keq(d,off+9,keyBytes,m.kS)){"
                        "_lruRemove(d,v,idx,m.bS);"  /* Remove from LRU list */
                        "d[off]=2;"  /* Mark as tombstone */
                        "v.count--;"
                        "return true;"
                    "}"
                "}"
                "return false;"
            "}"
            "throw new Error('unsupported map type for mapDelete');"
        "};"
        "})()");

    /* Check for string builder errors */
    if (sb.error) {
        strbuf_free(&sb);
        return -1;
    }

    JSValue result = JS_Eval(ctx, sb.buf, sb.len, "<map_helpers>", JS_EVAL_RETVAL);
    strbuf_free(&sb);

    if (JS_IsException(result)) {
        JS_GetException(ctx);
        return -1;
    }

    return 0;
}

/*
 * Get the exception default for a hook type, using the runtime's custom
 * callback if configured, otherwise falling back to built-in defaults.
 */
static int32_t get_exception_default(mbpf_runtime_t *rt, mbpf_hook_type_t hook_type) {
    if (rt && rt->config.exception_default_fn) {
        return rt->config.exception_default_fn(hook_type);
    }
    return mbpf_hook_exception_default(hook_type);
}

/*
 * Circuit breaker helper: check if the circuit should remain open.
 * Returns true if the circuit is open and the cooldown has not expired.
 * If cooldown has expired, closes the circuit and returns false.
 */
static bool check_circuit_open(mbpf_program_t *prog) {
    if (!prog || !prog->circuit_open) {
        return false;
    }

    mbpf_runtime_t *rt = prog->runtime;
    if (!rt || rt->config.circuit_breaker_cooldown_us == 0) {
        return true;  /* No cooldown configured, circuit stays open indefinitely */
    }

    /* Check if cooldown period has elapsed */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Calculate elapsed time in microseconds */
    int64_t elapsed_sec = now.tv_sec - prog->circuit_open_time.tv_sec;
    int64_t elapsed_nsec = now.tv_nsec - prog->circuit_open_time.tv_nsec;
    int64_t elapsed_us = elapsed_sec * 1000000 + elapsed_nsec / 1000;

    if (elapsed_us >= (int64_t)rt->config.circuit_breaker_cooldown_us) {
        /* Cooldown expired, close the circuit and reset failure count */
        prog->circuit_open = false;
        prog->consecutive_failures = 0;
        return false;
    }

    return true;  /* Circuit is still open */
}

/*
 * Circuit breaker helper: record a successful execution.
 * Resets the consecutive failure counter.
 */
static void circuit_breaker_record_success(mbpf_program_t *prog) {
    if (!prog) return;
    prog->consecutive_failures = 0;
}

/*
 * Circuit breaker helper: record a failed execution.
 * Increments the failure counter and trips the circuit if threshold is exceeded.
 */
static void circuit_breaker_record_failure(mbpf_program_t *prog) {
    if (!prog || !prog->runtime) return;

    mbpf_runtime_t *rt = prog->runtime;
    if (rt->config.circuit_breaker_threshold == 0) {
        return;  /* Circuit breaker not configured */
    }

    prog->consecutive_failures++;

    if (prog->consecutive_failures >= rt->config.circuit_breaker_threshold) {
        /* Trip the circuit breaker */
        prog->circuit_open = true;
        clock_gettime(CLOCK_MONOTONIC, &prog->circuit_open_time);
        prog->stats.circuit_breaker_trips++;
    }
}

/*
 * Check if an exception is an out-of-memory error.
 * Returns true if the exception is an OOM error, false otherwise.
 *
 * Note: We intentionally do NOT treat JS_NULL as OOM, because a user can
 * explicitly `throw null` which would be misclassified. MQuickJS only throws
 * JS_NULL when OOM occurs while already handling an OOM (extremely rare).
 * For normal OOM cases, MQuickJS creates an Error with "out of memory" message.
 */
static bool is_oom_exception(JSContext *ctx, JSValue exc) {
    /* User-thrown null/undefined should not be treated as OOM */
    if (JS_IsNull(exc) || JS_IsUndefined(exc)) {
        return false;
    }

    /* Check for "out of memory" message - MQuickJS throws this as various error types
     * (InternalError, Error, etc.) depending on the context */
    JSValue msg = JS_GetPropertyStr(ctx, exc, "message");
    if (JS_IsException(msg)) {
        JS_GetException(ctx);  /* Clear exception from property access */
        return false;
    }
    if (!JS_IsUndefined(msg)) {
        JSCStringBuf buf;
        const char *str = JS_ToCString(ctx, msg, &buf);
        if (!str) {
            JS_GetException(ctx);  /* Clear exception from toString */
            return false;
        }
        if (strstr(str, "out of memory") != NULL) {
            return true;
        }
    }

    return false;
}

/*
 * Sync map data from JS arrays back to C storage.
 * This is used before destroying JS instances to preserve map data.
 * Syncs array, hash, LRU, and per-CPU maps. Ring buffers and counters are not synced
 * (ring buffers are event streams, counters have simpler state).
 */
static void sync_maps_from_js_to_c(mbpf_instance_t *inst, mbpf_program_t *prog, uint32_t instance_idx) {
    if (!inst->js_initialized || !inst->js_ctx || !prog->maps) {
        return;
    }

    JSContext *ctx = inst->js_ctx;

    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];

        /*
         * Note: MQuickJS uses a compacting GC - values don't need manual freeing.
         * The GC will collect all temporary JSValues when it runs.
         */
        if (storage->type == MBPF_MAP_TYPE_ARRAY) {
            mbpf_array_map_t *arr = &storage->u.array;
            if (!arr->values || !arr->valid) continue;

            size_t total_bytes = (size_t)arr->max_entries * arr->value_size;

            /* Extract data array from JS, reading element by element */
            char code[256];
            snprintf(code, sizeof(code), "_mapData[%u];", i);

            JSValue data_arr = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(data_arr)) {
                for (size_t j = 0; j < total_bytes; j++) {
                    JSValue elem = JS_GetPropertyUint32(ctx, data_arr, (uint32_t)j);
                    int val = 0;
                    JS_ToInt32(ctx, &val, elem);
                    arr->values[j] = (uint8_t)val;
                }
            }

            /* Extract valid array from JS */
            snprintf(code, sizeof(code), "_mapValid[%u];", i);
            JSValue valid_arr = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(valid_arr)) {
                size_t bitmap_size = (arr->max_entries + 7) / 8;
                memset(arr->valid, 0, bitmap_size);
                for (uint32_t j = 0; j < arr->max_entries; j++) {
                    JSValue elem = JS_GetPropertyUint32(ctx, valid_arr, j);
                    int val = 0;
                    JS_ToInt32(ctx, &val, elem);
                    if (val) {
                        arr->valid[j / 8] |= (1 << (j % 8));
                    }
                }
            }
        } else if (storage->type == MBPF_MAP_TYPE_HASH) {
            mbpf_hash_map_t *hash = &storage->u.hash;
            if (!hash->buckets) continue;

            size_t bucket_size = 1 + hash->key_size + hash->value_size;
            size_t total_bytes = (size_t)hash->max_entries * bucket_size;

            /* Extract data array from JS */
            char code[256];
            snprintf(code, sizeof(code), "_mapData[%u];", i);

            JSValue data_arr = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(data_arr)) {
                for (size_t j = 0; j < total_bytes; j++) {
                    JSValue elem = JS_GetPropertyUint32(ctx, data_arr, (uint32_t)j);
                    int val = 0;
                    JS_ToInt32(ctx, &val, elem);
                    hash->buckets[j] = (uint8_t)val;
                }
            }

            /* Extract count from JS */
            snprintf(code, sizeof(code), "_mapValid[%u].count;", i);
            JSValue count_val = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(count_val)) {
                int count = 0;
                JS_ToInt32(ctx, &count, count_val);
                hash->count = (uint32_t)count;
            }
        } else if (storage->type == MBPF_MAP_TYPE_LRU) {
            mbpf_lru_hash_map_t *lru = &storage->u.lru_hash;
            if (!lru->buckets) continue;

            /* LRU bucket layout: [valid:1][prev:4][next:4][key][value] */
            size_t bucket_size = 1 + 4 + 4 + lru->key_size + lru->value_size;
            size_t total_bytes = (size_t)lru->max_entries * bucket_size;

            /* Extract data array from JS */
            char code[256];
            snprintf(code, sizeof(code), "_mapData[%u];", i);

            JSValue data_arr = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(data_arr)) {
                for (size_t j = 0; j < total_bytes; j++) {
                    JSValue elem = JS_GetPropertyUint32(ctx, data_arr, (uint32_t)j);
                    int val = 0;
                    JS_ToInt32(ctx, &val, elem);
                    lru->buckets[j] = (uint8_t)val;
                }
            }

            /* Extract count, head, tail from JS _mapValid object */
            snprintf(code, sizeof(code), "_mapValid[%u].count;", i);
            JSValue count_val = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(count_val)) {
                int count = 0;
                JS_ToInt32(ctx, &count, count_val);
                lru->count = (uint32_t)count;
            }

            snprintf(code, sizeof(code), "_mapValid[%u].head;", i);
            JSValue head_val = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(head_val)) {
                uint32_t head = 0;
                JS_ToUint32(ctx, &head, head_val);
                lru->lru_head = head;
            }

            snprintf(code, sizeof(code), "_mapValid[%u].tail;", i);
            JSValue tail_val = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(tail_val)) {
                uint32_t tail = 0;
                JS_ToUint32(ctx, &tail, tail_val);
                lru->lru_tail = tail;
            }
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_ARRAY) {
            mbpf_percpu_array_map_t *pca = &storage->u.percpu_array;
            if (!pca->values || !pca->valid) continue;
            if (instance_idx >= pca->num_cpus) continue;
            if (!pca->values[instance_idx] || !pca->valid[instance_idx]) continue;

            size_t total_bytes = (size_t)pca->max_entries * pca->value_size;

            /* Extract data array from JS */
            char code[256];
            snprintf(code, sizeof(code), "_mapData[%u];", i);

            JSValue data_arr = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(data_arr)) {
                for (size_t j = 0; j < total_bytes; j++) {
                    JSValue elem = JS_GetPropertyUint32(ctx, data_arr, (uint32_t)j);
                    int val = 0;
                    JS_ToInt32(ctx, &val, elem);
                    pca->values[instance_idx][j] = (uint8_t)val;
                }
            }

            /* Extract valid array from JS (1 byte per entry) */
            snprintf(code, sizeof(code), "_mapValid[%u];", i);
            JSValue valid_arr = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(valid_arr)) {
                for (uint32_t j = 0; j < pca->max_entries; j++) {
                    JSValue elem = JS_GetPropertyUint32(ctx, valid_arr, j);
                    int val = 0;
                    JS_ToInt32(ctx, &val, elem);
                    pca->valid[instance_idx][j] = (uint8_t)val;
                }
            }
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_HASH) {
            mbpf_percpu_hash_map_t *pch = &storage->u.percpu_hash;
            if (!pch->buckets || !pch->counts) continue;
            if (instance_idx >= pch->num_cpus) continue;
            if (!pch->buckets[instance_idx]) continue;

            size_t bucket_size = 1 + pch->key_size + pch->value_size;
            size_t total_bytes = (size_t)pch->max_entries * bucket_size;

            /* Extract data array from JS */
            char code[256];
            snprintf(code, sizeof(code), "_mapData[%u];", i);

            JSValue data_arr = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(data_arr)) {
                for (size_t j = 0; j < total_bytes; j++) {
                    JSValue elem = JS_GetPropertyUint32(ctx, data_arr, (uint32_t)j);
                    int val = 0;
                    JS_ToInt32(ctx, &val, elem);
                    pch->buckets[instance_idx][j] = (uint8_t)val;
                }
            }

            /* Extract count from JS */
            snprintf(code, sizeof(code), "_mapValid[%u].count;", i);
            JSValue count_val = JS_Eval(ctx, code, strlen(code), "<sync>", JS_EVAL_RETVAL);
            if (!JS_IsException(count_val)) {
                int count = 0;
                JS_ToInt32(ctx, &count, count_val);
                pch->counts[instance_idx] = (uint32_t)count;
            }
        }
        /* Ring buffer and counter maps are not synced:
         * - Ring buffers are event streams, not persistent data
         * - Counters could be synced but typically reset on update */
    }
}

/*
 * Initialize JS map arrays from C storage.
 * This is used after creating new JS instances to restore map data.
 * Must be called after setup_maps_object.
 *
 * Uses JS_Eval to set array elements since MQuickJS doesn't expose
 * direct buffer access for Uint8Arrays.
 */
static void sync_maps_from_c_to_js(mbpf_instance_t *inst, mbpf_program_t *prog, uint32_t instance_idx) {
    if (!inst->js_initialized || !inst->js_ctx || !prog->maps) {
        return;
    }

    JSContext *ctx = inst->js_ctx;

    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];

        if (storage->type == MBPF_MAP_TYPE_ARRAY) {
            mbpf_array_map_t *arr = &storage->u.array;
            if (!arr->values || !arr->valid) continue;

            size_t total_bytes = (size_t)arr->max_entries * arr->value_size;

            /* Build JS code to set all data bytes in batches using safe string builder */
            size_t initial_size = 256 + total_bytes * 4 + arr->max_entries * 4;
            mbpf_strbuf_t sb;
            if (!strbuf_init(&sb, initial_size)) continue;

            /* Generate: (function(d,v){for(var i=0;i<bytes.length;i++)d[i]=bytes[i];...})(_mapData[i],[b0,b1,...]) */
            strbuf_printf(&sb, "(function(d,v,bytes,valid){"
                "for(var i=0;i<bytes.length;i++)d[i]=bytes[i];"
                "for(var i=0;i<valid.length;i++)v[i]=valid[i];"
                "})(_mapData[%u],_mapValid[%u],[", i, i);

            /* Add data bytes */
            for (size_t j = 0; j < total_bytes; j++) {
                strbuf_printf(&sb, "%s%u", j > 0 ? "," : "", arr->values[j]);
            }

            /* Add valid array */
            strbuf_puts(&sb, "],[");

            for (uint32_t j = 0; j < arr->max_entries; j++) {
                int valid_bit = (arr->valid[j / 8] & (1 << (j % 8))) ? 1 : 0;
                strbuf_printf(&sb, "%s%d", j > 0 ? "," : "", valid_bit);
            }

            strbuf_puts(&sb, "]);");

            if (!sb.error) {
                JSValue result = JS_Eval(ctx, sb.buf, sb.len, "<sync>", JS_EVAL_RETVAL);
                if (JS_IsException(result)) {
                    JS_GetException(ctx);
                }
            }
            strbuf_free(&sb);

        } else if (storage->type == MBPF_MAP_TYPE_HASH) {
            mbpf_hash_map_t *hash = &storage->u.hash;
            if (!hash->buckets) continue;

            size_t bucket_size = 1 + hash->key_size + hash->value_size;
            size_t total_bytes = (size_t)hash->max_entries * bucket_size;

            /* Build JS code to set all bucket bytes using safe string builder */
            size_t initial_size = 256 + total_bytes * 4;
            mbpf_strbuf_t sb;
            if (!strbuf_init(&sb, initial_size)) continue;

            strbuf_printf(&sb, "(function(d,bytes){"
                "for(var i=0;i<bytes.length;i++)d[i]=bytes[i];"
                "})(_mapData[%u],[", i);

            for (size_t j = 0; j < total_bytes; j++) {
                strbuf_printf(&sb, "%s%u", j > 0 ? "," : "", hash->buckets[j]);
            }

            strbuf_printf(&sb, "]);_mapValid[%u].count=%u;", i, hash->count);

            if (!sb.error) {
                JSValue result = JS_Eval(ctx, sb.buf, sb.len, "<sync>", JS_EVAL_RETVAL);
                if (JS_IsException(result)) {
                    JS_GetException(ctx);
                }
            }
            strbuf_free(&sb);
        } else if (storage->type == MBPF_MAP_TYPE_LRU) {
            mbpf_lru_hash_map_t *lru = &storage->u.lru_hash;
            if (!lru->buckets) continue;

            /* LRU bucket layout: [valid:1][prev:4][next:4][key][value] */
            size_t bucket_size = 1 + 4 + 4 + lru->key_size + lru->value_size;
            size_t total_bytes = (size_t)lru->max_entries * bucket_size;

            /* Build JS code to set all bucket bytes and metadata using safe string builder */
            size_t initial_size = 256 + total_bytes * 4;
            mbpf_strbuf_t sb;
            if (!strbuf_init(&sb, initial_size)) continue;

            strbuf_printf(&sb, "(function(d,bytes){"
                "for(var i=0;i<bytes.length;i++)d[i]=bytes[i];"
                "})(_mapData[%u],[", i);

            for (size_t j = 0; j < total_bytes; j++) {
                strbuf_printf(&sb, "%s%u", j > 0 ? "," : "", lru->buckets[j]);
            }

            /* Set count, head, tail */
            strbuf_printf(&sb, "]);_mapValid[%u].count=%u;_mapValid[%u].head=%u;_mapValid[%u].tail=%u;",
                i, lru->count, i, lru->lru_head, i, lru->lru_tail);

            if (!sb.error) {
                JSValue result = JS_Eval(ctx, sb.buf, sb.len, "<sync>", JS_EVAL_RETVAL);
                if (JS_IsException(result)) {
                    JS_GetException(ctx);
                }
            }
            strbuf_free(&sb);
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_ARRAY) {
            mbpf_percpu_array_map_t *pca = &storage->u.percpu_array;
            if (!pca->values || !pca->valid) continue;
            if (instance_idx >= pca->num_cpus) continue;
            if (!pca->values[instance_idx] || !pca->valid[instance_idx]) continue;

            size_t total_bytes = (size_t)pca->max_entries * pca->value_size;

            /* Build JS code to set all data bytes and valid flags using safe string builder */
            size_t initial_size = 256 + total_bytes * 4 + pca->max_entries * 4;
            mbpf_strbuf_t sb;
            if (!strbuf_init(&sb, initial_size)) continue;

            strbuf_printf(&sb, "(function(d,v,bytes,valid){"
                "for(var i=0;i<bytes.length;i++)d[i]=bytes[i];"
                "for(var i=0;i<valid.length;i++)v[i]=valid[i];"
                "})(_mapData[%u],_mapValid[%u],[", i, i);

            /* Add data bytes */
            for (size_t j = 0; j < total_bytes; j++) {
                strbuf_printf(&sb, "%s%u", j > 0 ? "," : "", pca->values[instance_idx][j]);
            }

            /* Add valid array */
            strbuf_puts(&sb, "],[");

            for (uint32_t j = 0; j < pca->max_entries; j++) {
                strbuf_printf(&sb, "%s%u", j > 0 ? "," : "", pca->valid[instance_idx][j]);
            }

            strbuf_puts(&sb, "]);");

            if (!sb.error) {
                JSValue result = JS_Eval(ctx, sb.buf, sb.len, "<sync>", JS_EVAL_RETVAL);
                if (JS_IsException(result)) {
                    JS_GetException(ctx);
                }
            }
            strbuf_free(&sb);
        } else if (storage->type == MBPF_MAP_TYPE_PERCPU_HASH) {
            mbpf_percpu_hash_map_t *pch = &storage->u.percpu_hash;
            if (!pch->buckets || !pch->counts) continue;
            if (instance_idx >= pch->num_cpus) continue;
            if (!pch->buckets[instance_idx]) continue;

            size_t bucket_size = 1 + pch->key_size + pch->value_size;
            size_t total_bytes = (size_t)pch->max_entries * bucket_size;

            /* Build JS code to set all bucket bytes using safe string builder */
            size_t initial_size = 256 + total_bytes * 4;
            mbpf_strbuf_t sb;
            if (!strbuf_init(&sb, initial_size)) continue;

            strbuf_printf(&sb, "(function(d,bytes){"
                "for(var i=0;i<bytes.length;i++)d[i]=bytes[i];"
                "})(_mapData[%u],[", i);

            for (size_t j = 0; j < total_bytes; j++) {
                strbuf_printf(&sb, "%s%u", j > 0 ? "," : "", pch->buckets[instance_idx][j]);
            }

            strbuf_printf(&sb, "]);_mapValid[%u].count=%u;", i, pch->counts[instance_idx]);

            if (!sb.error) {
                JSValue result = JS_Eval(ctx, sb.buf, sb.len, "<sync>", JS_EVAL_RETVAL);
                if (JS_IsException(result)) {
                    JS_GetException(ctx);
                }
            }
            strbuf_free(&sb);
        }
        /* Ring buffer and counter maps are not synced */
    }
}

/* Get number of CPUs for per-CPU instance mode */
static uint32_t get_num_cpus(void) {
#ifdef _SC_NPROCESSORS_ONLN
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n > 0) {
        return (uint32_t)n;
    }
#endif
    return 1;
}

/* Runtime initialization */
mbpf_runtime_t *mbpf_runtime_init(const mbpf_runtime_config_t *cfg) {
    mbpf_runtime_t *rt = calloc(1, sizeof(mbpf_runtime_t));
    if (!rt) {
        return NULL;
    }

    /* Set reasonable defaults first, then override with explicit config. */
    rt->config.default_heap_size = 16384;    /* 16KB */
    rt->config.default_max_steps = 100000;
    rt->config.default_max_helpers = 1000;
    rt->config.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ |
                                      MBPF_CAP_MAP_WRITE | MBPF_CAP_MAP_ITERATE;
    rt->config.require_signatures = false;
    rt->config.debug_mode = false;
    rt->config.instance_mode = MBPF_INSTANCE_SINGLE;
    rt->config.instance_count = 1;

    if (cfg) {
        if (cfg->default_heap_size) {
            rt->config.default_heap_size = cfg->default_heap_size;
        }
        if (cfg->default_max_steps) {
            rt->config.default_max_steps = cfg->default_max_steps;
        }
        if (cfg->default_max_helpers) {
            rt->config.default_max_helpers = cfg->default_max_helpers;
        }
        if (cfg->allowed_capabilities) {
            rt->config.allowed_capabilities = cfg->allowed_capabilities;
        }
        rt->config.require_signatures = cfg->require_signatures;
        rt->config.debug_mode = cfg->debug_mode;
        if (cfg->log_fn) {
            rt->config.log_fn = cfg->log_fn;
        }
        if (cfg->instance_mode != MBPF_INSTANCE_SINGLE) {
            rt->config.instance_mode = cfg->instance_mode;
        }
        if (cfg->instance_count > 0) {
            rt->config.instance_count = cfg->instance_count;
        }
        if (cfg->exception_default_fn) {
            rt->config.exception_default_fn = cfg->exception_default_fn;
        }
        if (cfg->circuit_breaker_threshold) {
            rt->config.circuit_breaker_threshold = cfg->circuit_breaker_threshold;
        }
        if (cfg->circuit_breaker_cooldown_us) {
            rt->config.circuit_breaker_cooldown_us = cfg->circuit_breaker_cooldown_us;
        }
        rt->config.trace_enabled = cfg->trace_enabled;
        if (cfg->trace_rate_limit_per_sec) {
            rt->config.trace_rate_limit_per_sec = cfg->trace_rate_limit_per_sec;
        }
    }

    if (!rt->config.log_fn) {
        rt->config.log_fn = default_log_fn;
    }

    /* Determine number of instances based on mode */
    switch (rt->config.instance_mode) {
        case MBPF_INSTANCE_PER_CPU:
            rt->num_instances = get_num_cpus();
            break;
        case MBPF_INSTANCE_COUNT:
            rt->num_instances = rt->config.instance_count > 0
                                ? rt->config.instance_count : 1;
            break;
        case MBPF_INSTANCE_SINGLE:
        default:
            rt->num_instances = 1;
            break;
    }

    rt->initialized = true;
    return rt;
}

/* Runtime shutdown */
void mbpf_runtime_shutdown(mbpf_runtime_t *rt) {
    if (!rt) return;

    /* Unload all programs */
    mbpf_program_t *prog = rt->programs;
    while (prog) {
        mbpf_program_t *next = prog->next;
        mbpf_program_unload(rt, prog);
        prog = next;
    }

    free(rt);
}

/*
 * Validate that the entry function exists in the JS context.
 * Returns MBPF_OK if found, MBPF_ERR_MISSING_ENTRY if not.
 * Note: MQuickJS uses a compacting GC - values don't need manual freeing.
 */
static int validate_entry_function(JSContext *ctx, const char *entry_symbol) {
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsUndefined(global) || JS_IsException(global)) {
        return MBPF_ERR_MISSING_ENTRY;
    }

    JSValue entry_func = JS_GetPropertyStr(ctx, global, entry_symbol);
    if (JS_IsUndefined(entry_func) || !JS_IsFunction(ctx, entry_func)) {
        return MBPF_ERR_MISSING_ENTRY;
    }

    return MBPF_OK;
}

/*
 * Disable dangerous global APIs for security.
 *
 * This function removes or disables potentially dangerous JavaScript globals:
 * - Function constructor: Can dynamically create functions from strings
 * - eval: Can execute arbitrary code strings
 *
 * Note: MQuickJS is a minimal JS engine and does not include:
 * - Filesystem APIs (no 'fs', 'require', etc.)
 * - Network APIs (no 'fetch', 'XMLHttpRequest', 'WebSocket', etc.)
 * - Other Node.js or browser-specific APIs
 *
 * The load(), setTimeout(), and clearTimeout() functions are already
 * stubbed to throw errors in mbpf_stdlib.c.
 */
static void disable_dangerous_globals(JSContext *ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsUndefined(global) || JS_IsException(global)) {
        return;
    }

    /* Clear Function.prototype.constructor to prevent indirect access via
     * (function(){}).constructor. */
    JSValue function_ctor = JS_GetPropertyStr(ctx, global, "Function");
    if (!JS_IsUndefined(function_ctor) && !JS_IsException(function_ctor)) {
        JSValue function_proto = JS_GetPropertyStr(ctx, function_ctor, "prototype");
        if (!JS_IsUndefined(function_proto) && !JS_IsException(function_proto)) {
            JS_SetPropertyStr(ctx, function_proto, "constructor", JS_UNDEFINED);
        }
        /* Note: MQuickJS uses a compacting GC, temporary values don't need
         * explicit freeing - they're garbage collected automatically. */
    }

    /* Disable Function constructor by setting it to undefined.
     * This prevents code like: new Function('return 1')()
     * or Function('x', 'return x*2') */
    JS_SetPropertyStr(ctx, global, "Function", JS_UNDEFINED);

    /* Disable eval by setting it to undefined.
     * This prevents code like: eval('1+1') */
    JS_SetPropertyStr(ctx, global, "eval", JS_UNDEFINED);

    /* Note: The following are already not available in MQuickJS stdlib:
     * - require (no module system)
     * - process (no Node.js globals)
     * - fs, path, http, etc. (no Node.js modules)
     * - fetch, XMLHttpRequest (no browser APIs)
     * - WebSocket (no network APIs)
     * These would need explicit stub functions if we wanted to throw
     * informative errors, but they simply don't exist. */
}

/*
 * Create a single instance for a program.
 * Each instance has its own heap, JS context, and loaded bytecode.
 */
static int create_instance(mbpf_program_t *prog, uint32_t idx, size_t heap_size,
                           const void *bytecode, size_t bytecode_len) {
    mbpf_instance_t *inst = &prog->instances[idx];

    inst->index = idx;
    inst->program = prog;
    inst->in_use = 0;
    inst->heap_size = heap_size;

    /* Allocate JS heap */
    inst->js_heap = malloc(heap_size);
    if (!inst->js_heap) {
        return MBPF_ERR_NO_MEM;
    }

    /* Create JS context */
    inst->js_ctx = JS_NewContext(inst->js_heap, heap_size, mbpf_get_js_stdlib());
    if (!inst->js_ctx) {
        free(inst->js_heap);
        inst->js_heap = NULL;
        return MBPF_ERR_NO_MEM;
    }

    /* Set context opaque to point to instance for budget tracking */
    JS_SetContextOpaque(inst->js_ctx, inst);

    /* Set up interrupt handler for step budget enforcement */
    JS_SetInterruptHandler(inst->js_ctx, mbpf_interrupt_handler);

    /* Disable dangerous globals (Function constructor, eval) for security.
     * This must happen after context creation but before loading bytecode. */
    disable_dangerous_globals(inst->js_ctx);

    /* In non-debug mode, disable console.log by setting console to undefined.
     * The spec says: "console.log mapped to mbpf.log() in debug builds only."
     * This ensures programs can only use mbpf.log in production mode. */
    if (prog->runtime && !prog->runtime->config.debug_mode) {
        JSValue global = JS_GetGlobalObject(inst->js_ctx);
        if (!JS_IsUndefined(global) && !JS_IsException(global)) {
            JS_SetPropertyStr(inst->js_ctx, global, "console", JS_UNDEFINED);
        }
    }

    /* Initialize step budget from manifest */
    uint32_t max_steps = prog->manifest.budgets.max_steps;
    /* If manifest doesn't specify, use runtime default */
    if (max_steps == 0 && prog->runtime) {
        max_steps = prog->runtime->config.default_max_steps;
    }
    inst->max_steps = max_steps;
    inst->steps_remaining = max_steps;
    inst->budget_exceeded = 0;

    /* Initialize helper budget from manifest */
    uint32_t max_helpers = prog->manifest.budgets.max_helpers;
    /* If manifest doesn't specify, use runtime default */
    if (max_helpers == 0 && prog->runtime) {
        max_helpers = prog->runtime->config.default_max_helpers;
    }
    inst->max_helpers = max_helpers;

    /* Wall time budget is only enforced during mbpf_run, not during init.
     * We store the configured value but set max_wall_time_us to 0 during
     * instance creation to avoid timing out during setup JS_Eval calls.
     * The actual value will be applied later before the first run. */
    inst->max_wall_time_us = 0;  /* Disabled during init */
    memset(&inst->start_time, 0, sizeof(inst->start_time));

    /* Each instance needs its own copy of bytecode for relocation.
     * The bytecode must be kept alive as long as the context exists
     * because JS_LoadBytecode keeps a reference to it. */
    inst->bytecode = malloc(bytecode_len);
    if (!inst->bytecode) {
        JS_FreeContext(inst->js_ctx);
        inst->js_ctx = NULL;
        free(inst->js_heap);
        inst->js_heap = NULL;
        return MBPF_ERR_NO_MEM;
    }
    memcpy(inst->bytecode, bytecode, bytecode_len);
    inst->bytecode_len = bytecode_len;

    /* Load bytecode into this instance's context */
    mbpf_bytecode_info_t bc_info;
    int err = mbpf_bytecode_load(inst->js_ctx, inst->bytecode, bytecode_len,
                                  &bc_info, &inst->main_func);

    if (err != MBPF_OK) {
        free(inst->bytecode);
        inst->bytecode = NULL;
        JS_FreeContext(inst->js_ctx);
        inst->js_ctx = NULL;
        free(inst->js_heap);
        inst->js_heap = NULL;
        return err;
    }

    /* Validate that the entry function exists in the loaded bytecode */
    err = validate_entry_function(inst->js_ctx, prog->manifest.entry_symbol);
    if (err != MBPF_OK) {
        free(inst->bytecode);
        inst->bytecode = NULL;
        JS_FreeContext(inst->js_ctx);
        inst->js_ctx = NULL;
        free(inst->js_heap);
        inst->js_heap = NULL;
        return err;
    }

    inst->js_initialized = true;
    return MBPF_OK;
}

/*
 * Free resources for a single instance.
 */
static void free_instance(mbpf_instance_t *inst) {
    if (inst->js_initialized && inst->js_ctx) {
        /*
         * Release GC-protected references BEFORE freeing the context.
         * This is critical for proper cleanup - the GC reference list
         * must be cleaned up while the context is still valid.
         */
        if (inst->has_entry_func_ref) {
            JS_DeleteGCRef(inst->js_ctx, &inst->entry_func_ref);
            inst->has_entry_func_ref = false;
        }
        if (inst->has_maps_obj_ref) {
            JS_DeleteGCRef(inst->js_ctx, &inst->maps_obj_ref);
            inst->has_maps_obj_ref = false;
        }
        if (inst->has_ctx_obj_ref) {
            JS_DeleteGCRef(inst->js_ctx, &inst->ctx_obj_ref);
            inst->has_ctx_obj_ref = false;
        }
        inst->ctx_initialized = false;

        JS_FreeContext(inst->js_ctx);
        inst->js_ctx = NULL;
    }
    /* Free bytecode AFTER freeing context since context references it */
    if (inst->bytecode) {
        free(inst->bytecode);
        inst->bytecode = NULL;
    }
    if (inst->js_heap) {
        free(inst->js_heap);
        inst->js_heap = NULL;
    }
    inst->js_initialized = false;
}

/*
 * Register GC-protected references for persistent values that must survive
 * compacting GC. This should be called after setup_maps_object completes
 * so that both the entry function and maps object are available.
 *
 * MQuickJS uses a compacting GC, which means object addresses can change
 * during garbage collection. Any JSValue that is held across potential
 * GC points (like helper calls that may allocate) must be protected with
 * a GC reference.
 *
 * Returns 0 on success, -1 on error.
 */
static int register_gc_refs(mbpf_instance_t *inst, const char *entry_symbol) {
    if (!inst->js_initialized || !inst->js_ctx) {
        return -1;
    }

    JSContext *ctx = inst->js_ctx;
    JSValue *ref_val;

    /* Initialize the flags to false in case we fail partway */
    inst->has_entry_func_ref = false;
    inst->has_maps_obj_ref = false;

    /* Get global object to look up entry function and maps */
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsUndefined(global) || JS_IsException(global)) {
        return -1;
    }

    /* Cache entry function (e.g., mbpf_prog) with GC protection.
     * This function is called repeatedly during program execution,
     * so caching it with GC protection avoids repeated lookups and
     * ensures it remains valid after any GC that may occur during
     * helper calls or other allocations. */
    JSValue entry_func = JS_GetPropertyStr(ctx, global, entry_symbol);
    if (JS_IsUndefined(entry_func) || !JS_IsFunction(ctx, entry_func)) {
        /* Entry function must exist - validation should have caught this */
        return -1;
    }

    /* Register the entry function as a GC root */
    ref_val = JS_AddGCRef(ctx, &inst->entry_func_ref);
    if (!ref_val) {
        return -1;  /* Should not happen, but be safe */
    }
    *ref_val = entry_func;
    inst->has_entry_func_ref = true;

    /* Cache maps object with GC protection if it exists.
     * The maps object is accessed during every program run to sync
     * map state. Caching it avoids repeated global lookups. */
    JSValue maps_obj = JS_GetPropertyStr(ctx, global, "maps");
    if (!JS_IsUndefined(maps_obj) && !JS_IsException(maps_obj)) {
        ref_val = JS_AddGCRef(ctx, &inst->maps_obj_ref);
        if (!ref_val) {
            /* Clean up the entry function ref we just added */
            JS_DeleteGCRef(ctx, &inst->entry_func_ref);
            inst->has_entry_func_ref = false;
            return -1;
        }
        *ref_val = maps_obj;
        inst->has_maps_obj_ref = true;
    }

    return 0;
}

/*
 * Initialize reusable context object infrastructure for an instance.
 *
 * This creates a ctx object that can be reused across invocations,
 * avoiding per-invocation allocation. The approach:
 *
 * 1. Global variables store the current context data:
 *    - _ctx_scalars: Object with scalar properties (ifindex, pkt_len, etc.)
 *    - _ctx_data: Uint8Array for packet/buffer data
 *
 * 2. A persistent ctx object with getters that read from the globals
 *
 * 3. At each invocation, we update the global variables via JS_Eval
 *    rather than creating a new object.
 *
 * Returns 0 on success, -1 on error.
 */
static int init_reusable_ctx(mbpf_instance_t *inst) {
    if (!inst->js_initialized || !inst->js_ctx) {
        return -1;
    }

    JSContext *ctx = inst->js_ctx;
    inst->has_ctx_obj_ref = false;
    inst->ctx_initialized = false;

    /*
     * Create the infrastructure for reusable context.
     * We create global variables to hold the context data and a ctx object
     * with getters that reference those globals.
     *
     * The ctx object structure:
     * - Read-only scalar properties (ifindex, pkt_len, data_len, l2_proto, flags)
     *   that read from _ctx_scalars
     * - Read methods (readU8, readU16LE, readU32LE, readBytes) that read from _ctx_data
     *
     * For hook types without data (TIMER, TRACEPOINT), _ctx_data will be empty.
     */
    static const char init_code[] =
        /* Global storage for context data */
        "var _ctx_scalars={"
            "ifindex:0,pkt_len:0,data_len:0,l2_proto:0,flags:0,"
            /* Timer-specific fields */
            "timer_id:0,period_us:0,invocation_count:0,timestamp:0,"
            /* Tracepoint-specific fields */
            "tracepoint_id:0,cpu:0,pid:0,"
            /* Security-specific fields */
            "subject_id:0,object_id:0,action:0,"
            /* Custom-specific fields */
            "custom_hook_id:0,schema_version:0,field_count:0"
        "};"
        "var _ctx_data=new Uint8Array(0);"
        /* Create the reusable ctx object with getters */
        "var _ctx_obj=(function(){"
            "var s=_ctx_scalars,d=_ctx_data;"
            "var o={};"
            /* Standard NET_RX/NET_TX scalar properties */
            "Object.defineProperty(o,'ifindex',{get:function(){return s.ifindex;},set:function(){}});"
            "Object.defineProperty(o,'pkt_len',{get:function(){return s.pkt_len;},set:function(){}});"
            "Object.defineProperty(o,'data_len',{get:function(){return s.data_len;},set:function(){}});"
            "Object.defineProperty(o,'l2_proto',{get:function(){return s.l2_proto;},set:function(){}});"
            "Object.defineProperty(o,'flags',{get:function(){return s.flags;},set:function(){}});"
            /* Timer scalar properties */
            "Object.defineProperty(o,'timer_id',{get:function(){return s.timer_id;},set:function(){}});"
            "Object.defineProperty(o,'period_us',{get:function(){return s.period_us;},set:function(){}});"
            "Object.defineProperty(o,'invocation_count',{get:function(){return s.invocation_count;},set:function(){}});"
            "Object.defineProperty(o,'timestamp',{get:function(){return s.timestamp;},set:function(){}});"
            /* Tracepoint scalar properties */
            "Object.defineProperty(o,'tracepoint_id',{get:function(){return s.tracepoint_id;},set:function(){}});"
            "Object.defineProperty(o,'cpu',{get:function(){return s.cpu;},set:function(){}});"
            "Object.defineProperty(o,'pid',{get:function(){return s.pid;},set:function(){}});"
            /* Security scalar properties */
            "Object.defineProperty(o,'subject_id',{get:function(){return s.subject_id;},set:function(){}});"
            "Object.defineProperty(o,'object_id',{get:function(){return s.object_id;},set:function(){}});"
            "Object.defineProperty(o,'action',{get:function(){return s.action;},set:function(){}});"
            /* Custom hook scalar properties */
            "Object.defineProperty(o,'custom_hook_id',{get:function(){return s.custom_hook_id;},set:function(){}});"
            "Object.defineProperty(o,'schema_version',{get:function(){return s.schema_version;},set:function(){}});"
            "Object.defineProperty(o,'field_count',{get:function(){return s.field_count;},set:function(){}});"
            /* Data read methods - these reference _ctx_data which is updated */
            "o.readU8=function(off){"
                "var d=_ctx_data;"
                "if(typeof off!=='number')throw new TypeError('offset must be a number');"
                "if(off<0)throw new RangeError('offset must be non-negative');"
                "if(off>=d.length)throw new RangeError('offset out of bounds');"
                "return d[off];"
            "};"
            "o.readU16LE=function(off){"
                "var d=_ctx_data;"
                "if(typeof off!=='number')throw new TypeError('offset must be a number');"
                "if(off<0)throw new RangeError('offset must be non-negative');"
                "if(off+2>d.length)throw new RangeError('offset out of bounds');"
                "return d[off]|(d[off+1]<<8);"
            "};"
            "o.readU32LE=function(off){"
                "var d=_ctx_data;"
                "if(typeof off!=='number')throw new TypeError('offset must be a number');"
                "if(off<0)throw new RangeError('offset must be non-negative');"
                "if(off+4>d.length)throw new RangeError('offset out of bounds');"
                "return (d[off]|(d[off+1]<<8)|(d[off+2]<<16)|(d[off+3]<<24))>>>0;"
            "};"
            "o.readBytes=function(off,len,buf){"
                "var d=_ctx_data;"
                "if(typeof off!=='number')throw new TypeError('offset must be a number');"
                "if(typeof len!=='number')throw new TypeError('length must be a number');"
                "if(!(buf instanceof Uint8Array))throw new TypeError('outBuffer must be a Uint8Array');"
                "if(off<0)throw new RangeError('offset must be non-negative');"
                "if(len<0)throw new RangeError('length must be non-negative');"
                "if(off>=d.length)throw new RangeError('offset out of bounds');"
                "var n=len;if(off+n>d.length)n=d.length-off;if(n>buf.length)n=buf.length;"
                "for(var i=0;i<n;i++)buf[i]=d[off+i];"
                "return n;"
            "};"
            "return o;"
        "})();"
        "_ctx_obj";  /* Return the ctx object */

    JSValue result = JS_Eval(ctx, init_code, sizeof(init_code) - 1,
                             "<ctx_init>", JS_EVAL_RETVAL);
    if (JS_IsException(result)) {
        JS_GetException(ctx);  /* Clear exception */
        return -1;
    }

    /* Register the ctx object as a GC root so it survives across invocations */
    JSValue *ref_val = JS_AddGCRef(ctx, &inst->ctx_obj_ref);
    if (!ref_val) {
        return -1;
    }
    *ref_val = result;
    inst->has_ctx_obj_ref = true;
    inst->ctx_initialized = true;

    return 0;
}

/*
 * Helper to build the data array portion of the update code.
 *
 * For small data (<=256 bytes), uses inline array literal:
 *   "_ctx_data=new Uint8Array([byte0,byte1,...]);"
 *
 * For large data (>256 bytes), uses element-by-element assignment to avoid
 * parser/heap pressure from large inline array literals:
 *   "var _d=new Uint8Array(2000);_d[0]=11;_d[1]=170;...;_ctx_data=_d;"
 *
 * Returns number of bytes written, or -1 on error (buffer too small).
 */
static int build_data_array_code(char *buf, size_t buf_size,
                                  const uint8_t *data, uint32_t data_len) {
    if (!buf || buf_size == 0) return -1;

    char *p = buf;
    size_t remaining = buf_size;
    int written;

    if (!data || data_len == 0) {
        written = snprintf(p, remaining, "_ctx_data=new Uint8Array(0);");
        if (written < 0 || (size_t)written >= remaining) return -1;
        return written;
    }

    /* Use inline array for small data (<=256 bytes) */
    if (data_len <= 256) {
        /* Write opening */
        written = snprintf(p, remaining, "_ctx_data=new Uint8Array([");
        if (written < 0 || (size_t)written >= remaining) return -1;
        p += written;
        remaining -= (size_t)written;

        /* Write data bytes */
        for (uint32_t i = 0; i < data_len; i++) {
            if (i > 0) {
                if (remaining < 2) return -1;
                *p++ = ',';
                remaining--;
            }
            written = snprintf(p, remaining, "%u", data[i]);
            if (written < 0 || (size_t)written >= remaining) return -1;
            p += written;
            remaining -= (size_t)written;
        }

        /* Write closing */
        written = snprintf(p, remaining, "]);");
        if (written < 0 || (size_t)written >= remaining) return -1;
        p += written;

        return (int)(p - buf);
    }

    /*
     * For large data, use element assignment approach.
     * This avoids parser overhead of large inline array literals.
     */
    written = snprintf(p, remaining, "var _d=new Uint8Array(%u);", data_len);
    if (written < 0 || (size_t)written >= remaining) return -1;
    p += written;
    remaining -= (size_t)written;

    /* Write each element assignment */
    for (uint32_t i = 0; i < data_len; i++) {
        written = snprintf(p, remaining, "_d[%u]=%u;", i, data[i]);
        if (written < 0 || (size_t)written >= remaining) return -1;
        p += written;
        remaining -= (size_t)written;
    }

    /* Assign to global */
    written = snprintf(p, remaining, "_ctx_data=_d;");
    if (written < 0 || (size_t)written >= remaining) return -1;
    p += written;

    return (int)(p - buf);
}

/*
 * Calculate the buffer size needed for the data array code.
 *
 * For small data (<=256 bytes): inline array format
 *   Each byte needs at most 4 chars ("255,"), plus overhead for
 *   "_ctx_data=new Uint8Array([" (26 chars) and "]);" (3 chars).
 *
 * For large data (>256 bytes): element assignment format
 *   "var _d=new Uint8Array(N);" = ~30 chars
 *   Each element: "_d[NNNNN]=NNN;" = ~15 chars max
 *   "_ctx_data=_d;" = 13 chars
 */
static size_t calc_data_array_code_size(uint32_t data_len) {
    if (data_len == 0) {
        return 32;  /* "_ctx_data=new Uint8Array(0);" + margin */
    }
    if (data_len <= 256) {
        /* Inline array format: 26 for prefix + 4 per byte + 3 for suffix + margin */
        return 32 + (size_t)data_len * 4;
    }
    /* Element assignment format: 50 for prefix/suffix + 15 per element + margin */
    return 64 + (size_t)data_len * 15;
}

/*
 * Update the reusable context object with new data for an invocation.
 *
 * This updates the global _ctx_scalars and _ctx_data variables with
 * the current context blob data. The ctx object's getters will then
 * read the updated values.
 *
 * This is called at the start of each mbpf_run invocation instead of
 * creating a new ctx object.
 *
 * Returns the reusable ctx object (from inst->ctx_obj_ref) on success,
 * or JS_NULL on error.
 */
static JSValue update_reusable_ctx(mbpf_instance_t *inst, mbpf_hook_id_t hook,
                                   const void *ctx_blob, size_t ctx_len) {
    if (!inst->ctx_initialized || !inst->has_ctx_obj_ref) {
        return JS_NULL;
    }

    /* Early return for NULL ctx_blob to avoid any allocations on hot path */
    if (!ctx_blob || ctx_len == 0) {
        return JS_NULL;
    }

    JSContext *ctx = inst->js_ctx;
    char *update_code = NULL;
    uint8_t *owned_data = NULL;
    JSValue result = JS_NULL;

    /* Determine data length to calculate buffer size */
    uint32_t data_len = 0;
    const uint8_t *data = NULL;

    switch ((mbpf_hook_type_t)hook) {
        case MBPF_HOOK_NET_RX:
        case MBPF_HOOK_NET_TX:
            if (ctx_blob && ctx_len >= sizeof(mbpf_ctx_net_rx_v1_t)) {
                const mbpf_ctx_net_rx_v1_t *net_ctx = (const mbpf_ctx_net_rx_v1_t *)ctx_blob;
                data = net_ctx->data;
                data_len = net_ctx->data_len;
                /* Handle read_fn case */
                if (!data && net_ctx->read_fn && data_len > 0) {
                    owned_data = malloc(data_len);
                    if (owned_data) {
                        int read_rc = net_ctx->read_fn(ctx_blob, 0, data_len, owned_data);
                        if (read_rc > 0) {
                            data = owned_data;
                            if ((uint32_t)read_rc < data_len) {
                                data_len = (uint32_t)read_rc;
                            }
                        } else {
                            free(owned_data);
                            owned_data = NULL;
                            data = NULL;
                            data_len = 0;
                        }
                    }
                }
            }
            break;
        case MBPF_HOOK_TRACEPOINT:
            if (ctx_blob && ctx_len >= sizeof(mbpf_ctx_tracepoint_v1_t)) {
                const mbpf_ctx_tracepoint_v1_t *tp_ctx = (const mbpf_ctx_tracepoint_v1_t *)ctx_blob;
                data = tp_ctx->data;
                data_len = tp_ctx->data_len;
                if (!data && tp_ctx->read_fn && data_len > 0) {
                    owned_data = malloc(data_len);
                    if (owned_data) {
                        int read_rc = tp_ctx->read_fn(ctx_blob, 0, data_len, owned_data);
                        if (read_rc > 0) {
                            data = owned_data;
                            if ((uint32_t)read_rc < data_len) {
                                data_len = (uint32_t)read_rc;
                            }
                        } else {
                            free(owned_data);
                            owned_data = NULL;
                            data = NULL;
                            data_len = 0;
                        }
                    }
                }
            }
            break;
        case MBPF_HOOK_SECURITY:
            if (ctx_blob && ctx_len >= sizeof(mbpf_ctx_security_v1_t)) {
                const mbpf_ctx_security_v1_t *sec_ctx = (const mbpf_ctx_security_v1_t *)ctx_blob;
                data = sec_ctx->data;
                data_len = sec_ctx->data_len;
                if (!data && sec_ctx->read_fn && data_len > 0) {
                    owned_data = malloc(data_len);
                    if (owned_data) {
                        int read_rc = sec_ctx->read_fn(ctx_blob, 0, data_len, owned_data);
                        if (read_rc > 0) {
                            data = owned_data;
                            if ((uint32_t)read_rc < data_len) {
                                data_len = (uint32_t)read_rc;
                            }
                        } else {
                            free(owned_data);
                            owned_data = NULL;
                            data = NULL;
                            data_len = 0;
                        }
                    }
                }
            }
            break;
        case MBPF_HOOK_CUSTOM:
            if (ctx_blob && ctx_len >= sizeof(mbpf_ctx_custom_v1_t)) {
                const mbpf_ctx_custom_v1_t *custom_ctx = (const mbpf_ctx_custom_v1_t *)ctx_blob;
                data = custom_ctx->data;
                data_len = custom_ctx->data_len;
                if (!data && custom_ctx->read_fn && data_len > 0) {
                    owned_data = malloc(data_len);
                    if (owned_data) {
                        int read_rc = custom_ctx->read_fn(ctx_blob, 0, data_len, owned_data);
                        if (read_rc > 0) {
                            data = owned_data;
                            if ((uint32_t)read_rc < data_len) {
                                data_len = (uint32_t)read_rc;
                            }
                        } else {
                            free(owned_data);
                            owned_data = NULL;
                            data = NULL;
                            data_len = 0;
                        }
                    }
                }
            }
            break;
        default:
            /* TIMER and unknown hooks have no data */
            break;
    }

    /*
     * Calculate required buffer size:
     * - Fixed overhead: ~500 bytes for scalars reset + hook-specific updates + wrapper
     * - Data array: calc_data_array_code_size(data_len)
     */
    size_t buf_size = 512 + calc_data_array_code_size(data_len);
    update_code = malloc(buf_size);
    if (!update_code) {
        free(owned_data);
        return JS_NULL;
    }

    char *p = update_code;
    size_t remaining = buf_size;
    int written;

    /* Start with opening and reset ALL scalars to defaults.
     * This ensures fields from other hook types don't retain stale values.
     * Each hook type will then set only its relevant fields. */
    written = snprintf(p, remaining,
        "(function(){var s=_ctx_scalars;"
        /* Reset all fields to 0/defaults */
        "s.ifindex=0;s.pkt_len=0;s.data_len=0;s.l2_proto=0;s.flags=0;"
        "s.timer_id=0;s.period_us=0;s.invocation_count=0;s.timestamp=0;"
        "s.tracepoint_id=0;s.cpu=0;s.pid=0;"
        "s.subject_id=0;s.object_id=0;s.action=0;"
        "s.custom_hook_id=0;s.schema_version=0;s.field_count=0;");
    if (written < 0 || (size_t)written >= remaining) goto fail;
    p += written;
    remaining -= (size_t)written;

    switch ((mbpf_hook_type_t)hook) {
        case MBPF_HOOK_NET_RX:
        case MBPF_HOOK_NET_TX: {
            if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_net_rx_v1_t)) goto fail;
            const mbpf_ctx_net_rx_v1_t *net_ctx = (const mbpf_ctx_net_rx_v1_t *)ctx_blob;

            written = snprintf(p, remaining,
                "s.ifindex=%u;s.pkt_len=%u;s.data_len=%u;s.l2_proto=%u;s.flags=%u;",
                net_ctx->ifindex, net_ctx->pkt_len, net_ctx->data_len,
                (uint32_t)net_ctx->l2_proto, (uint32_t)net_ctx->flags);
            if (written < 0 || (size_t)written >= remaining) goto fail;
            p += written;
            remaining -= (size_t)written;

            written = build_data_array_code(p, remaining, data, data_len);
            if (written < 0) goto fail;
            p += written;
            remaining -= (size_t)written;
            break;
        }

        case MBPF_HOOK_TIMER: {
            if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_timer_v1_t)) goto fail;
            const mbpf_ctx_timer_v1_t *timer_ctx = (const mbpf_ctx_timer_v1_t *)ctx_blob;

            written = snprintf(p, remaining,
                "s.timer_id=%u;s.period_us=%u;s.invocation_count=%llu;"
                "s.timestamp=%llu;s.flags=%u;"
                "_ctx_data=new Uint8Array(0);",
                timer_ctx->timer_id, timer_ctx->period_us,
                (unsigned long long)timer_ctx->invocation_count,
                (unsigned long long)timer_ctx->timestamp,
                (uint32_t)timer_ctx->flags);
            if (written < 0 || (size_t)written >= remaining) goto fail;
            p += written;
            remaining -= (size_t)written;
            break;
        }

        case MBPF_HOOK_TRACEPOINT: {
            if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_tracepoint_v1_t)) goto fail;
            const mbpf_ctx_tracepoint_v1_t *tp_ctx = (const mbpf_ctx_tracepoint_v1_t *)ctx_blob;

            written = snprintf(p, remaining,
                "s.tracepoint_id=%u;s.timestamp=%llu;s.cpu=%u;s.pid=%u;"
                "s.data_len=%u;s.flags=%u;",
                tp_ctx->tracepoint_id,
                (unsigned long long)tp_ctx->timestamp,
                tp_ctx->cpu, tp_ctx->pid,
                tp_ctx->data_len, (uint32_t)tp_ctx->flags);
            if (written < 0 || (size_t)written >= remaining) goto fail;
            p += written;
            remaining -= (size_t)written;

            written = build_data_array_code(p, remaining, data, data_len);
            if (written < 0) goto fail;
            p += written;
            remaining -= (size_t)written;
            break;
        }

        case MBPF_HOOK_SECURITY: {
            if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_security_v1_t)) goto fail;
            const mbpf_ctx_security_v1_t *sec_ctx = (const mbpf_ctx_security_v1_t *)ctx_blob;

            written = snprintf(p, remaining,
                "s.subject_id=%u;s.object_id=%u;s.action=%u;"
                "s.data_len=%u;s.flags=%u;",
                sec_ctx->subject_id, sec_ctx->object_id,
                sec_ctx->action, sec_ctx->data_len, (uint32_t)sec_ctx->flags);
            if (written < 0 || (size_t)written >= remaining) goto fail;
            p += written;
            remaining -= (size_t)written;

            written = build_data_array_code(p, remaining, data, data_len);
            if (written < 0) goto fail;
            p += written;
            remaining -= (size_t)written;
            break;
        }

        case MBPF_HOOK_CUSTOM: {
            if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_custom_v1_t)) goto fail;
            const mbpf_ctx_custom_v1_t *custom_ctx = (const mbpf_ctx_custom_v1_t *)ctx_blob;

            written = snprintf(p, remaining,
                "s.custom_hook_id=%u;s.schema_version=%u;s.field_count=%u;"
                "s.data_len=%u;s.flags=%u;",
                custom_ctx->custom_hook_id, custom_ctx->schema_version,
                custom_ctx->field_count, custom_ctx->data_len,
                (uint32_t)custom_ctx->flags);
            if (written < 0 || (size_t)written >= remaining) goto fail;
            p += written;
            remaining -= (size_t)written;

            written = build_data_array_code(p, remaining, data, data_len);
            if (written < 0) goto fail;
            p += written;
            remaining -= (size_t)written;
            break;
        }

        default:
            written = snprintf(p, remaining, "_ctx_data=new Uint8Array(0);");
            if (written < 0 || (size_t)written >= remaining) goto fail;
            p += written;
            remaining -= (size_t)written;
            break;
    }

    /* Close and return the ctx object */
    written = snprintf(p, remaining, "return _ctx_obj;})()");
    if (written < 0 || (size_t)written >= remaining) goto fail;

    result = JS_Eval(ctx, update_code, strlen(update_code),
                     "<ctx_update>", JS_EVAL_RETVAL);
    if (JS_IsException(result)) {
        JS_GetException(ctx);  /* Clear exception */
        result = JS_NULL;
    }

    free(update_code);
    free(owned_data);
    return result;

fail:
    free(update_code);
    free(owned_data);
    return JS_NULL;
}

/*
 * Call mbpf_init() if defined in the program, for a specific instance.
 * This is called at load time after maps are created but before first run.
 * Returns MBPF_OK on success or if mbpf_init is not defined (optional).
 */
static int call_mbpf_init_on_instance(mbpf_instance_t *inst) {
    if (!inst->js_initialized || !inst->js_ctx) {
        return MBPF_OK;
    }

    JSContext *ctx = inst->js_ctx;

    /* Get global object */
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsUndefined(global) || JS_IsException(global)) {
        return MBPF_OK;  /* No global - treat as if mbpf_init not defined */
    }

    /* Look up mbpf_init function */
    JSValue init_func = JS_GetPropertyStr(ctx, global, "mbpf_init");
    if (JS_IsUndefined(init_func) || !JS_IsFunction(ctx, init_func)) {
        /* mbpf_init not defined - this is fine, it's optional */
        return MBPF_OK;
    }

    /* Check stack space: we need 2 slots (function + this) */
    if (JS_StackCheck(ctx, 2)) {
        /* Stack overflow */
        if (inst->program && inst->program->runtime &&
            inst->program->runtime->config.log_fn) {
            inst->program->runtime->config.log_fn(2, "mbpf_init: stack overflow");
        }
        return MBPF_ERR_BUDGET_EXCEEDED;
    }

    /* Call mbpf_init with no arguments (order: function, this) */
    JS_PushArg(ctx, init_func);   /* function */
    JS_PushArg(ctx, JS_NULL);     /* this */
    JSValue result = JS_Call(ctx, 0);

    /* Handle exceptions */
    if (JS_IsException(result)) {
        if (inst->program && inst->program->runtime &&
            inst->program->runtime->config.log_fn) {
            inst->program->runtime->config.log_fn(2, "mbpf_init threw exception");
        }
        JS_GetException(ctx);  /* Clear the exception */
        return MBPF_ERR_INIT_FAILED;
    }

    return MBPF_OK;
}

/* Program loading */
int mbpf_program_load(mbpf_runtime_t *rt, const void *pkg, size_t pkg_len,
                      const mbpf_load_opts_t *opts, mbpf_program_t **out_prog) {
    (void)opts;  /* TODO: use load options */

    if (!rt || !pkg || pkg_len < sizeof(mbpf_file_header_t) || !out_prog) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Parse header */
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(pkg, pkg_len, &header);
    if (err != MBPF_OK) {
        return err;
    }

    /* Allocate program structure */
    mbpf_program_t *prog = calloc(1, sizeof(mbpf_program_t));
    if (!prog) {
        return MBPF_ERR_NO_MEM;
    }

    prog->runtime = rt;

    /* Get and parse manifest */
    const void *manifest_data;
    size_t manifest_len;
    err = mbpf_package_get_section(pkg, pkg_len, MBPF_SEC_MANIFEST,
                                   &manifest_data, &manifest_len);
    if (err != MBPF_OK) {
        free(prog);
        return MBPF_ERR_MISSING_SECTION;
    }

    err = mbpf_package_parse_manifest(manifest_data, manifest_len,
                                       &prog->manifest);
    if (err != MBPF_OK) {
        free(prog);
        return err;
    }

    /* Validate API version compatibility (§11.5):
     * - Major versions must match exactly
     * - Runtime minor version must be >= program's required minor version */
    uint32_t prog_api_ver = prog->manifest.mbpf_api_version;
    uint32_t runtime_api_ver = MBPF_API_VERSION;
    uint16_t prog_major = (uint16_t)(prog_api_ver >> 16);
    uint16_t prog_minor = (uint16_t)(prog_api_ver & 0xFFFF);
    uint16_t runtime_major = (uint16_t)(runtime_api_ver >> 16);
    uint16_t runtime_minor = (uint16_t)(runtime_api_ver & 0xFFFF);

    if (prog_major != runtime_major) {
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_API_VERSION;
    }
    if (prog_minor > runtime_minor) {
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_API_VERSION;
    }

    /* Validate target architecture matches runtime (§15.1):
     * MQuickJS bytecode is architecture-dependent (word size and endianness).
     * Packages must be built for the target platform. Cross-loading
     * (mismatched word size or endianness) is rejected. */
    uint8_t runtime_word_size = mbpf_runtime_word_size();
    uint8_t runtime_endianness = mbpf_runtime_endianness();
    if (prog->manifest.target.word_size != runtime_word_size ||
        prog->manifest.target.endianness != runtime_endianness) {
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_TARGET_MISMATCH;
    }

    /* Validate per-helper versions if specified (§11.5, §12.3):
     * - Major versions must match exactly
     * - Runtime minor must be >= program's required minor
     * - Unknown helpers cause rejection */
    if (prog->manifest.helper_version_count > 0) {
        if (check_helper_versions(&prog->manifest) != 0) {
            mbpf_manifest_free(&prog->manifest);
            free(prog);
            return MBPF_ERR_HELPER_VERSION;
        }
    }

    /* Validate heap_size is at least the platform minimum */
    if (prog->manifest.heap_size < MBPF_MIN_HEAP_SIZE) {
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_HEAP_TOO_SMALL;
    }

    /* Validate capabilities: program must not request capabilities not allowed by runtime */
    uint32_t requested_caps = prog->manifest.capabilities;
    uint32_t allowed_caps = rt->config.allowed_capabilities;
    if ((requested_caps & ~allowed_caps) != 0) {
        /* Program requests capabilities that are not allowed */
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_CAPABILITY_DENIED;
    }

    /* Get bytecode section */
    const void *bytecode_data;
    size_t bytecode_len;
    err = mbpf_package_get_section(pkg, pkg_len, MBPF_SEC_BYTECODE,
                                   &bytecode_data, &bytecode_len);
    if (err != MBPF_OK) {
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_MISSING_SECTION;
    }

    /* Store bytecode for reference (used by each instance) */
    prog->bytecode = malloc(bytecode_len);
    if (!prog->bytecode) {
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_NO_MEM;
    }
    memcpy(prog->bytecode, bytecode_data, bytecode_len);
    prog->bytecode_len = bytecode_len;

    /* Determine heap size */
    size_t heap_size = prog->manifest.heap_size;
    if (heap_size < rt->config.default_heap_size) {
        heap_size = rt->config.default_heap_size;
    }

    /* Allocate instance array */
    prog->instance_count = rt->num_instances;
    prog->instances = calloc(prog->instance_count, sizeof(mbpf_instance_t));
    if (!prog->instances) {
        free(prog->bytecode);
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_NO_MEM;
    }

    /* Create map storage from manifest definitions.
     * For per-CPU maps, we need instance_count which is now known. */
    if (create_maps_from_manifest(prog, prog->instance_count) != 0) {
        free(prog->instances);
        free(prog->bytecode);
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_NO_MEM;
    }

    /* Create emit buffer if CAP_EMIT is granted */
    if (create_emit_buffer(prog) != 0) {
        free_maps(prog);
        free(prog->instances);
        free(prog->bytecode);
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_NO_MEM;
    }

    /* Create each instance with its own JSContext and heap */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        err = create_instance(prog, i, heap_size, bytecode_data, bytecode_len);
        if (err != MBPF_OK) {
            /* Clean up already created instances */
            for (uint32_t j = 0; j < i; j++) {
                free_instance(&prog->instances[j]);
            }
            free(prog->instances);
            free(prog->bytecode);
            free_emit_buffer(prog);
            free_maps(prog);
            mbpf_manifest_free(&prog->manifest);
            free(prog);
            return err;
        }
    }

    /* Store bc_info from bytecode for reference */
    mbpf_bytecode_check(prog->bytecode, prog->bytecode_len, &prog->bc_info);

    /* Set up mbpf and maps objects in each instance's JS context */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        if (setup_mbpf_object(prog->instances[i].js_ctx, prog->manifest.capabilities) != 0 ||
            setup_helper_tracking(prog->instances[i].js_ctx, prog->instances[i].max_helpers) != 0 ||
            setup_maps_object(prog->instances[i].js_ctx, prog, i) != 0 ||
            setup_lowlevel_map_helpers(prog->instances[i].js_ctx, prog) != 0) {
            for (uint32_t j = 0; j < prog->instance_count; j++) {
                free_instance(&prog->instances[j]);
            }
            free(prog->instances);
            free(prog->bytecode);
            free_emit_buffer(prog);
            free_maps(prog);
            mbpf_manifest_free(&prog->manifest);
            free(prog);
            return MBPF_ERR_NO_MEM;
        }
    }

    /* Register GC-protected references for persistent values.
     * This must be done after setup_maps_object so that both the entry
     * function and maps object are available for caching. */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        if (register_gc_refs(&prog->instances[i], prog->manifest.entry_symbol) != 0) {
            for (uint32_t j = 0; j < prog->instance_count; j++) {
                free_instance(&prog->instances[j]);
            }
            free(prog->instances);
            free(prog->bytecode);
            free_emit_buffer(prog);
            free_maps(prog);
            mbpf_manifest_free(&prog->manifest);
            free(prog);
            return MBPF_ERR_NO_MEM;
        }
    }

    /* Initialize reusable context object infrastructure for each instance.
     * This creates a ctx object that can be reused across invocations,
     * avoiding per-invocation allocation. */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        if (init_reusable_ctx(&prog->instances[i]) != 0) {
            /* Non-fatal - fall back to per-invocation ctx creation */
            prog->instances[i].ctx_initialized = false;
        }
    }

    /* Call mbpf_init() on all instances if defined.
     * This happens after maps are created but before the program is available
     * for running. */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        err = call_mbpf_init_on_instance(&prog->instances[i]);
        if (err != MBPF_OK) {
            /* mbpf_init failed - clean up and fail the load */
            for (uint32_t j = 0; j < prog->instance_count; j++) {
                free_instance(&prog->instances[j]);
            }
            free(prog->instances);
            free(prog->bytecode);
            free_emit_buffer(prog);
            free_maps(prog);
            mbpf_manifest_free(&prog->manifest);
            free(prog);
            return err;
        }
    }

    /* Try to load debug info (optional, failure is not fatal) */
    prog->has_debug_info = false;
    err = mbpf_package_get_debug_info(pkg, pkg_len, &prog->debug_info);
    if (err == MBPF_OK) {
        prog->has_debug_info = true;
    }
    /* err == MBPF_ERR_MISSING_SECTION is fine - debug info is optional */

    /* Add to runtime's program list */
    prog->next = rt->programs;
    rt->programs = prog;
    rt->program_count++;

    /* Trace: program loaded */
    mbpf_trace_log(rt, "program_load: prog=%s version=%s hook_type=%d",
                   prog->manifest.program_name,
                   prog->manifest.program_version,
                   prog->manifest.hook_type);

    *out_prog = prog;
    return MBPF_OK;
}

/*
 * Call mbpf_fini() if defined in the program, for a specific instance.
 * This is best-effort - exceptions are caught and logged.
 */
static void call_mbpf_fini_on_instance(mbpf_instance_t *inst) {
    if (!inst->js_initialized || !inst->js_ctx) {
        return;
    }

    JSContext *ctx = inst->js_ctx;

    /* Get global object */
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsUndefined(global) || JS_IsException(global)) {
        return;
    }

    /* Look up mbpf_fini function */
    JSValue fini_func = JS_GetPropertyStr(ctx, global, "mbpf_fini");
    if (JS_IsUndefined(fini_func) || !JS_IsFunction(ctx, fini_func)) {
        /* mbpf_fini not defined - this is fine, it's optional */
        return;
    }

    /* Check stack space: we need 2 slots (function + this) */
    if (JS_StackCheck(ctx, 2)) {
        /* Stack overflow - skip calling fini */
        if (inst->program && inst->program->runtime &&
            inst->program->runtime->config.log_fn) {
            inst->program->runtime->config.log_fn(2, "mbpf_fini: stack overflow, skipping");
        }
        return;
    }

    /* Call mbpf_fini with no arguments (order: function, this) */
    JS_PushArg(ctx, fini_func);   /* function */
    JS_PushArg(ctx, JS_NULL);     /* this */
    JSValue result = JS_Call(ctx, 0);

    /* Handle exceptions (best-effort, log and continue) */
    if (JS_IsException(result)) {
        if (inst->program && inst->program->runtime &&
            inst->program->runtime->config.log_fn) {
            inst->program->runtime->config.log_fn(2, "mbpf_fini threw exception");
        }
        JS_GetException(ctx);  /* Clear the exception */
    }
}

/* Program unloading */
int mbpf_program_unload(mbpf_runtime_t *rt, mbpf_program_t *prog) {
    if (!rt || !prog) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Handle double-unload gracefully */
    if (prog->unloaded) {
        return MBPF_ERR_ALREADY_UNLOADED;
    }

    /* Trace: program unload starting */
    mbpf_trace_log(rt, "program_unload: prog=%s", prog->manifest.program_name);

    /* Mark as unloaded immediately to prevent double-unload */
    prog->unloaded = true;

    /* Remove from runtime's program list */
    mbpf_program_t **pp = &rt->programs;
    while (*pp && *pp != prog) {
        pp = &(*pp)->next;
    }
    if (*pp) {
        *pp = prog->next;
        rt->program_count--;
    }

    /* Call mbpf_fini() on all instances and free them */
    if (prog->instances) {
        for (uint32_t i = 0; i < prog->instance_count; i++) {
            mbpf_instance_t *inst = &prog->instances[i];
            if (inst->js_initialized) {
                call_mbpf_fini_on_instance(inst);
            }
            free_instance(inst);
        }
        free(prog->instances);
        prog->instances = NULL;
    }

    /* Clean up emit buffer */
    free_emit_buffer(prog);

    /* Clean up map storage */
    free_maps(prog);

    /* Clean up debug info if present */
    if (prog->has_debug_info) {
        mbpf_debug_info_free(&prog->debug_info);
        prog->has_debug_info = false;
    }

    mbpf_manifest_free(&prog->manifest);
    if (prog->bytecode) {
        free(prog->bytecode);
        prog->bytecode = NULL;
    }
    free(prog);

    return MBPF_OK;
}

/*
 * Check if two map definitions are compatible for data preservation.
 * Maps are compatible if they have the same type, key_size, and value_size.
 * max_entries can differ - if new map is smaller, data may be truncated.
 */
static bool maps_compatible(const mbpf_map_storage_t *old_map,
                            const mbpf_map_def_t *new_def,
                            uint32_t num_instances) {
    /* Determine effective type for new map */
    uint32_t new_type = new_def->type;
    if (new_def->flags & MBPF_MAP_FLAG_PERCPU) {
        if (new_def->type == MBPF_MAP_TYPE_ARRAY) {
            new_type = MBPF_MAP_TYPE_PERCPU_ARRAY;
        } else if (new_def->type == MBPF_MAP_TYPE_HASH) {
            new_type = MBPF_MAP_TYPE_PERCPU_HASH;
        }
    }

    if (old_map->type != new_type) {
        return false;
    }

    /* Check type-specific compatibility */
    switch (old_map->type) {
        case MBPF_MAP_TYPE_ARRAY:
            return old_map->u.array.value_size == new_def->value_size;

        case MBPF_MAP_TYPE_HASH:
            return old_map->u.hash.key_size == new_def->key_size &&
                   old_map->u.hash.value_size == new_def->value_size;

        case MBPF_MAP_TYPE_LRU:
            return old_map->u.lru_hash.key_size == new_def->key_size &&
                   old_map->u.lru_hash.value_size == new_def->value_size;

        case MBPF_MAP_TYPE_PERCPU_ARRAY:
            return old_map->u.percpu_array.value_size == new_def->value_size &&
                   old_map->u.percpu_array.num_cpus == num_instances;

        case MBPF_MAP_TYPE_PERCPU_HASH:
            return old_map->u.percpu_hash.key_size == new_def->key_size &&
                   old_map->u.percpu_hash.value_size == new_def->value_size &&
                   old_map->u.percpu_hash.num_cpus == num_instances;

        case MBPF_MAP_TYPE_RING:
            return old_map->u.ring.max_event_size == new_def->value_size;

        case MBPF_MAP_TYPE_COUNTER:
            return true;  /* Counter maps are always compatible */

        default:
            return false;
    }
}

/*
 * Find a map by name in the old program's map storage.
 * Returns the index if found, or -1 if not found.
 */
static int find_map_by_name(mbpf_program_t *prog, const char *name) {
    for (uint32_t i = 0; i < prog->map_count; i++) {
        if (strncmp(prog->maps[i].name, name, sizeof(prog->maps[i].name)) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/*
 * Resize and copy map data from old storage to new storage.
 * Allocates new storage with the new max_entries and copies data.
 * For array maps: truncates if new is smaller, zero-fills if larger.
 * For hash maps: rehashes entries if capacity changes.
 * Returns 0 on success, -1 on allocation failure.
 */
static int resize_map_storage(mbpf_map_storage_t *new_storage,
                              const mbpf_map_storage_t *old_storage,
                              const mbpf_map_def_t *new_def,
                              uint32_t num_instances) {
    /* Copy basic info */
    strncpy(new_storage->name, new_def->name, sizeof(new_storage->name) - 1);
    new_storage->name[sizeof(new_storage->name) - 1] = '\0';
    new_storage->type = old_storage->type;

    switch (old_storage->type) {
        case MBPF_MAP_TYPE_ARRAY: {
            mbpf_array_map_t *new_arr = &new_storage->u.array;
            const mbpf_array_map_t *old_arr = &old_storage->u.array;

            new_arr->max_entries = new_def->max_entries;
            new_arr->value_size = old_arr->value_size;

            /* Validate allocation size against overflow */
            size_t new_data_size;
            if (!safe_size_mul((size_t)new_def->max_entries, (size_t)old_arr->value_size, &new_data_size)) {
                return -1;
            }
            size_t new_valid_size = (new_def->max_entries + 7) / 8;

            new_arr->values = calloc(1, new_data_size);
            new_arr->valid = calloc(1, new_valid_size);
            if (!new_arr->values || !new_arr->valid) {
                free(new_arr->values);
                free(new_arr->valid);
                return -1;
            }

            /* Copy data, truncating if new is smaller */
            uint32_t copy_entries = old_arr->max_entries < new_def->max_entries ?
                                    old_arr->max_entries : new_def->max_entries;
            size_t copy_data = (size_t)copy_entries * old_arr->value_size;
            memcpy(new_arr->values, old_arr->values, copy_data);

            /* Copy valid bitmap, bit by bit for the copied entries */
            for (uint32_t j = 0; j < copy_entries; j++) {
                if (old_arr->valid[j / 8] & (1 << (j % 8))) {
                    new_arr->valid[j / 8] |= (1 << (j % 8));
                }
            }
            pthread_mutex_init(&new_arr->writer_lock, NULL);
            break;
        }

        case MBPF_MAP_TYPE_HASH: {
            mbpf_hash_map_t *new_hash = &new_storage->u.hash;
            const mbpf_hash_map_t *old_hash = &old_storage->u.hash;

            new_hash->max_entries = new_def->max_entries;
            new_hash->key_size = old_hash->key_size;
            new_hash->value_size = old_hash->value_size;
            new_hash->count = 0;  /* Will be recalculated during rehash */

            /* Validate bucket size and total allocation against overflow */
            size_t old_bucket_size, new_total;
            if (!safe_size_add(1, (size_t)old_hash->key_size, &old_bucket_size) ||
                !safe_size_add(old_bucket_size, (size_t)old_hash->value_size, &old_bucket_size) ||
                !safe_size_mul((size_t)new_def->max_entries, old_bucket_size, &new_total)) {
                return -1;
            }
            size_t new_bucket_size = old_bucket_size;

            new_hash->buckets = calloc(1, new_total);
            if (!new_hash->buckets) {
                return -1;
            }

            /* Rehash valid entries from old to new */
            for (uint32_t j = 0; j < old_hash->max_entries; j++) {
                uint8_t *old_bucket = old_hash->buckets + j * old_bucket_size;
                if (old_bucket[0] != 1) continue;  /* Skip empty/deleted */

                uint8_t *key = old_bucket + 1;
                uint8_t *value = old_bucket + 1 + old_hash->key_size;

                /* FNV-1a hash */
                uint32_t h = 2166136261u;
                for (uint32_t k = 0; k < old_hash->key_size; k++) {
                    h ^= key[k];
                    h *= 16777619u;
                }

                /* Find slot in new table */
                for (uint32_t probe = 0; probe < new_def->max_entries; probe++) {
                    uint32_t idx = (h + probe) % new_def->max_entries;
                    uint8_t *new_bucket = new_hash->buckets + idx * new_bucket_size;
                    if (new_bucket[0] == 0) {
                        new_bucket[0] = 1;
                        memcpy(new_bucket + 1, key, old_hash->key_size);
                        memcpy(new_bucket + 1 + old_hash->key_size, value, old_hash->value_size);
                        new_hash->count++;
                        break;
                    }
                }
            }
            pthread_mutex_init(&new_hash->writer_lock, NULL);
            break;
        }

        case MBPF_MAP_TYPE_LRU: {
            mbpf_lru_hash_map_t *new_lru = &new_storage->u.lru_hash;
            const mbpf_lru_hash_map_t *old_lru = &old_storage->u.lru_hash;

            new_lru->max_entries = new_def->max_entries;
            new_lru->key_size = old_lru->key_size;
            new_lru->value_size = old_lru->value_size;
            new_lru->count = 0;
            new_lru->lru_head = 0xFFFFFFFF;
            new_lru->lru_tail = 0xFFFFFFFF;

            /* LRU bucket layout: [valid:1][prev:4][next:4][key][value]
             * Validate bucket size and total allocation against overflow */
            size_t old_bucket_size, new_total;
            if (!safe_size_add(9, (size_t)old_lru->key_size, &old_bucket_size) ||  /* 1 + 4 + 4 = 9 */
                !safe_size_add(old_bucket_size, (size_t)old_lru->value_size, &old_bucket_size) ||
                !safe_size_mul((size_t)new_def->max_entries, old_bucket_size, &new_total)) {
                return -1;
            }
            size_t new_bucket_size = old_bucket_size;

            new_lru->buckets = calloc(1, new_total);
            if (!new_lru->buckets) {
                return -1;
            }

            /* Collect valid entries in LRU order (MRU first) and rehash */
            /* We need to maintain LRU order during resize */
            uint32_t idx = old_lru->lru_head;
            while (idx != 0xFFFFFFFF && new_lru->count < new_def->max_entries) {
                uint8_t *old_bucket = old_lru->buckets + idx * old_bucket_size;
                if (old_bucket[0] != 1) break;  /* Should not happen in valid list */

                uint8_t *key = old_bucket + 9;  /* Skip valid + prev + next */
                uint8_t *value = old_bucket + 9 + old_lru->key_size;

                /* FNV-1a hash */
                uint32_t h = 2166136261u;
                for (uint32_t k = 0; k < old_lru->key_size; k++) {
                    h ^= key[k];
                    h *= 16777619u;
                }

                /* Find slot in new table */
                for (uint32_t probe = 0; probe < new_def->max_entries; probe++) {
                    uint32_t new_idx = (h + probe) % new_def->max_entries;
                    uint8_t *new_bucket = new_lru->buckets + new_idx * new_bucket_size;
                    if (new_bucket[0] == 0) {
                        new_bucket[0] = 1;
                        /* Set prev/next for LRU list - add to tail */
                        uint32_t prev_tail = new_lru->lru_tail;
                        /* prev = prev_tail */
                        new_bucket[1] = prev_tail & 0xFF;
                        new_bucket[2] = (prev_tail >> 8) & 0xFF;
                        new_bucket[3] = (prev_tail >> 16) & 0xFF;
                        new_bucket[4] = (prev_tail >> 24) & 0xFF;
                        /* next = NULL */
                        new_bucket[5] = 0xFF;
                        new_bucket[6] = 0xFF;
                        new_bucket[7] = 0xFF;
                        new_bucket[8] = 0xFF;
                        /* Copy key and value */
                        memcpy(new_bucket + 9, key, old_lru->key_size);
                        memcpy(new_bucket + 9 + old_lru->key_size, value, old_lru->value_size);

                        /* Update LRU list */
                        if (prev_tail != 0xFFFFFFFF) {
                            uint8_t *prev_bucket = new_lru->buckets + prev_tail * new_bucket_size;
                            prev_bucket[5] = new_idx & 0xFF;
                            prev_bucket[6] = (new_idx >> 8) & 0xFF;
                            prev_bucket[7] = (new_idx >> 16) & 0xFF;
                            prev_bucket[8] = (new_idx >> 24) & 0xFF;
                        }
                        if (new_lru->lru_head == 0xFFFFFFFF) {
                            new_lru->lru_head = new_idx;
                        }
                        new_lru->lru_tail = new_idx;
                        new_lru->count++;
                        break;
                    }
                }

                /* Move to next in old LRU list */
                uint32_t next_idx = (uint32_t)old_bucket[5] |
                                   ((uint32_t)old_bucket[6] << 8) |
                                   ((uint32_t)old_bucket[7] << 16) |
                                   ((uint32_t)old_bucket[8] << 24);
                idx = next_idx;
            }
            break;
        }

        case MBPF_MAP_TYPE_PERCPU_ARRAY: {
            mbpf_percpu_array_map_t *new_pca = &new_storage->u.percpu_array;
            const mbpf_percpu_array_map_t *old_pca = &old_storage->u.percpu_array;

            new_pca->max_entries = new_def->max_entries;
            new_pca->value_size = old_pca->value_size;
            new_pca->num_cpus = num_instances;

            /* Validate allocation size against overflow */
            size_t new_data_size;
            if (!safe_size_mul((size_t)new_def->max_entries, (size_t)old_pca->value_size, &new_data_size)) {
                return -1;
            }

            new_pca->values = calloc(num_instances, sizeof(uint8_t *));
            new_pca->valid = calloc(num_instances, sizeof(uint8_t *));
            if (!new_pca->values || !new_pca->valid) {
                free(new_pca->values);
                free(new_pca->valid);
                return -1;
            }
            uint32_t copy_entries = old_pca->max_entries < new_def->max_entries ?
                                    old_pca->max_entries : new_def->max_entries;
            size_t copy_data = (size_t)copy_entries * old_pca->value_size;

            for (uint32_t cpu = 0; cpu < num_instances; cpu++) {
                new_pca->values[cpu] = calloc(1, new_data_size);
                new_pca->valid[cpu] = calloc(new_def->max_entries, 1);
                if (!new_pca->values[cpu] || !new_pca->valid[cpu]) {
                    /* Cleanup on failure */
                    for (uint32_t c = 0; c <= cpu; c++) {
                        free(new_pca->values[c]);
                        free(new_pca->valid[c]);
                    }
                    free(new_pca->values);
                    free(new_pca->valid);
                    return -1;
                }

                if (cpu < old_pca->num_cpus && old_pca->values[cpu] && old_pca->valid[cpu]) {
                    memcpy(new_pca->values[cpu], old_pca->values[cpu], copy_data);
                    memcpy(new_pca->valid[cpu], old_pca->valid[cpu], copy_entries);
                }
            }
            break;
        }

        case MBPF_MAP_TYPE_PERCPU_HASH: {
            mbpf_percpu_hash_map_t *new_pch = &new_storage->u.percpu_hash;
            const mbpf_percpu_hash_map_t *old_pch = &old_storage->u.percpu_hash;

            new_pch->max_entries = new_def->max_entries;
            new_pch->key_size = old_pch->key_size;
            new_pch->value_size = old_pch->value_size;
            new_pch->num_cpus = num_instances;

            /* Validate bucket size and total allocation against overflow */
            size_t old_bucket_size, new_total;
            if (!safe_size_add(1, (size_t)old_pch->key_size, &old_bucket_size) ||
                !safe_size_add(old_bucket_size, (size_t)old_pch->value_size, &old_bucket_size) ||
                !safe_size_mul((size_t)new_def->max_entries, old_bucket_size, &new_total)) {
                return -1;
            }
            size_t new_bucket_size = old_bucket_size;

            new_pch->buckets = calloc(num_instances, sizeof(uint8_t *));
            new_pch->counts = calloc(num_instances, sizeof(uint32_t));
            if (!new_pch->buckets || !new_pch->counts) {
                free(new_pch->buckets);
                free(new_pch->counts);
                return -1;
            }

            for (uint32_t cpu = 0; cpu < num_instances; cpu++) {
                new_pch->buckets[cpu] = calloc(1, new_total);
                if (!new_pch->buckets[cpu]) {
                    for (uint32_t c = 0; c < cpu; c++) {
                        free(new_pch->buckets[c]);
                    }
                    free(new_pch->buckets);
                    free(new_pch->counts);
                    return -1;
                }
                new_pch->counts[cpu] = 0;

                if (cpu < old_pch->num_cpus && old_pch->buckets[cpu]) {
                    /* Rehash entries for this CPU */
                    for (uint32_t j = 0; j < old_pch->max_entries; j++) {
                        uint8_t *old_bucket = old_pch->buckets[cpu] + j * old_bucket_size;
                        if (old_bucket[0] != 1) continue;

                        uint8_t *key = old_bucket + 1;
                        uint8_t *value = old_bucket + 1 + old_pch->key_size;

                        uint32_t h = 2166136261u;
                        for (uint32_t k = 0; k < old_pch->key_size; k++) {
                            h ^= key[k];
                            h *= 16777619u;
                        }

                        for (uint32_t probe = 0; probe < new_def->max_entries; probe++) {
                            uint32_t idx = (h + probe) % new_def->max_entries;
                            uint8_t *new_bucket = new_pch->buckets[cpu] + idx * new_bucket_size;
                            if (new_bucket[0] == 0) {
                                new_bucket[0] = 1;
                                memcpy(new_bucket + 1, key, old_pch->key_size);
                                memcpy(new_bucket + 1 + old_pch->key_size, value, old_pch->value_size);
                                new_pch->counts[cpu]++;
                                break;
                            }
                        }
                    }
                }
            }
            break;
        }

        case MBPF_MAP_TYPE_RING: {
            /* Ring buffers are event streams - resize buffer but don't preserve data */
            mbpf_ring_buffer_map_t *new_ring = &new_storage->u.ring;
            const mbpf_ring_buffer_map_t *old_ring = &old_storage->u.ring;

            /* Validate buffer size against overflow: buffer_size = max_entries * value_size */
            size_t buffer_size;
            if (!safe_size_mul((size_t)new_def->max_entries, (size_t)new_def->value_size, &buffer_size)) {
                return -1;
            }
            if (buffer_size > UINT32_MAX) {
                return -1;
            }
            if (buffer_size < 64) {
                buffer_size = 64;  /* Minimum 64 bytes */
            }

            new_ring->buffer_size = (uint32_t)buffer_size;
            new_ring->max_event_size = old_ring->max_event_size;
            new_ring->head = 0;
            new_ring->tail = 0;
            new_ring->dropped = 0;
            new_ring->event_count = 0;

            new_ring->buffer = calloc(1, buffer_size);
            if (!new_ring->buffer) {
                return -1;
            }
            /* Don't copy old ring data - it's an event stream */
            break;
        }

        case MBPF_MAP_TYPE_COUNTER: {
            mbpf_counter_map_t *new_cnt = &new_storage->u.counter;
            const mbpf_counter_map_t *old_cnt = &old_storage->u.counter;

            new_cnt->max_entries = new_def->max_entries;

            /* Validate allocation size against overflow */
            size_t counters_size;
            if (!safe_size_mul((size_t)new_def->max_entries, sizeof(int64_t), &counters_size)) {
                return -1;
            }

            new_cnt->counters = calloc(counters_size, 1);
            if (!new_cnt->counters) {
                return -1;
            }

            /* Copy counters, truncating if smaller */
            uint32_t copy_entries = old_cnt->max_entries < new_def->max_entries ?
                                    old_cnt->max_entries : new_def->max_entries;
            memcpy(new_cnt->counters, old_cnt->counters, copy_entries * sizeof(int64_t));
            break;
        }

        default:
            return -1;
    }

    return 0;
}

/*
 * Update a program to a new version (hot swap).
 * By default, maps are preserved if the new program's map definitions are
 * compatible with the old program's maps (same name, type, key_size, value_size).
 */
int mbpf_program_update(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        const void *pkg, size_t pkg_len,
                        const mbpf_update_opts_t *opts) {
    if (!rt || !prog || !pkg || pkg_len < sizeof(mbpf_file_header_t)) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Verify the program is in this runtime's program list (catches use-after-free) */
    bool found = false;
    for (mbpf_program_t *p = rt->programs; p; p = p->next) {
        if (p == prog) {
            found = true;
            break;
        }
    }
    if (!found) {
        /* Program was unloaded (freed) or never belonged to this runtime */
        return MBPF_ERR_ALREADY_UNLOADED;
    }

    if (prog->runtime != rt) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Program must be detached before update */
    if (prog->attached) {
        return MBPF_ERR_STILL_ATTACHED;
    }

    /* Cannot update an unloaded program (redundant but kept for clarity) */
    if (prog->unloaded) {
        return MBPF_ERR_ALREADY_UNLOADED;
    }

    /* Parse new package header */
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(pkg, pkg_len, &header);
    if (err != MBPF_OK) {
        return err;
    }

    /* Parse new manifest */
    const void *manifest_data;
    size_t manifest_len;
    err = mbpf_package_get_section(pkg, pkg_len, MBPF_SEC_MANIFEST,
                                   &manifest_data, &manifest_len);
    if (err != MBPF_OK) {
        return MBPF_ERR_MISSING_SECTION;
    }

    mbpf_manifest_t new_manifest;
    memset(&new_manifest, 0, sizeof(new_manifest));
    err = mbpf_package_parse_manifest(manifest_data, manifest_len, &new_manifest);
    if (err != MBPF_OK) {
        return err;
    }

    /* Validate heap_size is at least the platform minimum */
    if (new_manifest.heap_size < MBPF_MIN_HEAP_SIZE) {
        mbpf_manifest_free(&new_manifest);
        return MBPF_ERR_HEAP_TOO_SMALL;
    }

    /* Validate capabilities: program must not request capabilities not allowed by runtime */
    uint32_t requested_caps = new_manifest.capabilities;
    uint32_t allowed_caps = rt->config.allowed_capabilities;
    if ((requested_caps & ~allowed_caps) != 0) {
        mbpf_manifest_free(&new_manifest);
        return MBPF_ERR_CAPABILITY_DENIED;
    }

    /* Get new bytecode section */
    const void *bytecode_data;
    size_t bytecode_len;
    err = mbpf_package_get_section(pkg, pkg_len, MBPF_SEC_BYTECODE,
                                   &bytecode_data, &bytecode_len);
    if (err != MBPF_OK) {
        mbpf_manifest_free(&new_manifest);
        return MBPF_ERR_MISSING_SECTION;
    }

    /* Determine map policy */
    uint32_t map_policy = MBPF_MAP_POLICY_PRESERVE;
    if (opts && opts->map_policy == MBPF_MAP_POLICY_DESTROY) {
        map_policy = MBPF_MAP_POLICY_DESTROY;
    }

    /* Check map compatibility if we want to preserve */
    bool can_preserve_maps = (map_policy == MBPF_MAP_POLICY_PRESERVE);

    if (can_preserve_maps && new_manifest.maps && new_manifest.map_count > 0) {
        /* Check each new map has a compatible old map */
        for (uint32_t i = 0; i < new_manifest.map_count; i++) {
            mbpf_map_def_t *new_def = &new_manifest.maps[i];
            int old_idx = find_map_by_name(prog, new_def->name);
            if (old_idx < 0) {
                /* New map doesn't exist in old program - can't preserve */
                can_preserve_maps = false;
                break;
            }
            if (!maps_compatible(&prog->maps[old_idx], new_def, prog->instance_count)) {
                /* Map schema changed - can't preserve */
                can_preserve_maps = false;
                break;
            }
        }
    }

    /* Save old maps if we're preserving them */
    mbpf_map_storage_t *old_maps = NULL;
    uint32_t old_map_count = 0;

    if (can_preserve_maps) {
        /* Sync map data from JS to C storage before destroying instances.
         * For regular maps, we only need instance 0 since they share storage.
         * For per-CPU maps, each instance has its own storage, so sync all. */
        if (prog->instances && prog->instance_count > 0) {
            for (uint32_t i = 0; i < prog->instance_count; i++) {
                sync_maps_from_js_to_c(&prog->instances[i], prog, i);
            }
        }

        old_maps = prog->maps;
        old_map_count = prog->map_count;
        prog->maps = NULL;
        prog->map_count = 0;
    }

    /* Call mbpf_fini() on all instances before tearing down */
    if (prog->instances) {
        for (uint32_t i = 0; i < prog->instance_count; i++) {
            mbpf_instance_t *inst = &prog->instances[i];
            if (inst->js_initialized) {
                call_mbpf_fini_on_instance(inst);
            }
        }
    }

    /* Free old instances */
    if (prog->instances) {
        for (uint32_t i = 0; i < prog->instance_count; i++) {
            free_instance(&prog->instances[i]);
        }
        free(prog->instances);
        prog->instances = NULL;
    }

    /* Free old maps if not preserving */
    if (!can_preserve_maps) {
        free_maps(prog);
    }

    /* Allocate new bytecode BEFORE freeing old resources.
     * This ensures the program remains in a consistent state on allocation failure. */
    void *new_bytecode = malloc(bytecode_len);
    if (!new_bytecode) {
        /* Restore old maps on failure */
        if (old_maps) {
            prog->maps = old_maps;
            prog->map_count = old_map_count;
        }
        mbpf_manifest_free(&new_manifest);
        return MBPF_ERR_NO_MEM;
    }
    memcpy(new_bytecode, bytecode_data, bytecode_len);

    /* Now free old resources and install new ones */
    if (prog->bytecode) {
        free(prog->bytecode);
    }
    prog->bytecode = new_bytecode;
    prog->bytecode_len = bytecode_len;

    /* Free old manifest and install new one */
    mbpf_manifest_free(&prog->manifest);
    prog->manifest = new_manifest;

    /* Determine heap size */
    size_t heap_size = prog->manifest.heap_size;
    if (heap_size < rt->config.default_heap_size) {
        heap_size = rt->config.default_heap_size;
    }

    /* Allocate new instances */
    prog->instances = calloc(prog->instance_count, sizeof(mbpf_instance_t));
    if (!prog->instances) {
        free(prog->bytecode);
        prog->bytecode = NULL;
        if (old_maps) {
            prog->maps = old_maps;
            prog->map_count = old_map_count;
        }
        return MBPF_ERR_NO_MEM;
    }

    /* Handle map storage */
    if (can_preserve_maps && old_maps) {
        /* Restore preserved maps with potentially new map ordering and resizing */
        prog->map_count = prog->manifest.map_count;
        /* Handle zero maps case: calloc(0, size) may return NULL or a unique pointer.
         * Only treat NULL as failure when map_count > 0. */
        if (prog->map_count > 0) {
            prog->maps = calloc(prog->map_count, sizeof(mbpf_map_storage_t));
            if (!prog->maps) {
                free(prog->instances);
                prog->instances = NULL;
                free(prog->bytecode);
                prog->bytecode = NULL;
                /* Restore old maps temporarily just to free them properly */
                prog->maps = old_maps;
                prog->map_count = old_map_count;
                free_maps(prog);
                return MBPF_ERR_NO_MEM;
            }
        } else {
            prog->maps = NULL;
        }

        /* Track which old maps were used so we can free the rest */
        bool *old_map_used = NULL;
        if (old_map_count > 0) {
            old_map_used = calloc(old_map_count, sizeof(bool));
            if (!old_map_used) {
                free(prog->maps);
                prog->maps = old_maps;
                prog->map_count = old_map_count;
                free_maps(prog);
                free(prog->instances);
                prog->instances = NULL;
                free(prog->bytecode);
                prog->bytecode = NULL;
                return MBPF_ERR_NO_MEM;
            }
        }

        /* Copy and resize compatible maps from old storage to new positions */
        for (uint32_t i = 0; i < prog->map_count; i++) {
            mbpf_map_def_t *new_def = &prog->manifest.maps[i];
            int old_idx = -1;

            /* Find the old map with this name */
            for (uint32_t j = 0; j < old_map_count; j++) {
                if (strncmp(old_maps[j].name, new_def->name,
                            sizeof(old_maps[j].name)) == 0) {
                    old_idx = (int)j;
                    break;
                }
            }

            if (old_idx >= 0) {
                /* Resize and copy map data using new max_entries */
                if (resize_map_storage(&prog->maps[i], &old_maps[old_idx],
                                       new_def, prog->instance_count) != 0) {
                    /* Cleanup on failure */
                    for (uint32_t k = 0; k < i; k++) {
                        /* Free already-allocated new maps */
                        mbpf_map_storage_t *s = &prog->maps[k];
                        if (s->type == MBPF_MAP_TYPE_ARRAY) {
                            pthread_mutex_destroy(&s->u.array.writer_lock);
                            free(s->u.array.values);
                            free(s->u.array.valid);
                        } else if (s->type == MBPF_MAP_TYPE_HASH) {
                            pthread_mutex_destroy(&s->u.hash.writer_lock);
                            free(s->u.hash.buckets);
                        } else if (s->type == MBPF_MAP_TYPE_LRU) {
                            pthread_mutex_destroy(&s->u.lru_hash.writer_lock);
                            free(s->u.lru_hash.buckets);
                        } else if (s->type == MBPF_MAP_TYPE_PERCPU_ARRAY) {
                            for (uint32_t cpu = 0; cpu < s->u.percpu_array.num_cpus; cpu++) {
                                free(s->u.percpu_array.values[cpu]);
                                free(s->u.percpu_array.valid[cpu]);
                            }
                            free(s->u.percpu_array.values);
                            free(s->u.percpu_array.valid);
                        } else if (s->type == MBPF_MAP_TYPE_PERCPU_HASH) {
                            for (uint32_t cpu = 0; cpu < s->u.percpu_hash.num_cpus; cpu++) {
                                free(s->u.percpu_hash.buckets[cpu]);
                            }
                            free(s->u.percpu_hash.buckets);
                            free(s->u.percpu_hash.counts);
                        } else if (s->type == MBPF_MAP_TYPE_RING) {
                            free(s->u.ring.buffer);
                        } else if (s->type == MBPF_MAP_TYPE_COUNTER) {
                            free(s->u.counter.counters);
                        }
                    }
                    free(prog->maps);
                    prog->maps = old_maps;
                    prog->map_count = old_map_count;
                    free_maps(prog);
                    free(old_map_used);
                    free(prog->instances);
                    prog->instances = NULL;
                    free(prog->bytecode);
                    prog->bytecode = NULL;
                    return MBPF_ERR_NO_MEM;
                }
                old_map_used[old_idx] = true;
            }
        }

        /* Free old maps (all of them - new storage was allocated in resize_map_storage) */
        for (uint32_t i = 0; i < old_map_count; i++) {
            mbpf_map_storage_t *storage = &old_maps[i];
            if (storage->type == MBPF_MAP_TYPE_ARRAY && storage->u.array.values) {
                pthread_mutex_destroy(&storage->u.array.writer_lock);
                free(storage->u.array.values);
                free(storage->u.array.valid);
            } else if (storage->type == MBPF_MAP_TYPE_HASH && storage->u.hash.buckets) {
                pthread_mutex_destroy(&storage->u.hash.writer_lock);
                free(storage->u.hash.buckets);
            } else if (storage->type == MBPF_MAP_TYPE_LRU && storage->u.lru_hash.buckets) {
                pthread_mutex_destroy(&storage->u.lru_hash.writer_lock);
                free(storage->u.lru_hash.buckets);
            } else if (storage->type == MBPF_MAP_TYPE_PERCPU_ARRAY && storage->u.percpu_array.values) {
                for (uint32_t cpu = 0; cpu < storage->u.percpu_array.num_cpus; cpu++) {
                    free(storage->u.percpu_array.values[cpu]);
                    free(storage->u.percpu_array.valid[cpu]);
                }
                free(storage->u.percpu_array.values);
                free(storage->u.percpu_array.valid);
            } else if (storage->type == MBPF_MAP_TYPE_PERCPU_HASH && storage->u.percpu_hash.buckets) {
                for (uint32_t cpu = 0; cpu < storage->u.percpu_hash.num_cpus; cpu++) {
                    free(storage->u.percpu_hash.buckets[cpu]);
                }
                free(storage->u.percpu_hash.buckets);
                free(storage->u.percpu_hash.counts);
            } else if (storage->type == MBPF_MAP_TYPE_RING && storage->u.ring.buffer) {
                free(storage->u.ring.buffer);
            } else if (storage->type == MBPF_MAP_TYPE_COUNTER && storage->u.counter.counters) {
                free(storage->u.counter.counters);
            }
        }
        free(old_maps);
        free(old_map_used);
    } else {
        /* Create fresh maps from new manifest */
        if (create_maps_from_manifest(prog, prog->instance_count) != 0) {
            free(prog->instances);
            prog->instances = NULL;
            free(prog->bytecode);
            prog->bytecode = NULL;
            return MBPF_ERR_NO_MEM;
        }
    }

    /* Create new instances */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        err = create_instance(prog, i, heap_size, bytecode_data, bytecode_len);
        if (err != MBPF_OK) {
            for (uint32_t j = 0; j < i; j++) {
                free_instance(&prog->instances[j]);
            }
            free(prog->instances);
            prog->instances = NULL;
            free(prog->bytecode);
            prog->bytecode = NULL;
            free_maps(prog);
            return err;
        }
    }

    /* Update bc_info */
    mbpf_bytecode_check(prog->bytecode, prog->bytecode_len, &prog->bc_info);

    /* Set up mbpf and maps objects in each instance's JS context */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        if (setup_mbpf_object(prog->instances[i].js_ctx, prog->manifest.capabilities) != 0 ||
            setup_helper_tracking(prog->instances[i].js_ctx, prog->instances[i].max_helpers) != 0 ||
            setup_maps_object(prog->instances[i].js_ctx, prog, i) != 0 ||
            setup_lowlevel_map_helpers(prog->instances[i].js_ctx, prog) != 0) {
            for (uint32_t j = 0; j < prog->instance_count; j++) {
                free_instance(&prog->instances[j]);
            }
            free(prog->instances);
            prog->instances = NULL;
            free(prog->bytecode);
            prog->bytecode = NULL;
            free_maps(prog);
            return MBPF_ERR_NO_MEM;
        }
    }

    /* If we preserved maps, sync the C storage data to the new JS arrays */
    if (can_preserve_maps) {
        for (uint32_t i = 0; i < prog->instance_count; i++) {
            sync_maps_from_c_to_js(&prog->instances[i], prog, i);
        }
    }

    /* Register GC-protected references for persistent values.
     * This must be done after setup_maps_object so that both the entry
     * function and maps object are available for caching. */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        if (register_gc_refs(&prog->instances[i], prog->manifest.entry_symbol) != 0) {
            for (uint32_t j = 0; j < prog->instance_count; j++) {
                free_instance(&prog->instances[j]);
            }
            free(prog->instances);
            prog->instances = NULL;
            free(prog->bytecode);
            prog->bytecode = NULL;
            free_maps(prog);
            return MBPF_ERR_NO_MEM;
        }
    }

    /* Initialize reusable context object infrastructure for each instance */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        if (init_reusable_ctx(&prog->instances[i]) != 0) {
            /* Non-fatal - fall back to per-invocation ctx creation */
            prog->instances[i].ctx_initialized = false;
        }
    }

    /* Call mbpf_init() on all instances */
    for (uint32_t i = 0; i < prog->instance_count; i++) {
        err = call_mbpf_init_on_instance(&prog->instances[i]);
        if (err != MBPF_OK) {
            for (uint32_t j = 0; j < prog->instance_count; j++) {
                free_instance(&prog->instances[j]);
            }
            free(prog->instances);
            prog->instances = NULL;
            free(prog->bytecode);
            prog->bytecode = NULL;
            free_maps(prog);
            return err;
        }
    }

    return MBPF_OK;
}

/* Program attach */
int mbpf_program_attach(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        mbpf_hook_id_t hook) {
    if (!rt || !prog) {
        return MBPF_ERR_INVALID_ARG;
    }

    if (prog->runtime != rt) {
        return MBPF_ERR_INVALID_ARG;
    }

    if (hook != (mbpf_hook_id_t)prog->manifest.hook_type) {
        return MBPF_ERR_HOOK_MISMATCH;
    }

    /* Validate hook context ABI version compatibility.
     * The program's required ABI version must match the runtime's supported version. */
    uint32_t runtime_abi = mbpf_hook_abi_version((mbpf_hook_type_t)hook);
    if (runtime_abi == 0) {
        return MBPF_ERR_HOOK_MISMATCH;  /* Unknown hook type */
    }
    if (prog->manifest.hook_ctx_abi_version != runtime_abi) {
        return MBPF_ERR_ABI_MISMATCH;
    }

    if (prog->attached) {
        return MBPF_ERR_ALREADY_ATTACHED;
    }

    prog->attached_hook = hook;
    prog->attached = true;

    /* Trace: program attached */
    mbpf_trace_log(rt, "program_attach: prog=%s hook=%u",
                   prog->manifest.program_name, hook);

    return MBPF_OK;
}

/* Program detach */
int mbpf_program_detach(mbpf_runtime_t *rt, mbpf_program_t *prog,
                        mbpf_hook_id_t hook) {
    if (!rt || !prog) {
        return MBPF_ERR_INVALID_ARG;
    }

    if (prog->runtime != rt) {
        return MBPF_ERR_INVALID_ARG;
    }

    if (!prog->attached || prog->attached_hook != hook) {
        return MBPF_ERR_NOT_ATTACHED;
    }

    prog->attached = false;
    prog->attached_hook = 0;

    /* Trace: program detached */
    mbpf_trace_log(rt, "program_detach: prog=%s hook=%u",
                   prog->manifest.program_name, hook);

    return MBPF_OK;
}

/*
 * Select an instance for execution.
 * For per-CPU mode, selects based on current CPU.
 * For single mode, always returns instance 0.
 */
static mbpf_instance_t *select_instance(mbpf_program_t *prog) {
    if (!prog->instances || prog->instance_count == 0) {
        return NULL;
    }

    /* For single instance mode, always use instance 0 */
    if (prog->instance_count == 1) {
        return &prog->instances[0];
    }

    /* For per-CPU mode, select based on sched_getcpu() or round-robin */
#ifdef _GNU_SOURCE
    int cpu = sched_getcpu();
    if (cpu >= 0) {
        return &prog->instances[cpu % prog->instance_count];
    }
#endif

    /* Fallback: use instance 0 */
    return &prog->instances[0];
}

/*
 * Create a NET_RX context object from ctx_blob.
 * Returns JS object with read-only ifindex, pkt_len, data_len, l2_proto properties
 * and readU8, readU16LE, readU32LE, readBytes methods.
 *
 * Properties are implemented as getter+empty setter pairs via Object.defineProperty,
 * so writes are silently ignored without throwing exceptions.
 *
 * The read methods are pure JS implementations that operate on an internal data buffer.
 */
static JSValue create_net_rx_ctx(JSContext *ctx, const void *ctx_blob, size_t ctx_len) {
    if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_net_rx_v1_t)) {
        return JS_NULL;
    }

    const mbpf_ctx_net_rx_v1_t *net_ctx = (const mbpf_ctx_net_rx_v1_t *)ctx_blob;

    /* Determine if we have data to embed */
    const uint8_t *data = net_ctx->data;
    uint32_t data_len = net_ctx->data_len;
    uint8_t *owned_data = NULL;

    /* If no contiguous data but a read_fn is provided, snapshot via read_fn. */
    if (!data && net_ctx->read_fn && data_len > 0) {
        owned_data = malloc(data_len);
        if (!owned_data) {
            return JS_NULL;
        }

        int read_rc = net_ctx->read_fn(ctx_blob, 0, data_len, owned_data);
        if (read_rc <= 0) {
            free(owned_data);
            owned_data = NULL;
            data = NULL;
            data_len = 0;
        } else {
            data = owned_data;
            if ((uint32_t)read_rc < data_len) {
                data_len = (uint32_t)read_rc;
            }
        }
    }

    /* Build JS code to create a new object.
     * If data is available, we create a Uint8Array with the data embedded
     * and add read methods that operate on it. */

    /* Calculate buffer size needed:
     * - Base JS code: ~2000 bytes
     * - Data as hex: data_len * 4 bytes (for "0xXX," format)
     * - Safety margin: 512 bytes
     */
    size_t code_size = 2512;
    if (data && data_len > 0) {
        code_size += data_len * 5;  /* "0xXX," = 5 chars per byte */
    }

    char *code = malloc(code_size);
    if (!code) {
        free(owned_data);
        return JS_NULL;
    }

    char *p = code;
    size_t remaining = code_size;
    int written;

    /* Start the IIFE */
    written = snprintf(p, remaining, "(function(){var o={};");
    p += written;
    remaining -= written;

    /* Add read-only scalar properties */
    written = snprintf(p, remaining,
        "Object.defineProperty(o,'ifindex',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'pkt_len',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'data_len',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'l2_proto',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'flags',{get:function(){return %u;},set:function(){}});",
        net_ctx->ifindex,
        net_ctx->pkt_len,
        net_ctx->data_len,
        (uint32_t)net_ctx->l2_proto,
        (uint32_t)net_ctx->flags);
    p += written;
    remaining -= written;

    /* Add data buffer and read methods if data is available */
    if (data && data_len > 0) {
        /* Create internal data array */
        written = snprintf(p, remaining, "var d=new Uint8Array([");
        p += written;
        remaining -= written;

        for (uint32_t i = 0; i < data_len; i++) {
            if (i > 0) {
                *p++ = ',';
                remaining--;
            }
            written = snprintf(p, remaining, "%u", data[i]);
            p += written;
            remaining -= written;
        }

        written = snprintf(p, remaining, "]);");
        p += written;
        remaining -= written;

        /* Add readU8 method */
        written = snprintf(p, remaining,
            "o.readU8=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off>=d.length)throw new RangeError('offset out of bounds');"
            "return d[off];"
            "};");
        p += written;
        remaining -= written;

        /* Add readU16LE method */
        written = snprintf(p, remaining,
            "o.readU16LE=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off+2>d.length)throw new RangeError('offset out of bounds');"
            "return d[off]|(d[off+1]<<8);"
            "};");
        p += written;
        remaining -= written;

        /* Add readU32LE method */
        written = snprintf(p, remaining,
            "o.readU32LE=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off+4>d.length)throw new RangeError('offset out of bounds');"
            "return (d[off]|(d[off+1]<<8)|(d[off+2]<<16)|(d[off+3]<<24))>>>0;"
            "};");
        p += written;
        remaining -= written;

        /* Add readBytes method */
        written = snprintf(p, remaining,
            "o.readBytes=function(off,len,buf){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(typeof len!=='number')throw new TypeError('length must be a number');"
            "if(!(buf instanceof Uint8Array))throw new TypeError('outBuffer must be a Uint8Array');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(len<0)throw new RangeError('length must be non-negative');"
            "if(off>=d.length)throw new RangeError('offset out of bounds');"
            "var n=len;if(off+n>d.length)n=d.length-off;if(n>buf.length)n=buf.length;"
            "for(var i=0;i<n;i++)buf[i]=d[off+i];"
            "return n;"
            "};");
        p += written;
        remaining -= written;
    } else {
        /* No data available - add methods that always throw */
        written = snprintf(p, remaining,
            "o.readU8=function(){throw new RangeError('no data available');};"
            "o.readU16LE=function(){throw new RangeError('no data available');};"
            "o.readU32LE=function(){throw new RangeError('no data available');};"
            "o.readBytes=function(){throw new RangeError('no data available');};");
        p += written;
        remaining -= written;
    }

    /* Close the IIFE and return the object */
    written = snprintf(p, remaining, "return o;})()");
    p += written;

    JSValue result = JS_Eval(ctx, code, strlen(code), "<ctx>", JS_EVAL_RETVAL);
    free(code);
    free(owned_data);

    if (JS_IsException(result)) {
        JSValue ex = JS_GetException(ctx);
        (void)ex;
        return JS_NULL;
    }

    return result;
}

/*
 * Create a TIMER context object from ctx_blob.
 * Returns JS object with read-only timer_id, period_us, invocation_count,
 * timestamp, and flags properties.
 * Timer contexts do not have data buffers or read methods.
 */
static JSValue create_timer_ctx(JSContext *ctx, const void *ctx_blob, size_t ctx_len) {
    if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_timer_v1_t)) {
        return JS_NULL;
    }

    const mbpf_ctx_timer_v1_t *timer_ctx = (const mbpf_ctx_timer_v1_t *)ctx_blob;

    /* Build JS code to create a new object with read-only properties. */
    char code[1024];
    int written = snprintf(code, sizeof(code),
        "(function(){var o={};"
        "Object.defineProperty(o,'timer_id',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'period_us',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'invocation_count',{get:function(){return %llu;},set:function(){}});"
        "Object.defineProperty(o,'timestamp',{get:function(){return %llu;},set:function(){}});"
        "Object.defineProperty(o,'flags',{get:function(){return %u;},set:function(){}});"
        "return o;})()",
        timer_ctx->timer_id,
        timer_ctx->period_us,
        (unsigned long long)timer_ctx->invocation_count,
        (unsigned long long)timer_ctx->timestamp,
        (uint32_t)timer_ctx->flags);

    if (written < 0 || (size_t)written >= sizeof(code)) {
        return JS_NULL;
    }

    JSValue result = JS_Eval(ctx, code, strlen(code), "<ctx>", JS_EVAL_RETVAL);

    if (JS_IsException(result)) {
        JSValue ex = JS_GetException(ctx);
        (void)ex;
        return JS_NULL;
    }

    return result;
}

/*
 * Create a TRACEPOINT context object from ctx_blob.
 * Returns JS object with read-only tracepoint_id, timestamp, cpu, pid,
 * data_len, flags properties and readU8, readU16LE, readU32LE, readBytes methods.
 */
static JSValue create_tracepoint_ctx(JSContext *ctx, const void *ctx_blob, size_t ctx_len) {
    if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_tracepoint_v1_t)) {
        return JS_NULL;
    }

    const mbpf_ctx_tracepoint_v1_t *tp_ctx = (const mbpf_ctx_tracepoint_v1_t *)ctx_blob;

    /* Determine if we have data to embed */
    const uint8_t *data = tp_ctx->data;
    uint32_t data_len = tp_ctx->data_len;
    uint8_t *owned_data = NULL;

    /* If no contiguous data but a read_fn is provided, snapshot via read_fn. */
    if (!data && tp_ctx->read_fn && data_len > 0) {
        owned_data = malloc(data_len);
        if (!owned_data) {
            return JS_NULL;
        }

        int read_rc = tp_ctx->read_fn(ctx_blob, 0, data_len, owned_data);
        if (read_rc <= 0) {
            free(owned_data);
            owned_data = NULL;
            data = NULL;
            data_len = 0;
        } else {
            data = owned_data;
            if ((uint32_t)read_rc < data_len) {
                data_len = (uint32_t)read_rc;
            }
        }
    }

    /* Build JS code to create a new object. */
    size_t code_size = 2512;
    if (data && data_len > 0) {
        code_size += data_len * 5;
    }

    char *code = malloc(code_size);
    if (!code) {
        free(owned_data);
        return JS_NULL;
    }

    char *p = code;
    size_t remaining = code_size;
    int written;

    /* Start the IIFE */
    written = snprintf(p, remaining, "(function(){var o={};");
    p += written;
    remaining -= written;

    /* Add read-only scalar properties */
    written = snprintf(p, remaining,
        "Object.defineProperty(o,'tracepoint_id',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'timestamp',{get:function(){return %llu;},set:function(){}});"
        "Object.defineProperty(o,'cpu',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'pid',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'data_len',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'flags',{get:function(){return %u;},set:function(){}});",
        tp_ctx->tracepoint_id,
        (unsigned long long)tp_ctx->timestamp,
        tp_ctx->cpu,
        tp_ctx->pid,
        tp_ctx->data_len,
        (uint32_t)tp_ctx->flags);
    p += written;
    remaining -= written;

    /* Add data buffer and read methods if data is available */
    if (data && data_len > 0) {
        /* Create internal data array */
        written = snprintf(p, remaining, "var d=new Uint8Array([");
        p += written;
        remaining -= written;

        for (uint32_t i = 0; i < data_len; i++) {
            if (i > 0) {
                *p++ = ',';
                remaining--;
            }
            written = snprintf(p, remaining, "%u", data[i]);
            p += written;
            remaining -= written;
        }

        written = snprintf(p, remaining, "]);");
        p += written;
        remaining -= written;

        /* Add readU8 method */
        written = snprintf(p, remaining,
            "o.readU8=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off>=d.length)throw new RangeError('offset out of bounds');"
            "return d[off];"
            "};");
        p += written;
        remaining -= written;

        /* Add readU16LE method */
        written = snprintf(p, remaining,
            "o.readU16LE=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off+2>d.length)throw new RangeError('offset out of bounds');"
            "return d[off]|(d[off+1]<<8);"
            "};");
        p += written;
        remaining -= written;

        /* Add readU32LE method */
        written = snprintf(p, remaining,
            "o.readU32LE=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off+4>d.length)throw new RangeError('offset out of bounds');"
            "return (d[off]|(d[off+1]<<8)|(d[off+2]<<16)|(d[off+3]<<24))>>>0;"
            "};");
        p += written;
        remaining -= written;

        /* Add readBytes method */
        written = snprintf(p, remaining,
            "o.readBytes=function(off,len,buf){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(typeof len!=='number')throw new TypeError('length must be a number');"
            "if(!(buf instanceof Uint8Array))throw new TypeError('outBuffer must be a Uint8Array');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(len<0)throw new RangeError('length must be non-negative');"
            "if(off>=d.length)throw new RangeError('offset out of bounds');"
            "var n=len;if(off+n>d.length)n=d.length-off;if(n>buf.length)n=buf.length;"
            "for(var i=0;i<n;i++)buf[i]=d[off+i];"
            "return n;"
            "};");
        p += written;
        remaining -= written;
    } else {
        /* No data available - add methods that always throw */
        written = snprintf(p, remaining,
            "o.readU8=function(){throw new RangeError('no data available');};"
            "o.readU16LE=function(){throw new RangeError('no data available');};"
            "o.readU32LE=function(){throw new RangeError('no data available');};"
            "o.readBytes=function(){throw new RangeError('no data available');};");
        p += written;
        remaining -= written;
    }

    /* Close the IIFE and return the object */
    written = snprintf(p, remaining, "return o;})()");
    p += written;

    JSValue result = JS_Eval(ctx, code, strlen(code), "<ctx>", JS_EVAL_RETVAL);
    free(code);
    free(owned_data);

    if (JS_IsException(result)) {
        JSValue ex = JS_GetException(ctx);
        (void)ex;
        return JS_NULL;
    }

    return result;
}

/*
 * Create a SECURITY context object from ctx_blob.
 * Returns JS object with read-only subject_id, object_id, action, data_len,
 * flags properties and readU8, readU16LE, readU32LE, readBytes methods.
 */
static JSValue create_security_ctx(JSContext *ctx, const void *ctx_blob, size_t ctx_len) {
    if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_security_v1_t)) {
        return JS_NULL;
    }

    const mbpf_ctx_security_v1_t *sec_ctx = (const mbpf_ctx_security_v1_t *)ctx_blob;

    /* Determine if we have data to embed */
    const uint8_t *data = sec_ctx->data;
    uint32_t data_len = sec_ctx->data_len;
    uint8_t *owned_data = NULL;

    /* If no contiguous data but a read_fn is provided, snapshot via read_fn. */
    if (!data && sec_ctx->read_fn && data_len > 0) {
        owned_data = malloc(data_len);
        if (!owned_data) {
            return JS_NULL;
        }

        int read_rc = sec_ctx->read_fn(ctx_blob, 0, data_len, owned_data);
        if (read_rc <= 0) {
            free(owned_data);
            owned_data = NULL;
            data = NULL;
            data_len = 0;
        } else {
            data = owned_data;
            if ((uint32_t)read_rc < data_len) {
                data_len = (uint32_t)read_rc;
            }
        }
    }

    /* Build JS code to create a new object. */
    size_t code_size = 2512;
    if (data && data_len > 0) {
        code_size += data_len * 5;
    }

    char *code = malloc(code_size);
    if (!code) {
        free(owned_data);
        return JS_NULL;
    }

    char *p = code;
    size_t remaining = code_size;
    int written;

    /* Start the IIFE */
    written = snprintf(p, remaining, "(function(){var o={};");
    p += written;
    remaining -= written;

    /* Add read-only scalar properties */
    written = snprintf(p, remaining,
        "Object.defineProperty(o,'subject_id',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'object_id',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'action',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'data_len',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'flags',{get:function(){return %u;},set:function(){}});",
        sec_ctx->subject_id,
        sec_ctx->object_id,
        sec_ctx->action,
        sec_ctx->data_len,
        (uint32_t)sec_ctx->flags);
    p += written;
    remaining -= written;

    /* Add data buffer and read methods if data is available */
    if (data && data_len > 0) {
        /* Create internal data array */
        written = snprintf(p, remaining, "var d=new Uint8Array([");
        p += written;
        remaining -= written;

        for (uint32_t i = 0; i < data_len; i++) {
            if (i > 0) {
                *p++ = ',';
                remaining--;
            }
            written = snprintf(p, remaining, "%u", data[i]);
            p += written;
            remaining -= written;
        }

        written = snprintf(p, remaining, "]);");
        p += written;
        remaining -= written;

        /* Add readU8 method */
        written = snprintf(p, remaining,
            "o.readU8=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off>=d.length)throw new RangeError('offset out of bounds');"
            "return d[off];"
            "};");
        p += written;
        remaining -= written;

        /* Add readU16LE method */
        written = snprintf(p, remaining,
            "o.readU16LE=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off+2>d.length)throw new RangeError('offset out of bounds');"
            "return d[off]|(d[off+1]<<8);"
            "};");
        p += written;
        remaining -= written;

        /* Add readU32LE method */
        written = snprintf(p, remaining,
            "o.readU32LE=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off+4>d.length)throw new RangeError('offset out of bounds');"
            "return (d[off]|(d[off+1]<<8)|(d[off+2]<<16)|(d[off+3]<<24))>>>0;"
            "};");
        p += written;
        remaining -= written;

        /* Add readBytes method */
        written = snprintf(p, remaining,
            "o.readBytes=function(off,len,buf){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(typeof len!=='number')throw new TypeError('length must be a number');"
            "if(!(buf instanceof Uint8Array))throw new TypeError('outBuffer must be a Uint8Array');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(len<0)throw new RangeError('length must be non-negative');"
            "if(off>=d.length)throw new RangeError('offset out of bounds');"
            "var n=len;if(off+n>d.length)n=d.length-off;if(n>buf.length)n=buf.length;"
            "for(var i=0;i<n;i++)buf[i]=d[off+i];"
            "return n;"
            "};");
        p += written;
        remaining -= written;
    } else {
        /* No data available - add methods that always throw */
        written = snprintf(p, remaining,
            "o.readU8=function(){throw new RangeError('no data available');};"
            "o.readU16LE=function(){throw new RangeError('no data available');};"
            "o.readU32LE=function(){throw new RangeError('no data available');};"
            "o.readBytes=function(){throw new RangeError('no data available');};");
        p += written;
        remaining -= written;
    }

    /* Close the IIFE and return the object */
    written = snprintf(p, remaining, "return o;})()");
    p += written;

    JSValue result = JS_Eval(ctx, code, strlen(code), "<ctx>", JS_EVAL_RETVAL);
    free(code);
    free(owned_data);

    if (JS_IsException(result)) {
        JSValue ex = JS_GetException(ctx);
        (void)ex;
        return JS_NULL;
    }

    return result;
}

/*
 * Create a CUSTOM context object from ctx_blob.
 * Returns JS object with read-only custom_hook_id, schema_version, field_count,
 * data_len, flags properties and dynamically-generated field accessors plus
 * readU8, readU16LE, readU32LE, readBytes methods.
 *
 * Custom hooks allow platforms to define their own context schemas with typed fields.
 */
static JSValue create_custom_ctx(JSContext *ctx, const void *ctx_blob, size_t ctx_len) {
    if (!ctx_blob || ctx_len < sizeof(mbpf_ctx_custom_v1_t)) {
        return JS_NULL;
    }

    const mbpf_ctx_custom_v1_t *custom_ctx = (const mbpf_ctx_custom_v1_t *)ctx_blob;

    /* Determine if we have data to embed */
    const uint8_t *data = custom_ctx->data;
    uint32_t data_len = custom_ctx->data_len;
    uint8_t *owned_data = NULL;

    /* If no contiguous data but a read_fn is provided, snapshot via read_fn. */
    if (!data && custom_ctx->read_fn && data_len > 0) {
        owned_data = malloc(data_len);
        if (!owned_data) {
            return JS_NULL;
        }

        int read_rc = custom_ctx->read_fn(ctx_blob, 0, data_len, owned_data);
        if (read_rc <= 0) {
            free(owned_data);
            owned_data = NULL;
            data = NULL;
            data_len = 0;
        } else {
            data = owned_data;
            if ((uint32_t)read_rc < data_len) {
                data_len = (uint32_t)read_rc;
            }
        }
    }

    /* Build JS code to create a new object.
     * Base size + custom field definitions + data array */
    size_t code_size = 4096;
    if (data && data_len > 0) {
        code_size += data_len * 5;  /* "0xXX," = 5 chars per byte */
    }
    /* Add space for field accessors - each field name + accessor ~200 bytes */
    if (custom_ctx->fields && custom_ctx->field_count > 0) {
        code_size += custom_ctx->field_count * 256;
    }

    char *code = malloc(code_size);
    if (!code) {
        free(owned_data);
        return JS_NULL;
    }

    char *p = code;
    size_t remaining = code_size;
    int written;

    /* Start the IIFE */
    written = snprintf(p, remaining, "(function(){var o={};");
    p += written;
    remaining -= written;

    /* Add read-only scalar properties */
    written = snprintf(p, remaining,
        "Object.defineProperty(o,'custom_hook_id',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'schema_version',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'field_count',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'data_len',{get:function(){return %u;},set:function(){}});"
        "Object.defineProperty(o,'flags',{get:function(){return %u;},set:function(){}});",
        custom_ctx->custom_hook_id,
        custom_ctx->schema_version,
        custom_ctx->field_count,
        custom_ctx->data_len,
        (uint32_t)custom_ctx->flags);
    p += written;
    remaining -= written;

    /* Add data buffer if available */
    if (data && data_len > 0) {
        /* Create internal data array */
        written = snprintf(p, remaining, "var d=new Uint8Array([");
        p += written;
        remaining -= written;

        for (uint32_t i = 0; i < data_len; i++) {
            if (i > 0) {
                *p++ = ',';
                remaining--;
            }
            written = snprintf(p, remaining, "%u", data[i]);
            p += written;
            remaining -= written;
        }

        written = snprintf(p, remaining, "]);");
        p += written;
        remaining -= written;

        /* Generate typed field accessors from schema if provided */
        if (custom_ctx->fields && custom_ctx->field_count > 0) {
            for (uint32_t i = 0; i < custom_ctx->field_count; i++) {
                const mbpf_custom_field_t *field = &custom_ctx->fields[i];
                if (!field->name) continue;

                uint32_t off = field->offset;
                switch (field->type) {
                    case MBPF_FIELD_U8:
                        if (off < data_len) {
                            written = snprintf(p, remaining,
                                "Object.defineProperty(o,'%s',{get:function(){return d[%u];},set:function(){}});",
                                field->name, off);
                            p += written;
                            remaining -= written;
                        }
                        break;

                    case MBPF_FIELD_I8:
                        if (off < data_len) {
                            written = snprintf(p, remaining,
                                "Object.defineProperty(o,'%s',{get:function(){return (d[%u]<<24)>>24;},set:function(){}});",
                                field->name, off);
                            p += written;
                            remaining -= written;
                        }
                        break;

                    case MBPF_FIELD_U16:
                        if (off + 2 <= data_len) {
                            written = snprintf(p, remaining,
                                "Object.defineProperty(o,'%s',{get:function(){return d[%u]|(d[%u]<<8);},set:function(){}});",
                                field->name, off, off + 1);
                            p += written;
                            remaining -= written;
                        }
                        break;

                    case MBPF_FIELD_I16:
                        if (off + 2 <= data_len) {
                            written = snprintf(p, remaining,
                                "Object.defineProperty(o,'%s',{get:function(){var v=(d[%u]|(d[%u]<<8));return (v<<16)>>16;},set:function(){}});",
                                field->name, off, off + 1);
                            p += written;
                            remaining -= written;
                        }
                        break;

                    case MBPF_FIELD_U32:
                        if (off + 4 <= data_len) {
                            written = snprintf(p, remaining,
                                "Object.defineProperty(o,'%s',{get:function(){return (d[%u]|(d[%u]<<8)|(d[%u]<<16)|(d[%u]<<24))>>>0;},set:function(){}});",
                                field->name, off, off + 1, off + 2, off + 3);
                            p += written;
                            remaining -= written;
                        }
                        break;

                    case MBPF_FIELD_I32:
                        if (off + 4 <= data_len) {
                            written = snprintf(p, remaining,
                                "Object.defineProperty(o,'%s',{get:function(){return (d[%u]|(d[%u]<<8)|(d[%u]<<16)|(d[%u]<<24))|0;},set:function(){}});",
                                field->name, off, off + 1, off + 2, off + 3);
                            p += written;
                            remaining -= written;
                        }
                        break;

                    case MBPF_FIELD_U64:
                        /* Return as [lo, hi] array per spec */
                        if (off + 8 <= data_len) {
                            written = snprintf(p, remaining,
                                "Object.defineProperty(o,'%s',{get:function(){"
                                "var lo=(d[%u]|(d[%u]<<8)|(d[%u]<<16)|(d[%u]<<24))>>>0;"
                                "var hi=(d[%u]|(d[%u]<<8)|(d[%u]<<16)|(d[%u]<<24))>>>0;"
                                "return [lo,hi];},set:function(){}});",
                                field->name,
                                off, off + 1, off + 2, off + 3,
                                off + 4, off + 5, off + 6, off + 7);
                            p += written;
                            remaining -= written;
                        }
                        break;

                    case MBPF_FIELD_I64:
                        /* Return as [lo, hi] array with signed high word */
                        if (off + 8 <= data_len) {
                            written = snprintf(p, remaining,
                                "Object.defineProperty(o,'%s',{get:function(){"
                                "var lo=(d[%u]|(d[%u]<<8)|(d[%u]<<16)|(d[%u]<<24))>>>0;"
                                "var hi=(d[%u]|(d[%u]<<8)|(d[%u]<<16)|(d[%u]<<24))|0;"
                                "return [lo,hi];},set:function(){}});",
                                field->name,
                                off, off + 1, off + 2, off + 3,
                                off + 4, off + 5, off + 6, off + 7);
                            p += written;
                            remaining -= written;
                        }
                        break;

                    case MBPF_FIELD_BYTES:
                        /* Return a slice of the data as Uint8Array */
                        if (off + field->length <= data_len) {
                            written = snprintf(p, remaining,
                                "Object.defineProperty(o,'%s',{get:function(){return d.slice(%u,%u);},set:function(){}});",
                                field->name, off, off + field->length);
                            p += written;
                            remaining -= written;
                        }
                        break;
                }
            }
        }

        /* Add readU8 method */
        written = snprintf(p, remaining,
            "o.readU8=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off>=d.length)throw new RangeError('offset out of bounds');"
            "return d[off];"
            "};");
        p += written;
        remaining -= written;

        /* Add readU16LE method */
        written = snprintf(p, remaining,
            "o.readU16LE=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off+2>d.length)throw new RangeError('offset out of bounds');"
            "return d[off]|(d[off+1]<<8);"
            "};");
        p += written;
        remaining -= written;

        /* Add readU32LE method */
        written = snprintf(p, remaining,
            "o.readU32LE=function(off){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(off+4>d.length)throw new RangeError('offset out of bounds');"
            "return (d[off]|(d[off+1]<<8)|(d[off+2]<<16)|(d[off+3]<<24))>>>0;"
            "};");
        p += written;
        remaining -= written;

        /* Add readBytes method */
        written = snprintf(p, remaining,
            "o.readBytes=function(off,len,buf){"
            "if(typeof off!=='number')throw new TypeError('offset must be a number');"
            "if(typeof len!=='number')throw new TypeError('length must be a number');"
            "if(!(buf instanceof Uint8Array))throw new TypeError('outBuffer must be a Uint8Array');"
            "if(off<0)throw new RangeError('offset must be non-negative');"
            "if(len<0)throw new RangeError('length must be non-negative');"
            "if(off>=d.length)throw new RangeError('offset out of bounds');"
            "var n=len;if(off+n>d.length)n=d.length-off;if(n>buf.length)n=buf.length;"
            "for(var i=0;i<n;i++)buf[i]=d[off+i];"
            "return n;"
            "};");
        p += written;
        remaining -= written;
    } else {
        /* No data available - add methods that always throw */
        written = snprintf(p, remaining,
            "o.readU8=function(){throw new RangeError('no data available');};"
            "o.readU16LE=function(){throw new RangeError('no data available');};"
            "o.readU32LE=function(){throw new RangeError('no data available');};"
            "o.readBytes=function(){throw new RangeError('no data available');};");
        p += written;
        remaining -= written;
    }

    /* Close the IIFE and return the object */
    written = snprintf(p, remaining, "return o;})()");
    p += written;

    JSValue result = JS_Eval(ctx, code, strlen(code), "<ctx>", JS_EVAL_RETVAL);
    free(code);
    free(owned_data);

    if (JS_IsException(result)) {
        JSValue ex = JS_GetException(ctx);
        (void)ex;
        return JS_NULL;
    }

    return result;
}

/*
 * Create a context object from ctx_blob based on the hook type.
 * Returns a JS object with hook-specific properties.
 */
static JSValue create_hook_ctx(JSContext *ctx, mbpf_hook_id_t hook,
                                const void *ctx_blob, size_t ctx_len) {
    switch ((mbpf_hook_type_t)hook) {
        case MBPF_HOOK_NET_RX:
        case MBPF_HOOK_NET_TX:
            return create_net_rx_ctx(ctx, ctx_blob, ctx_len);

        case MBPF_HOOK_TRACEPOINT:
            return create_tracepoint_ctx(ctx, ctx_blob, ctx_len);

        case MBPF_HOOK_TIMER:
            return create_timer_ctx(ctx, ctx_blob, ctx_len);

        case MBPF_HOOK_SECURITY:
            return create_security_ctx(ctx, ctx_blob, ctx_len);

        case MBPF_HOOK_CUSTOM:
            return create_custom_ctx(ctx, ctx_blob, ctx_len);

        default:
            /* For unknown hook types without context structure, pass null */
            if (!ctx_blob || ctx_len == 0) {
                return JS_NULL;
            }
            /* Create a minimal object with just the blob length */
            {
                JSValue obj = JS_NewObject(ctx);
                if (!JS_IsException(obj)) {
                    JS_SetPropertyStr(ctx, obj, "length", JS_NewUint32(ctx, (uint32_t)ctx_len));
                }
                return obj;
            }
    }
}

/*
 * Execute a program on a specific instance.
 * Returns MBPF_OK on success, error code on failure.
 */
static int run_on_instance(mbpf_instance_t *inst, mbpf_program_t *prog,
                           mbpf_hook_id_t hook,
                           const void *ctx_blob, size_t ctx_len,
                           int32_t *out_rc) {
    if (!inst || !inst->js_initialized || !inst->js_ctx) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Trace: program execution starting */
    mbpf_trace_log(prog->runtime, "run_on_instance: prog=%s hook=%u ctx_len=%zu",
                   prog->manifest.program_name, hook, ctx_len);

    /* Get the exception default for this hook type */
    int32_t exception_default = get_exception_default(
        prog->runtime, (mbpf_hook_type_t)hook);

    /* Check for nested execution using atomic compare-and-swap */
    int expected = 0;
    if (!__atomic_compare_exchange_n(&inst->in_use, &expected, 1,
                                      0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        prog->stats.nested_dropped++;
        *out_rc = exception_default;
        mbpf_trace_log(prog->runtime, "run_on_instance: nested execution blocked");
        return MBPF_ERR_NESTED_EXEC;
    }

    /* Reset step budget for this invocation */
    inst->steps_remaining = inst->max_steps;
    inst->budget_exceeded = 0;

    /* Set up wall time budget from manifest and record start time.
     * Wall time budget is only enforced during mbpf_run, not during init. */
    inst->max_wall_time_us = prog->manifest.budgets.max_wall_time_us;
    if (inst->max_wall_time_us > 0) {
        clock_gettime(CLOCK_MONOTONIC, &inst->start_time);
    }

    /* Set up log context for mbpf.log helper */
    mbpf_set_log_context((void *)prog->runtime->config.log_fn,
                         prog->runtime->config.debug_mode);

    JSContext *ctx = inst->js_ctx;

    /* Get global object */
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsUndefined(global) || JS_IsException(global)) {
        prog->stats.exceptions++;
        *out_rc = exception_default;
        mbpf_clear_log_context();
        __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
        return MBPF_OK;
    }

    /* Reset helper count for this invocation if helper budget is enforced */
    if (inst->max_helpers > 0) {
        JSValue reset = JS_Eval(ctx, "_helperCount=0;_helperBudgetExceeded=false;", 43, "<reset>", 0);
        if (JS_IsException(reset)) {
            JS_GetException(ctx);  /* Clear exception, non-fatal */
        }
    }

    /* Sync ring buffer state from C to JS before running.
     * This ensures host-side reads (which modify C state) are reflected in JS. */
    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];
        if (storage->type == MBPF_MAP_TYPE_RING) {
            mbpf_ring_buffer_map_t *ring = &storage->u.ring;

            /* Update JS metadata from C state */
            char sync_code[256];
            snprintf(sync_code, sizeof(sync_code),
                "(function(){"
                    "var m=_mapValid[%u];"
                    "m.head=%u;"
                    "m.tail=%u;"
                    "m.dropped=%u;"
                    "m.eventCount=%u;"
                "})()",
                i, ring->head, ring->tail, ring->dropped, ring->event_count);

            JSValue sync_result = JS_Eval(ctx, sync_code, strlen(sync_code),
                                          "<ring_sync_in>", JS_EVAL_RETVAL);
            if (JS_IsException(sync_result)) {
                JS_GetException(ctx);  /* Clear exception state */
            }
            /* JSValue managed by GC, no manual free needed */

            /* Copy data buffer from C to JS using chunked updates.
             * Only sync bytes that contain event data (between tail and head).
             * Use MBPF_RING_SYNC_MAX_CHUNK to limit JS string size per chunk.
             * Each "d[N]=V;" is up to 15 chars, so ~4K bytes per chunk at ~16 chars each. */
            if (ring->buffer_size > 0 && ring->event_count > 0) {
                /* Calculate bytes used in the ring buffer */
                uint32_t bytes_used;
                if (ring->head >= ring->tail) {
                    bytes_used = ring->head - ring->tail;
                } else {
                    bytes_used = ring->buffer_size - ring->tail + ring->head;
                }

                /* Limit sync to actual used bytes, capped at buffer size */
                if (bytes_used > ring->buffer_size) {
                    bytes_used = ring->buffer_size;
                }

                /* Calculate bytes per chunk (leave room for JS overhead) */
                uint32_t bytes_per_chunk = MBPF_RING_SYNC_MAX_CHUNK / 16;
                if (bytes_per_chunk < 256) bytes_per_chunk = 256;

                /* Sync in chunks starting from tail */
                uint32_t synced = 0;
                while (synced < bytes_used) {
                    uint32_t chunk_size = bytes_used - synced;
                    if (chunk_size > bytes_per_chunk) {
                        chunk_size = bytes_per_chunk;
                    }

                    /* Allocate buffer for this chunk: 16 chars per byte + overhead */
                    size_t code_size = (size_t)chunk_size * 16 + 256;
                    char *data_code = malloc(code_size);
                    if (!data_code) break;

                    char *p = data_code;
                    char *end = data_code + code_size - 32;
                    p += sprintf(p, "(function(){var d=_mapData[%u];", i);

                    for (uint32_t j = 0; j < chunk_size && p < end; j++) {
                        uint32_t idx = (ring->tail + synced + j) % ring->buffer_size;
                        p += sprintf(p, "d[%u]=%u;", idx, ring->buffer[idx]);
                    }
                    p += sprintf(p, "})()");

                    JSValue data_result = JS_Eval(ctx, data_code, strlen(data_code),
                                                   "<ring_data_in>", JS_EVAL_RETVAL);
                    if (JS_IsException(data_result)) {
                        JS_GetException(ctx);
                    }
                    free(data_code);

                    synced += chunk_size;
                }
            }
        } else if (storage->type == MBPF_MAP_TYPE_COUNTER) {
            /* Sync counter values from C to JS before running.
             * Read current C values atomically and update JS hi/lo arrays.
             * Also clear the delta accumulators for this run. */
            mbpf_counter_map_t *ctr = &storage->u.counter;

            /* Build sync code to update JS arrays with current C values.
             * Each entry can be up to ~100 bytes, so allocate 128 per entry + header. */
            size_t code_size = (size_t)ctr->max_entries * 128 + 256;
            char *sync_code = malloc(code_size);
            if (sync_code) {
                char *p = sync_code;
                size_t remaining = code_size;
                int written = snprintf(p, remaining, "(function(){var d=_mapData[%u];", i);
                p += written;
                remaining -= (size_t)written;
                for (uint32_t j = 0; j < ctr->max_entries && remaining > 128; j++) {
                    /* Read atomically from C storage */
                    int64_t val = __atomic_load_n(&ctr->counters[j], __ATOMIC_SEQ_CST);
                    int32_t hi = (int32_t)(val >> 32);
                    uint32_t lo = (uint32_t)(val & 0xFFFFFFFFLL);
                    written = snprintf(p, remaining, "d.hi[%u]=%d;d.lo[%u]=%u;d.dhi[%u]=0;d.dlo[%u]=0;",
                                 j, hi, j, lo, j, j);
                    p += written;
                    remaining -= (size_t)written;
                }
                /* Clear sets array */
                snprintf(p, remaining, "d.sets=[];})()");

                JSValue sync_result = JS_Eval(ctx, sync_code, strlen(sync_code),
                                              "<counter_sync_in>", JS_EVAL_RETVAL);
                if (JS_IsException(sync_result)) {
                    JS_GetException(ctx);
                }
                free(sync_code);
            }
        }
    }

    /* Sync emit buffer state from C to JS before running.
     * This ensures host-side reads (which modify C state) are reflected in JS. */
    if (prog->has_emit_cap && prog->emit_buffer) {
        mbpf_emit_buffer_t *emit = prog->emit_buffer;

        /* Update JS metadata from C state */
        char sync_code[256];
        snprintf(sync_code, sizeof(sync_code),
            "(function(){"
                "var m=_mbpf_emit_meta;"
                "m.head=%u;"
                "m.tail=%u;"
                "m.dropped=%u;"
                "m.eventCount=%u;"
            "})()",
            emit->head, emit->tail, emit->dropped, emit->event_count);

        JSValue sync_result = JS_Eval(ctx, sync_code, strlen(sync_code),
                                      "<emit_sync_in>", JS_EVAL_RETVAL);
        if (JS_IsException(sync_result)) {
            JS_GetException(ctx);  /* Clear exception state */
        }

        /* Copy buffer data from C to JS */
        if (emit->buffer_size > 0) {
            size_t code_size = (size_t)emit->buffer_size * 16 + 256;
            char *data_code = malloc(code_size);
            if (data_code) {
                char *p = data_code;
                char *end = data_code + code_size - 32;  /* Leave room */
                p += sprintf(p, "(function(){var d=_mbpf_emit_buf;");
                for (uint32_t j = 0; j < emit->buffer_size && p < end; j++) {
                    p += sprintf(p, "d[%u]=%u;", j, emit->buffer[j]);
                }
                p += sprintf(p, "})()");
                JSValue data_result = JS_Eval(ctx, data_code, strlen(data_code),
                                               "<emit_data_in>", JS_EVAL_RETVAL);
                if (JS_IsException(data_result)) {
                    JS_GetException(ctx);  /* Clear exception state */
                }
                free(data_code);
            }
        }
    }

    /* Check stack space: we need 3 slots (arg + function + this) */
    if (JS_StackCheck(ctx, 3)) {
        prog->stats.exceptions++;
        *out_rc = exception_default;
        mbpf_clear_log_context();
        __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
        return MBPF_OK;
    }

    /* Get context object for this invocation.
     * If reusable ctx infrastructure is initialized, update and use the
     * cached ctx object. Otherwise fall back to creating a new one. */
    JSValue ctx_arg;
    if (inst->ctx_initialized) {
        /* Use reusable ctx: update global data and get the cached object */
        ctx_arg = update_reusable_ctx(inst, hook, ctx_blob, ctx_len);
        if (JS_IsNull(ctx_arg)) {
            /* Fallback to per-invocation creation if update failed */
            ctx_arg = create_hook_ctx(ctx, hook, ctx_blob, ctx_len);
        }
    } else {
        /* No reusable ctx - create a new one for this invocation */
        ctx_arg = create_hook_ctx(ctx, hook, ctx_blob, ctx_len);
    }

    /* Use the GC-protected entry function reference.
     * The entry function is registered with JS_AddGCRef at load time,
     * which ensures it remains valid even after GC/compaction cycles.
     * This is more efficient than looking it up on every invocation and
     * is safe because the JSGCRef.val is updated by the GC when objects move. */
    JSValue prog_func;
    if (inst->has_entry_func_ref) {
        prog_func = inst->entry_func_ref.val;
    } else {
        /* Fallback: look up entry function if GC ref wasn't registered.
         * This should only happen if register_gc_refs failed silently. */
        prog_func = JS_GetPropertyStr(ctx, global, prog->manifest.entry_symbol);
    }

    if (JS_IsUndefined(prog_func) || !JS_IsFunction(ctx, prog_func)) {
        prog->stats.exceptions++;
        *out_rc = exception_default;
        mbpf_clear_log_context();
        __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
        return MBPF_OK;
    }

    /* Push in order: argument(s), function, this */
    JS_PushArg(ctx, ctx_arg);      /* ctx argument */
    JS_PushArg(ctx, prog_func);    /* function */
    JS_PushArg(ctx, JS_NULL);      /* this */

    /* Update _mbpf_time_ns if CAP_TIME is granted.
     * This provides the current monotonic time in nanoseconds to mbpf.nowNs(). */
    if (prog->manifest.capabilities & MBPF_CAP_TIME) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        int64_t ns = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
        uint32_t lo = (uint32_t)(ns & 0xFFFFFFFFULL);
        uint32_t hi = (uint32_t)((uint64_t)ns >> 32);

        char time_code[128];
        snprintf(time_code, sizeof(time_code),
            "_mbpf_time_ns[0]=%u;_mbpf_time_ns[1]=%u;", lo, hi);
        JSValue time_result = JS_Eval(ctx, time_code, strlen(time_code),
                                       "<time>", 0);
        if (JS_IsException(time_result)) {
            JS_GetException(ctx);  /* Clear exception, non-fatal */
        }
    }

    /* Update _mbpf_stats if CAP_STATS is granted.
     * This provides the current program stats to mbpf.stats(). */
    if (prog->manifest.capabilities & MBPF_CAP_STATS) {
        char stats_code[600];
        snprintf(stats_code, sizeof(stats_code),
            "_mbpf_stats.invocations[0]=%u;_mbpf_stats.invocations[1]=%u;"
            "_mbpf_stats.successes[0]=%u;_mbpf_stats.successes[1]=%u;"
            "_mbpf_stats.exceptions[0]=%u;_mbpf_stats.exceptions[1]=%u;"
            "_mbpf_stats.oom_errors[0]=%u;_mbpf_stats.oom_errors[1]=%u;"
            "_mbpf_stats.budget_exceeded[0]=%u;_mbpf_stats.budget_exceeded[1]=%u;"
            "_mbpf_stats.nested_dropped[0]=%u;_mbpf_stats.nested_dropped[1]=%u;"
            "_mbpf_stats.deferred_dropped[0]=%u;_mbpf_stats.deferred_dropped[1]=%u;",
            (uint32_t)(prog->stats.invocations & 0xFFFFFFFFULL),
            (uint32_t)(prog->stats.invocations >> 32),
            (uint32_t)(prog->stats.successes & 0xFFFFFFFFULL),
            (uint32_t)(prog->stats.successes >> 32),
            (uint32_t)(prog->stats.exceptions & 0xFFFFFFFFULL),
            (uint32_t)(prog->stats.exceptions >> 32),
            (uint32_t)(prog->stats.oom_errors & 0xFFFFFFFFULL),
            (uint32_t)(prog->stats.oom_errors >> 32),
            (uint32_t)(prog->stats.budget_exceeded & 0xFFFFFFFFULL),
            (uint32_t)(prog->stats.budget_exceeded >> 32),
            (uint32_t)(prog->stats.nested_dropped & 0xFFFFFFFFULL),
            (uint32_t)(prog->stats.nested_dropped >> 32),
            (uint32_t)(prog->stats.deferred_dropped & 0xFFFFFFFFULL),
            (uint32_t)(prog->stats.deferred_dropped >> 32));
        JSValue stats_result = JS_Eval(ctx, stats_code, strlen(stats_code),
                                        "<stats>", 0);
        if (JS_IsException(stats_result)) {
            JS_GetException(ctx);  /* Clear exception, non-fatal */
        }
    }

    prog->stats.invocations++;

    JSValue result = JS_Call(ctx, 1);  /* 1 argument */

    if (JS_IsException(result)) {
        /* Get the exception to determine its type */
        JSValue exc = JS_GetException(ctx);

        /* Check if this is an out-of-memory error first */
        if (is_oom_exception(ctx, exc)) {
            prog->stats.oom_errors++;
            circuit_breaker_record_failure(prog);
            *out_rc = exception_default;
            mbpf_trace_log(prog->runtime, "run_on_instance: OOM error prog=%s",
                           prog->manifest.program_name);
            mbpf_clear_log_context();
            __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
            return MBPF_OK;
        }

        /* Check if this exception was due to budget exceeded (step or helper) */
        bool helper_budget_exceeded = false;
        if (inst->max_helpers > 0) {
            JSValue flag = JS_GetPropertyStr(ctx, global, "_helperBudgetExceeded");
            if (JS_IsBool(flag)) {
                helper_budget_exceeded = (flag == JS_TRUE);
            }
        }
        if (inst->budget_exceeded || helper_budget_exceeded) {
            prog->stats.budget_exceeded++;
            mbpf_trace_log(prog->runtime, "run_on_instance: budget exceeded prog=%s",
                           prog->manifest.program_name);
        } else {
            prog->stats.exceptions++;
            mbpf_trace_log(prog->runtime, "run_on_instance: exception prog=%s",
                           prog->manifest.program_name);
        }
        circuit_breaker_record_failure(prog);
        *out_rc = exception_default;
        mbpf_clear_log_context();
        __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
        return MBPF_OK;
    }

    /* If budget was exceeded but caught inside JS, enforce fail-safe default */
    if (inst->budget_exceeded || inst->max_helpers > 0) {
        bool helper_budget_exceeded = false;
        if (inst->max_helpers > 0) {
            JSValue flag = JS_GetPropertyStr(ctx, global, "_helperBudgetExceeded");
            if (JS_IsBool(flag)) {
                helper_budget_exceeded = (flag == JS_TRUE);
            }
        }
        if (inst->budget_exceeded || helper_budget_exceeded) {
            prog->stats.budget_exceeded++;
            circuit_breaker_record_failure(prog);
            *out_rc = exception_default;
            mbpf_clear_log_context();
            __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
            return MBPF_OK;
        }
    }

    /* Convert result to int32 */
    if (JS_IsNumber(ctx, result)) {
        int res = 0;
        if (JS_ToInt32(ctx, &res, result) == 0) {
            *out_rc = (int32_t)res;
        } else {
            *out_rc = 0;
        }
    } else {
        *out_rc = 0;  /* Default if not a number */
    }

    prog->stats.successes++;
    circuit_breaker_record_success(prog);

    /* Trace: successful execution */
    mbpf_trace_log(prog->runtime, "run_on_instance: success prog=%s rc=%d",
                   prog->manifest.program_name, *out_rc);

    /* Sync ring buffer state from JS to C storage.
     * This allows host-side APIs to read events written by the program.
     * Use direct property access instead of building large arrays. */
    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];
        if (storage->type == MBPF_MAP_TYPE_RING) {
            mbpf_ring_buffer_map_t *ring = &storage->u.ring;

            /* Get the ring buffer metadata from JS first */
            char sync_code[256];
            snprintf(sync_code, sizeof(sync_code),
                "(function(){"
                    "var m=_mapValid[%u];"
                    "return [m.head,m.tail,m.dropped,m.eventCount];"
                "})()", i);

            JSValue meta_result = JS_Eval(ctx, sync_code, strlen(sync_code),
                                          "<ring_meta>", JS_EVAL_RETVAL);
            if (JS_IsException(meta_result)) {
                JS_GetException(ctx);
                continue;
            }

            int32_t head = 0, tail = 0, dropped = 0, event_count = 0;
            JSValue v0 = JS_GetPropertyUint32(ctx, meta_result, 0);
            JSValue v1 = JS_GetPropertyUint32(ctx, meta_result, 1);
            JSValue v2 = JS_GetPropertyUint32(ctx, meta_result, 2);
            JSValue v3 = JS_GetPropertyUint32(ctx, meta_result, 3);

            JS_ToInt32(ctx, &head, v0);
            JS_ToInt32(ctx, &tail, v1);
            JS_ToInt32(ctx, &dropped, v2);
            JS_ToInt32(ctx, &event_count, v3);

            ring->head = (uint32_t)head;
            ring->tail = (uint32_t)tail;
            ring->dropped = (uint32_t)dropped;
            ring->event_count = (uint32_t)event_count;

            /* Copy used data bytes directly from JS Uint8Array.
             * Only sync bytes between tail and head to avoid large allocations. */
            if (event_count > 0 && ring->buffer_size > 0) {
                /* Get the data array object */
                char get_data_code[64];
                snprintf(get_data_code, sizeof(get_data_code), "_mapData[%u]", i);
                JSValue data_arr = JS_Eval(ctx, get_data_code, strlen(get_data_code),
                                            "<ring_data>", JS_EVAL_RETVAL);
                if (!JS_IsException(data_arr)) {
                    /* Calculate bytes used */
                    uint32_t bytes_used;
                    if ((uint32_t)head >= (uint32_t)tail) {
                        bytes_used = (uint32_t)head - (uint32_t)tail;
                    } else {
                        bytes_used = ring->buffer_size - (uint32_t)tail + (uint32_t)head;
                    }
                    if (bytes_used > ring->buffer_size) {
                        bytes_used = ring->buffer_size;
                    }

                    /* Copy bytes in chunks to avoid too many property accesses */
                    uint32_t synced = 0;
                    while (synced < bytes_used) {
                        uint32_t chunk_size = bytes_used - synced;
                        if (chunk_size > MBPF_RING_SYNC_MAX_CHUNK) {
                            chunk_size = MBPF_RING_SYNC_MAX_CHUNK;
                        }

                        for (uint32_t j = 0; j < chunk_size; j++) {
                            uint32_t idx = ((uint32_t)tail + synced + j) % ring->buffer_size;
                            JSValue elem = JS_GetPropertyUint32(ctx, data_arr, idx);
                            int32_t byte_val = 0;
                            JS_ToInt32(ctx, &byte_val, elem);
                            ring->buffer[idx] = (uint8_t)byte_val;
                        }
                        synced += chunk_size;
                    }
                } else {
                    JS_GetException(ctx);
                }
            }
        } else if (storage->type == MBPF_MAP_TYPE_COUNTER) {
            /* Sync counter deltas and sets from JS to C storage atomically.
             * First apply any set() operations, then apply add() deltas. */
            mbpf_counter_map_t *ctr = &storage->u.counter;

            /* Get sets array and deltas from JS */
            char sync_code[512];
            snprintf(sync_code, sizeof(sync_code),
                "(function(){"
                    "var d=_mapData[%u];"
                    "var r={sets:d.sets.slice(),dhi:[],dlo:[]};"
                    "for(var i=0;i<%u;i++){r.dhi.push(d.dhi[i]);r.dlo.push(d.dlo[i]);}"
                    "return r;"
                "})()", i, ctr->max_entries);

            JSValue sync_result = JS_Eval(ctx, sync_code, strlen(sync_code),
                                          "<counter_sync_out>", JS_EVAL_RETVAL);
            if (!JS_IsException(sync_result)) {
                /* Process set operations first (they override any pending deltas) */
                JSValue sets_array = JS_GetPropertyStr(ctx, sync_result, "sets");
                JSValue sets_len_val = JS_GetPropertyStr(ctx, sets_array, "length");
                int32_t sets_len = 0;
                JS_ToInt32(ctx, &sets_len, sets_len_val);

                for (int32_t j = 0; j < sets_len; j++) {
                    JSValue set_obj = JS_GetPropertyUint32(ctx, sets_array, (uint32_t)j);
                    JSValue idx_val = JS_GetPropertyStr(ctx, set_obj, "i");
                    JSValue val_val = JS_GetPropertyStr(ctx, set_obj, "v");

                    int32_t idx = 0;
                    JS_ToInt32(ctx, &idx, idx_val);

                    /* Get the value as a double and convert to int64 */
                    double dval = 0;
                    JS_ToNumber(ctx, &dval, val_val);
                    int64_t new_val = (int64_t)dval;

                    if (idx >= 0 && (uint32_t)idx < ctr->max_entries) {
                        /* Atomically store the new value */
                        __atomic_store_n(&ctr->counters[idx], new_val, __ATOMIC_SEQ_CST);
                    }
                }

                /* Process delta additions atomically */
                JSValue dhi_array = JS_GetPropertyStr(ctx, sync_result, "dhi");
                JSValue dlo_array = JS_GetPropertyStr(ctx, sync_result, "dlo");

                for (uint32_t j = 0; j < ctr->max_entries; j++) {
                    JSValue dhi_val = JS_GetPropertyUint32(ctx, dhi_array, j);
                    JSValue dlo_val = JS_GetPropertyUint32(ctx, dlo_array, j);

                    int32_t dhi = 0, dlo = 0;
                    JS_ToInt32(ctx, &dhi, dhi_val);
                    JS_ToInt32(ctx, &dlo, dlo_val);

                    /* Combine hi/lo into 64-bit delta */
                    int64_t delta = ((int64_t)dhi << 32) | ((uint32_t)dlo);

                    if (delta != 0) {
                        /* Atomically add delta to counter */
                        __atomic_fetch_add(&ctr->counters[j], delta, __ATOMIC_SEQ_CST);
                    }
                }
            } else {
                JS_GetException(ctx);
            }
        }
    }

    /* Sync emit buffer state from JS to C storage.
     * This allows host-side APIs to read events emitted by the program.
     * We use direct property access rather than JS_Eval since MQuickJS
     * has issues with nested function evals. */
    if (prog->has_emit_cap && prog->emit_buffer) {
        mbpf_emit_buffer_t *emit = prog->emit_buffer;

        /* Get _mbpf_emit_meta and _mbpf_emit_buf from global object */
        JSValue meta = JS_GetPropertyStr(ctx, global, "_mbpf_emit_meta");
        JSValue buf = JS_GetPropertyStr(ctx, global, "_mbpf_emit_buf");

        if (!JS_IsUndefined(meta) && !JS_IsException(meta) &&
            !JS_IsUndefined(buf) && !JS_IsException(buf)) {
            /* Read metadata */
            JSValue vh = JS_GetPropertyStr(ctx, meta, "head");
            JSValue vt = JS_GetPropertyStr(ctx, meta, "tail");
            JSValue vd = JS_GetPropertyStr(ctx, meta, "dropped");
            JSValue ve = JS_GetPropertyStr(ctx, meta, "eventCount");

            int32_t head = 0, tail = 0, dropped = 0, event_count = 0;
            JS_ToInt32(ctx, &head, vh);
            JS_ToInt32(ctx, &tail, vt);
            JS_ToInt32(ctx, &dropped, vd);
            JS_ToInt32(ctx, &event_count, ve);

            emit->head = (uint32_t)head;
            emit->tail = (uint32_t)tail;
            emit->dropped = (uint32_t)dropped;
            emit->event_count = (uint32_t)event_count;

            /* Copy buffer data if there are events */
            if (event_count > 0) {
                JSValue v_len = JS_GetPropertyStr(ctx, buf, "length");
                int32_t buf_len = 0;
                JS_ToInt32(ctx, &buf_len, v_len);

                /* Copy bytes from JS Uint8Array to C buffer */
                for (int32_t i = 0; i < buf_len && (uint32_t)i < emit->buffer_size; i++) {
                    JSValue elem = JS_GetPropertyUint32(ctx, buf, (uint32_t)i);
                    int32_t byte_val = 0;
                    JS_ToInt32(ctx, &byte_val, elem);
                    emit->buffer[i] = (uint8_t)byte_val;
                }
            }
        }
    }

    mbpf_clear_log_context();
    __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
    return MBPF_OK;
}

/* Run program */
int mbpf_run(mbpf_runtime_t *rt, mbpf_hook_id_t hook,
             const void *ctx_blob, size_t ctx_len,
             int32_t *out_rc) {
    if (!rt || !out_rc) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Default value when no programs are attached: passthrough (0).
     * This differs from exception defaults which are fail-safe. */
    *out_rc = 0;
    int programs_run = 0;

    /* Find and execute all attached programs for this hook */
    for (mbpf_program_t *prog = rt->programs; prog; prog = prog->next) {
        if (!prog->unloaded && prog->attached && prog->attached_hook == hook) {
            /* Check circuit breaker before running */
            if (check_circuit_open(prog)) {
                /* Circuit is open, skip this program */
                prog->stats.circuit_breaker_skipped++;
                *out_rc = get_exception_default(rt, (mbpf_hook_type_t)hook);
                continue;
            }

            /* Select an instance for execution */
            mbpf_instance_t *inst = select_instance(prog);
            if (!inst) {
                continue;
            }

            int32_t prog_rc = 0;
            int err = run_on_instance(inst, prog, hook, ctx_blob, ctx_len, &prog_rc);
            if (err == MBPF_OK) {
                /* For decision hooks, use the most restrictive decision.
                 * For now, the last program's return value wins. */
                *out_rc = prog_rc;
                programs_run++;
            } else if (err == MBPF_ERR_NESTED_EXEC) {
                /* Nested execution was detected. prog_rc contains the safe
                 * default (set by run_on_instance). Propagate it so the
                 * caller gets the appropriate fail-safe value. */
                *out_rc = prog_rc;
            }
        }
    }

    return MBPF_OK;
}

/* Stats access */
int mbpf_program_stats(mbpf_program_t *prog, mbpf_stats_t *out_stats) {
    if (!prog || !out_stats) {
        return MBPF_ERR_INVALID_ARG;
    }

    *out_stats = prog->stats;
    return MBPF_OK;
}

/* Version info */
const char *mbpf_version_string(void) {
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d",
             MBPF_VERSION_MAJOR, MBPF_VERSION_MINOR, MBPF_VERSION_PATCH);
    return version;
}

uint32_t mbpf_api_version(void) {
    return MBPF_API_VERSION;
}

const char *mbpf_error_string(mbpf_error_t err) {
    switch (err) {
        case MBPF_OK:
            return "success";
        case MBPF_ERR_INVALID_ARG:
            return "invalid argument";
        case MBPF_ERR_NO_MEM:
            return "out of memory";
        case MBPF_ERR_INVALID_PACKAGE:
            return "invalid package format";
        case MBPF_ERR_INVALID_MAGIC:
            return "invalid magic number (expected 0x4D425046)";
        case MBPF_ERR_UNSUPPORTED_VER:
            return "unsupported package format version";
        case MBPF_ERR_MISSING_SECTION:
            return "required section missing";
        case MBPF_ERR_INVALID_BYTECODE:
            return "invalid or incompatible bytecode";
        case MBPF_ERR_HOOK_MISMATCH:
            return "hook type mismatch";
        case MBPF_ERR_CAPABILITY_DENIED:
            return "required capability not granted";
        case MBPF_ERR_BUDGET_EXCEEDED:
            return "execution budget exceeded";
        case MBPF_ERR_ALREADY_ATTACHED:
            return "program already attached to hook";
        case MBPF_ERR_NOT_ATTACHED:
            return "program not attached to hook";
        case MBPF_ERR_NESTED_EXEC:
            return "nested execution not allowed";
        case MBPF_ERR_SIGNATURE:
            return "signature verification failed";
        case MBPF_ERR_SECTION_BOUNDS:
            return "section extends past package end";
        case MBPF_ERR_SECTION_OVERLAP:
            return "overlapping sections detected";
        case MBPF_ERR_CRC_MISMATCH:
            return "CRC32 checksum mismatch";
        case MBPF_ERR_HEAP_TOO_SMALL:
            return "heap size below platform minimum";
        case MBPF_ERR_ALREADY_UNLOADED:
            return "program already unloaded";
        case MBPF_ERR_ABI_MISMATCH:
            return "hook context ABI version mismatch";
        case MBPF_ERR_MISSING_ENTRY:
            return "entry function not found";
        case MBPF_ERR_INIT_FAILED:
            return "program initialization failed";
        case MBPF_ERR_MAP_INCOMPATIBLE:
            return "map schema incompatible with existing map";
        case MBPF_ERR_STILL_ATTACHED:
            return "program still attached";
        case MBPF_ERR_API_VERSION:
            return "helper API version incompatible";
        case MBPF_ERR_HELPER_VERSION:
            return "per-helper version incompatible";
        case MBPF_ERR_TARGET_MISMATCH:
            return "target word size or endianness mismatch";
        default:
            return "unknown error";
    }
}

/* Runtime target architecture info */
uint8_t mbpf_runtime_word_size(void) {
    return (uint8_t)(sizeof(void*) * 8);  /* 32 or 64 */
}

uint8_t mbpf_runtime_endianness(void) {
    /* Detect endianness at runtime */
    union { uint16_t u; uint8_t b[2]; } test = { .u = 0x0102 };
    return test.b[0] == 0x01 ? 1 : 0;  /* 1 = big, 0 = little */
}

/* Hook ABI version query */
uint32_t mbpf_hook_abi_version(mbpf_hook_type_t hook_type) {
    switch (hook_type) {
        case MBPF_HOOK_TRACEPOINT:
            return 1;
        case MBPF_HOOK_TIMER:
            return 1;
        case MBPF_HOOK_NET_RX:
            return 1;
        case MBPF_HOOK_NET_TX:
            return 1;
        case MBPF_HOOK_SECURITY:
            return 1;
        case MBPF_HOOK_CUSTOM:
            return 1;
        default:
            return 0;  /* Unknown hook type */
    }
}

/*
 * Get the default return code for a hook type on exception.
 * Used when a program throws an exception or encounters an error.
 *
 * Built-in defaults follow the principle of least privilege for security hooks
 * and safe passthrough for network/observability hooks.
 */
int32_t mbpf_hook_exception_default(mbpf_hook_type_t hook_type) {
    switch (hook_type) {
        case MBPF_HOOK_NET_RX:
        case MBPF_HOOK_NET_TX:
            return MBPF_NET_PASS;  /* Allow packets to pass on error */

        case MBPF_HOOK_SECURITY:
            return MBPF_SEC_DENY;  /* Deny access on error (fail-safe) */

        case MBPF_HOOK_TRACEPOINT:
        case MBPF_HOOK_TIMER:
        case MBPF_HOOK_CUSTOM:
        default:
            return 0;  /* No decision impact for observability hooks */
    }
}

/* Instance access */
uint32_t mbpf_program_instance_count(mbpf_program_t *prog) {
    if (!prog) {
        return 0;
    }
    return prog->instance_count;
}

size_t mbpf_program_instance_heap_size(mbpf_program_t *prog, uint32_t idx) {
    if (!prog || idx >= prog->instance_count || !prog->instances) {
        return 0;
    }
    return prog->instances[idx].heap_size;
}

mbpf_instance_t *mbpf_program_get_instance(mbpf_program_t *prog, uint32_t idx) {
    if (!prog || idx >= prog->instance_count || !prog->instances) {
        return NULL;
    }
    return &prog->instances[idx];
}

/* Ring buffer map access (host-side API) */

int mbpf_program_find_ring_map(mbpf_program_t *prog, const char *name) {
    if (!prog || !name || !prog->maps) {
        return -1;
    }

    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];
        if (storage->type == MBPF_MAP_TYPE_RING &&
            strncmp(storage->name, name, sizeof(storage->name)) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int mbpf_ring_read(mbpf_program_t *prog, int map_idx,
                   void *out_data, size_t max_len) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_RING) {
        return -1;
    }

    mbpf_ring_buffer_map_t *ring = &storage->u.ring;

    /* Check if buffer is empty */
    if (ring->event_count == 0) {
        return 0;
    }

    /* Read length header (4 bytes, little-endian) with wrap-around */
    uint32_t tail = ring->tail;
    uint32_t buf_size = ring->buffer_size;
    uint32_t len = ring->buffer[tail % buf_size] |
                   ((uint32_t)ring->buffer[(tail + 1) % buf_size] << 8) |
                   ((uint32_t)ring->buffer[(tail + 2) % buf_size] << 16) |
                   ((uint32_t)ring->buffer[(tail + 3) % buf_size] << 24);

    /* Copy event data */
    if (out_data && max_len > 0) {
        size_t copy_len = len < max_len ? len : max_len;
        uint32_t data_start = (tail + 4) % buf_size;
        for (size_t i = 0; i < copy_len; i++) {
            ((uint8_t *)out_data)[i] = ring->buffer[(data_start + i) % buf_size];
        }
    }

    /* Consume the event */
    uint32_t record_size = 4 + len;
    ring->tail = (tail + record_size) % buf_size;
    ring->event_count--;

    return (int)len;
}

int mbpf_ring_peek(mbpf_program_t *prog, int map_idx,
                   void *out_data, size_t max_len) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_RING) {
        return -1;
    }

    mbpf_ring_buffer_map_t *ring = &storage->u.ring;

    /* Check if buffer is empty */
    if (ring->event_count == 0) {
        return 0;
    }

    /* Read length header (4 bytes, little-endian) with wrap-around */
    uint32_t tail = ring->tail;
    uint32_t buf_size = ring->buffer_size;
    uint32_t len = ring->buffer[tail % buf_size] |
                   ((uint32_t)ring->buffer[(tail + 1) % buf_size] << 8) |
                   ((uint32_t)ring->buffer[(tail + 2) % buf_size] << 16) |
                   ((uint32_t)ring->buffer[(tail + 3) % buf_size] << 24);

    /* Copy event data (without consuming) */
    if (out_data && max_len > 0) {
        size_t copy_len = len < max_len ? len : max_len;
        uint32_t data_start = (tail + 4) % buf_size;
        for (size_t i = 0; i < copy_len; i++) {
            ((uint8_t *)out_data)[i] = ring->buffer[(data_start + i) % buf_size];
        }
    }

    return (int)len;
}

int mbpf_ring_count(mbpf_program_t *prog, int map_idx) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_RING) {
        return -1;
    }

    return (int)storage->u.ring.event_count;
}

int mbpf_ring_dropped(mbpf_program_t *prog, int map_idx) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_RING) {
        return -1;
    }

    return (int)storage->u.ring.dropped;
}

/* Emit event buffer access (host-side API for mbpf.emit events) */

int mbpf_emit_read(mbpf_program_t *prog, uint32_t *out_event_id,
                   void *out_data, size_t max_len) {
    if (!prog || !prog->emit_buffer) {
        return -1;
    }

    mbpf_emit_buffer_t *emit = prog->emit_buffer;

    /* Check if buffer is empty */
    if (emit->event_count == 0) {
        return 0;
    }

    /* Read eventId (4 bytes, little-endian) with wrap-around */
    uint32_t tail = emit->tail;
    uint32_t buf_size = emit->buffer_size;
    uint32_t event_id = emit->buffer[tail % buf_size] |
                        ((uint32_t)emit->buffer[(tail + 1) % buf_size] << 8) |
                        ((uint32_t)emit->buffer[(tail + 2) % buf_size] << 16) |
                        ((uint32_t)emit->buffer[(tail + 3) % buf_size] << 24);

    /* Read data length (4 bytes, little-endian) */
    uint32_t len = emit->buffer[(tail + 4) % buf_size] |
                   ((uint32_t)emit->buffer[(tail + 5) % buf_size] << 8) |
                   ((uint32_t)emit->buffer[(tail + 6) % buf_size] << 16) |
                   ((uint32_t)emit->buffer[(tail + 7) % buf_size] << 24);

    /* Output event ID if requested */
    if (out_event_id) {
        *out_event_id = event_id;
    }

    /* Copy event data */
    if (out_data && max_len > 0) {
        size_t copy_len = len < max_len ? len : max_len;
        uint32_t data_start = (tail + 8) % buf_size;
        for (size_t i = 0; i < copy_len; i++) {
            ((uint8_t *)out_data)[i] = emit->buffer[(data_start + i) % buf_size];
        }
    }

    /* Consume the event: eventId(4) + dataLen(4) + data */
    uint32_t record_size = 8 + len;
    emit->tail = (tail + record_size) % buf_size;
    emit->event_count--;

    return (int)len;
}

int mbpf_emit_peek(mbpf_program_t *prog, uint32_t *out_event_id,
                   void *out_data, size_t max_len) {
    if (!prog || !prog->emit_buffer) {
        return -1;
    }

    mbpf_emit_buffer_t *emit = prog->emit_buffer;

    /* Check if buffer is empty */
    if (emit->event_count == 0) {
        return 0;
    }

    /* Read eventId (4 bytes, little-endian) with wrap-around */
    uint32_t tail = emit->tail;
    uint32_t buf_size = emit->buffer_size;
    uint32_t event_id = emit->buffer[tail % buf_size] |
                        ((uint32_t)emit->buffer[(tail + 1) % buf_size] << 8) |
                        ((uint32_t)emit->buffer[(tail + 2) % buf_size] << 16) |
                        ((uint32_t)emit->buffer[(tail + 3) % buf_size] << 24);

    /* Read data length (4 bytes, little-endian) */
    uint32_t len = emit->buffer[(tail + 4) % buf_size] |
                   ((uint32_t)emit->buffer[(tail + 5) % buf_size] << 8) |
                   ((uint32_t)emit->buffer[(tail + 6) % buf_size] << 16) |
                   ((uint32_t)emit->buffer[(tail + 7) % buf_size] << 24);

    /* Output event ID if requested */
    if (out_event_id) {
        *out_event_id = event_id;
    }

    /* Copy event data (without consuming) */
    if (out_data && max_len > 0) {
        size_t copy_len = len < max_len ? len : max_len;
        uint32_t data_start = (tail + 8) % buf_size;
        for (size_t i = 0; i < copy_len; i++) {
            ((uint8_t *)out_data)[i] = emit->buffer[(data_start + i) % buf_size];
        }
    }

    return (int)len;
}

int mbpf_emit_count(mbpf_program_t *prog) {
    if (!prog || !prog->emit_buffer) {
        return -1;
    }
    return (int)prog->emit_buffer->event_count;
}

int mbpf_emit_dropped(mbpf_program_t *prog) {
    if (!prog || !prog->emit_buffer) {
        return -1;
    }
    return (int)prog->emit_buffer->dropped;
}

/* Circuit breaker API */

bool mbpf_program_circuit_open(mbpf_program_t *prog) {
    if (!prog) {
        return false;
    }
    return check_circuit_open(prog);
}

int mbpf_program_circuit_reset(mbpf_program_t *prog) {
    if (!prog) {
        return MBPF_ERR_INVALID_ARG;
    }
    prog->circuit_open = false;
    prog->consecutive_failures = 0;
    return MBPF_OK;
}

/*
 * Deferred Execution Queue Implementation
 *
 * Supports deferring observer hook invocations (TRACEPOINT, TIMER) to a
 * worker context. Decision hooks (NET_RX, NET_TX, SECURITY) must run inline.
 */

/* Maximum context size we can store in a single invocation entry */
#define MBPF_DEFERRED_MAX_CTX_SIZE 4096

/* A single queued invocation */
typedef struct mbpf_deferred_entry {
    mbpf_runtime_t *runtime;
    mbpf_hook_id_t hook;
    mbpf_hook_type_t hook_type;

    /* Snapshotted context union - supports TRACEPOINT and TIMER */
    union {
        mbpf_ctx_tracepoint_v1_t tracepoint;
        mbpf_ctx_timer_v1_t timer;
    } ctx;

    /* Snapshotted data buffer (for TRACEPOINT with data) */
    uint8_t *data_snapshot;
    uint32_t data_snapshot_len;
    uint16_t flags;             /* MBPF_CTX_F_TRUNCATED if truncated */
} mbpf_deferred_entry_t;

/* The deferred queue itself */
struct mbpf_deferred_queue {
    mbpf_deferred_entry_t *entries;
    uint32_t max_entries;
    uint32_t max_snapshot_bytes;
    volatile uint32_t head;     /* Next write position */
    volatile uint32_t tail;     /* Next read position */
    volatile uint32_t count;    /* Number of pending entries */
    volatile uint64_t dropped;  /* Dropped invocations counter */
};

bool mbpf_hook_can_defer(mbpf_hook_type_t hook_type) {
    switch (hook_type) {
    case MBPF_HOOK_TRACEPOINT:
    case MBPF_HOOK_TIMER:
        return true;
    case MBPF_HOOK_NET_RX:
    case MBPF_HOOK_NET_TX:
    case MBPF_HOOK_SECURITY:
    case MBPF_HOOK_CUSTOM:
        return false;
    default:
        return false;
    }
}

mbpf_deferred_queue_t *mbpf_deferred_queue_create(const mbpf_deferred_config_t *cfg) {
    if (!cfg || cfg->max_entries == 0) {
        return NULL;
    }

    mbpf_deferred_queue_t *queue = malloc(sizeof(mbpf_deferred_queue_t));
    if (!queue) {
        return NULL;
    }

    queue->entries = calloc(cfg->max_entries, sizeof(mbpf_deferred_entry_t));
    if (!queue->entries) {
        free(queue);
        return NULL;
    }

    queue->max_entries = cfg->max_entries;
    queue->max_snapshot_bytes = cfg->max_snapshot_bytes > 0 ?
                                cfg->max_snapshot_bytes :
                                MBPF_DEFERRED_MAX_CTX_SIZE;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    queue->dropped = 0;

    return queue;
}

void mbpf_deferred_queue_destroy(mbpf_deferred_queue_t *queue) {
    if (!queue) {
        return;
    }

    /* Free any snapshot buffers still in the queue */
    if (queue->entries) {
        for (uint32_t i = 0; i < queue->max_entries; i++) {
            if (queue->entries[i].data_snapshot) {
                free(queue->entries[i].data_snapshot);
            }
        }
        free(queue->entries);
    }

    free(queue);
}

/*
 * Snapshot context for deferred execution.
 * Copies scalar fields and optionally data buffer.
 */
static int snapshot_context(mbpf_deferred_entry_t *entry,
                            mbpf_hook_type_t hook_type,
                            const void *ctx_blob, size_t ctx_len,
                            uint32_t max_snapshot_bytes) {
    entry->hook_type = hook_type;
    entry->flags = 0;

    switch (hook_type) {
    case MBPF_HOOK_TRACEPOINT: {
        if (ctx_len < sizeof(mbpf_ctx_tracepoint_v1_t)) {
            return MBPF_ERR_INVALID_ARG;
        }
        const mbpf_ctx_tracepoint_v1_t *src =
            (const mbpf_ctx_tracepoint_v1_t *)ctx_blob;

        /* Copy scalar fields */
        entry->ctx.tracepoint.abi_version = src->abi_version;
        entry->ctx.tracepoint.tracepoint_id = src->tracepoint_id;
        entry->ctx.tracepoint.timestamp = src->timestamp;
        entry->ctx.tracepoint.cpu = src->cpu;
        entry->ctx.tracepoint.pid = src->pid;
        entry->ctx.tracepoint.flags = src->flags;
        entry->ctx.tracepoint.reserved = src->reserved;
        entry->ctx.tracepoint.read_fn = NULL;  /* Can't use original read_fn */

        /* Snapshot data buffer if present (direct or via read_fn). */
        uint32_t data_len = src->data_len;
        if (data_len > 0 && (src->data || src->read_fn)) {
            uint32_t copy_len = data_len;
            if (copy_len > max_snapshot_bytes) {
                copy_len = max_snapshot_bytes;
                entry->flags |= MBPF_CTX_F_TRUNCATED;
            }

            entry->data_snapshot = malloc(copy_len);
            if (!entry->data_snapshot) {
                entry->data_snapshot_len = 0;
                entry->ctx.tracepoint.data_len = 0;
                entry->ctx.tracepoint.data = NULL;
                return MBPF_ERR_NO_MEM;
            }

            if (src->data) {
                memcpy(entry->data_snapshot, src->data, copy_len);
            } else {
                int read_rc = src->read_fn(ctx_blob, 0, copy_len,
                                           entry->data_snapshot);
                if (read_rc <= 0) {
                    free(entry->data_snapshot);
                    entry->data_snapshot = NULL;
                    entry->data_snapshot_len = 0;
                    entry->ctx.tracepoint.data_len = 0;
                    entry->ctx.tracepoint.data = NULL;
                    entry->flags &= ~MBPF_CTX_F_TRUNCATED;
                    copy_len = 0;
                } else if ((uint32_t)read_rc < copy_len) {
                    copy_len = (uint32_t)read_rc;
                    if (copy_len < data_len) {
                        entry->flags |= MBPF_CTX_F_TRUNCATED;
                    }
                }
            }

            if (entry->data_snapshot) {
                entry->data_snapshot_len = copy_len;
                entry->ctx.tracepoint.data_len = copy_len;
                entry->ctx.tracepoint.data = entry->data_snapshot;
            }
        } else {
            entry->data_snapshot = NULL;
            entry->data_snapshot_len = 0;
            entry->ctx.tracepoint.data_len = 0;
            entry->ctx.tracepoint.data = NULL;
        }
        entry->ctx.tracepoint.flags |= entry->flags;
        break;
    }

    case MBPF_HOOK_TIMER: {
        if (ctx_len < sizeof(mbpf_ctx_timer_v1_t)) {
            return MBPF_ERR_INVALID_ARG;
        }
        const mbpf_ctx_timer_v1_t *src =
            (const mbpf_ctx_timer_v1_t *)ctx_blob;

        /* TIMER contexts have no data buffer - just copy scalars */
        entry->ctx.timer = *src;
        entry->data_snapshot = NULL;
        entry->data_snapshot_len = 0;
        break;
    }

    default:
        return MBPF_ERR_INVALID_ARG;
    }

    return MBPF_OK;
}

int mbpf_queue_invocation(mbpf_deferred_queue_t *queue,
                          mbpf_runtime_t *rt,
                          mbpf_hook_id_t hook,
                          mbpf_hook_type_t hook_type,
                          const void *ctx_blob, size_t ctx_len) {
    if (!queue || !rt || !ctx_blob || ctx_len == 0) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Only observer hooks can be deferred */
    if (!mbpf_hook_can_defer(hook_type)) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Check if queue is full - backpressure: drop and count per-program */
    if (queue->count >= queue->max_entries) {
        __atomic_add_fetch(&queue->dropped, 1, __ATOMIC_RELAXED);
        /* Increment per-program deferred_dropped counter for all programs
         * attached to this hook */
        for (mbpf_program_t *prog = rt->programs; prog; prog = prog->next) {
            if (!prog->unloaded && prog->attached && prog->attached_hook == hook) {
                __atomic_add_fetch(&prog->stats.deferred_dropped, 1, __ATOMIC_RELAXED);
            }
        }
        return MBPF_ERR_NO_MEM;
    }

    /* Get next write position */
    uint32_t pos = queue->head % queue->max_entries;
    mbpf_deferred_entry_t *entry = &queue->entries[pos];

    /* Free any previous snapshot buffer */
    if (entry->data_snapshot) {
        free(entry->data_snapshot);
        entry->data_snapshot = NULL;
    }

    /* Snapshot the context */
    int err = snapshot_context(entry, hook_type, ctx_blob, ctx_len,
                               queue->max_snapshot_bytes);
    if (err != MBPF_OK) {
        return err;
    }

    /* Fill in remaining fields */
    entry->runtime = rt;
    entry->hook = hook;

    /* Atomically increment head and count */
    __atomic_add_fetch(&queue->head, 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&queue->count, 1, __ATOMIC_RELEASE);

    return MBPF_OK;
}

int mbpf_drain_deferred(mbpf_deferred_queue_t *queue) {
    if (!queue) {
        return -1;
    }

    int executed = 0;

    while (queue->count > 0) {
        uint32_t pos = queue->tail % queue->max_entries;
        mbpf_deferred_entry_t *entry = &queue->entries[pos];

        /* Execute the program via mbpf_run */
        int32_t out_rc;
        void *ctx_blob = NULL;
        size_t ctx_len = 0;

        switch (entry->hook_type) {
        case MBPF_HOOK_TRACEPOINT:
            ctx_blob = &entry->ctx.tracepoint;
            ctx_len = sizeof(entry->ctx.tracepoint);
            break;
        case MBPF_HOOK_TIMER:
            ctx_blob = &entry->ctx.timer;
            ctx_len = sizeof(entry->ctx.timer);
            break;
        default:
            /* Should not happen - skip this entry */
            goto next_entry;
        }

        /* Execute the hook */
        mbpf_run(entry->runtime, entry->hook, ctx_blob, ctx_len, &out_rc);
        executed++;

    next_entry:
        /* Free snapshot buffer */
        if (entry->data_snapshot) {
            free(entry->data_snapshot);
            entry->data_snapshot = NULL;
        }

        /* Atomically decrement count and advance tail */
        __atomic_add_fetch(&queue->tail, 1, __ATOMIC_RELEASE);
        __atomic_sub_fetch(&queue->count, 1, __ATOMIC_RELEASE);
    }

    return executed;
}

uint32_t mbpf_deferred_pending(const mbpf_deferred_queue_t *queue) {
    if (!queue) {
        return 0;
    }
    return __atomic_load_n(&queue->count, __ATOMIC_ACQUIRE);
}

uint64_t mbpf_deferred_dropped(const mbpf_deferred_queue_t *queue) {
    if (!queue) {
        return 0;
    }
    return __atomic_load_n(&queue->dropped, __ATOMIC_ACQUIRE);
}

/* ============================================================================
 * Debug Info Query API
 * ============================================================================ */

bool mbpf_program_has_debug_info(mbpf_program_t *prog) {
    if (!prog) return false;
    return prog->has_debug_info;
}

const char *mbpf_program_debug_entry_symbol(mbpf_program_t *prog) {
    if (!prog || !prog->has_debug_info) return NULL;
    if (prog->debug_info.entry_symbol[0] == '\0') return NULL;
    return prog->debug_info.entry_symbol;
}

const char *mbpf_program_debug_hook_name(mbpf_program_t *prog) {
    if (!prog || !prog->has_debug_info) return NULL;
    if (prog->debug_info.hook_name[0] == '\0') return NULL;
    return prog->debug_info.hook_name;
}

int mbpf_program_debug_source_hash(mbpf_program_t *prog, uint8_t out_hash[32]) {
    if (!prog || !out_hash) {
        return MBPF_ERR_INVALID_ARG;
    }
    if (!prog->has_debug_info) {
        return MBPF_ERR_MISSING_SECTION;
    }
    if (!(prog->debug_info.flags & MBPF_DEBUG_FLAG_HAS_SOURCE_HASH)) {
        return MBPF_ERR_MISSING_SECTION;
    }
    memcpy(out_hash, prog->debug_info.source_hash, 32);
    return MBPF_OK;
}

uint32_t mbpf_program_debug_map_count(mbpf_program_t *prog) {
    if (!prog || !prog->has_debug_info) return 0;
    return prog->debug_info.map_count;
}

const char *mbpf_program_debug_map_name(mbpf_program_t *prog, uint32_t index) {
    if (!prog || !prog->has_debug_info) return NULL;
    if (index >= prog->debug_info.map_count) return NULL;
    if (!prog->debug_info.map_names) return NULL;
    return prog->debug_info.map_names[index];
}

/* ============================================================================
 * Lock-Free Map Read API
 *
 * These functions provide lock-free reads from C-side map storage.
 * They use a seqlock pattern to detect torn reads and retry automatically.
 *
 * Note: These APIs read from C-side storage which is synced from JS-side
 * at certain points (program unload, update). For real-time concurrent
 * access, the host must ensure syncs happen appropriately.
 * ============================================================================ */

int mbpf_program_find_map(mbpf_program_t *prog, const char *name) {
    if (!prog || !name || !prog->maps) {
        return -1;
    }

    for (uint32_t i = 0; i < prog->map_count; i++) {
        mbpf_map_storage_t *storage = &prog->maps[i];
        if (strncmp(storage->name, name, sizeof(storage->name)) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int mbpf_map_get_type(mbpf_program_t *prog, int map_idx) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps) {
        return -1;
    }
    return (int)prog->maps[map_idx].type;
}

/*
 * Lock-free array map lookup.
 *
 * Uses seqlock to detect torn reads and retries automatically.
 * Returns:
 *   1 - Entry found and copied to out_value
 *   0 - Entry not found (index invalid or not set)
 *  -1 - Error (invalid arguments)
 */
int mbpf_array_map_lookup_lockfree(mbpf_program_t *prog, int map_idx,
                                    uint32_t index, void *out_value, size_t max_len) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps || !out_value) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_ARRAY) {
        return -1;
    }

    mbpf_array_map_t *arr = &storage->u.array;
    if (index >= arr->max_entries || !arr->values || !arr->valid) {
        return -1;
    }

    size_t copy_len = arr->value_size < max_len ? arr->value_size : max_len;
    size_t offset = (size_t)index * arr->value_size;
    uint32_t bitmap_byte = index / 8;
    uint8_t bitmap_bit = (uint8_t)(1 << (index % 8));

    /* Lock-free read with seqlock retry loop */
    for (;;) {
        uint32_t seq = seqlock_read_begin(&arr->seqlock);

        /* Check validity */
        uint8_t is_valid = arr->valid[bitmap_byte] & bitmap_bit;
        if (!is_valid) {
            /* Entry not set - validate and return */
            if (seqlock_read_validate(&arr->seqlock, seq)) {
                return 0;
            }
            continue;  /* Retry */
        }

        /* Copy value */
        memcpy(out_value, arr->values + offset, copy_len);

        /* Validate read - if sequence changed, we may have read torn data */
        if (seqlock_read_validate(&arr->seqlock, seq)) {
            return 1;  /* Success */
        }
        /* Retry the read */
    }
}

/*
 * Lock-free hash map lookup.
 *
 * Uses seqlock to detect torn reads and retries automatically.
 * Returns:
 *   1 - Entry found and copied to out_value
 *   0 - Entry not found
 *  -1 - Error (invalid arguments)
 */
int mbpf_hash_map_lookup_lockfree(mbpf_program_t *prog, int map_idx,
                                   const void *key, size_t key_len,
                                   void *out_value, size_t max_len) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps ||
        !key || !out_value) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_HASH) {
        return -1;
    }

    mbpf_hash_map_t *hash = &storage->u.hash;
    if (!hash->buckets || key_len < hash->key_size) {
        return -1;
    }

    size_t bucket_size = 1 + hash->key_size + hash->value_size;
    size_t copy_len = hash->value_size < max_len ? hash->value_size : max_len;

    /* FNV-1a hash function */
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < hash->key_size; i++) {
        h ^= ((const uint8_t *)key)[i];
        h *= 16777619u;
    }

    /* Lock-free read with seqlock retry loop */
    for (;;) {
        uint32_t seq = seqlock_read_begin(&hash->seqlock);

        /* Linear probing search */
        for (uint32_t i = 0; i < hash->max_entries; i++) {
            uint32_t idx = (h + i) % hash->max_entries;
            size_t off = idx * bucket_size;
            uint8_t status = hash->buckets[off];

            if (status == 0) {
                /* Empty slot - key not found */
                if (seqlock_read_validate(&hash->seqlock, seq)) {
                    return 0;
                }
                break;  /* Retry from scratch */
            }

            if (status == 1) {
                /* Valid entry - check if key matches */
                if (memcmp(hash->buckets + off + 1, key, hash->key_size) == 0) {
                    /* Key matches - copy value */
                    memcpy(out_value, hash->buckets + off + 1 + hash->key_size, copy_len);
                    if (seqlock_read_validate(&hash->seqlock, seq)) {
                        return 1;  /* Success */
                    }
                    break;  /* Retry from scratch */
                }
            }
            /* status == 2 means deleted (tombstone), keep probing */
        }

        /* Either we need to retry or we exhausted all slots */
        if (seqlock_read_validate(&hash->seqlock, seq)) {
            return 0;  /* Key not found */
        }
        /* Retry the read */
    }
}

/*
 * Lock-free LRU hash map lookup.
 *
 * Note: LRU lookups typically update the access order, but this lock-free
 * read does NOT update LRU order (which would require a write). For true
 * LRU semantics, use the JS-side lookup which updates order.
 *
 * Returns:
 *   1 - Entry found and copied to out_value
 *   0 - Entry not found
 *  -1 - Error (invalid arguments)
 */
int mbpf_lru_map_lookup_lockfree(mbpf_program_t *prog, int map_idx,
                                  const void *key, size_t key_len,
                                  void *out_value, size_t max_len) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps ||
        !key || !out_value) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_LRU) {
        return -1;
    }

    mbpf_lru_hash_map_t *lru = &storage->u.lru_hash;
    if (!lru->buckets || key_len < lru->key_size) {
        return -1;
    }

    /* LRU bucket layout: [valid:1][prev:4][next:4][key][value] */
    size_t bucket_size = 1 + 4 + 4 + lru->key_size + lru->value_size;
    size_t copy_len = lru->value_size < max_len ? lru->value_size : max_len;

    /* FNV-1a hash function */
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < lru->key_size; i++) {
        h ^= ((const uint8_t *)key)[i];
        h *= 16777619u;
    }

    /* Lock-free read with seqlock retry loop */
    for (;;) {
        uint32_t seq = seqlock_read_begin(&lru->seqlock);

        /* Linear probing search */
        for (uint32_t i = 0; i < lru->max_entries; i++) {
            uint32_t idx = (h + i) % lru->max_entries;
            size_t off = idx * bucket_size;
            uint8_t status = lru->buckets[off];

            if (status == 0) {
                /* Empty slot - key not found */
                if (seqlock_read_validate(&lru->seqlock, seq)) {
                    return 0;
                }
                break;  /* Retry from scratch */
            }

            if (status == 1) {
                /* Valid entry - check if key matches (key starts at offset 9) */
                if (memcmp(lru->buckets + off + 9, key, lru->key_size) == 0) {
                    /* Key matches - copy value (value starts after key) */
                    memcpy(out_value, lru->buckets + off + 9 + lru->key_size, copy_len);
                    if (seqlock_read_validate(&lru->seqlock, seq)) {
                        return 1;  /* Success */
                    }
                    break;  /* Retry from scratch */
                }
            }
            /* status == 2 means deleted (tombstone), keep probing */
        }

        /* Either we need to retry or we exhausted all slots */
        if (seqlock_read_validate(&lru->seqlock, seq)) {
            return 0;  /* Key not found */
        }
        /* Retry the read */
    }
}

/*
 * Array map update with seqlock protection.
 *
 * This function updates an array map entry while holding the seqlock,
 * ensuring that concurrent lock-free reads see consistent data.
 *
 * Writers are serialized via mutex to prevent concurrent write races.
 * The sequence is: acquire mutex -> seqlock_write_begin -> modify data ->
 * seqlock_write_end -> release mutex.
 *
 * Returns:
 *   0 - Success
 *  -1 - Error (invalid arguments)
 */
int mbpf_array_map_update_locked(mbpf_program_t *prog, int map_idx,
                                  uint32_t index, const void *value, size_t value_len) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps || !value) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_ARRAY) {
        return -1;
    }

    mbpf_array_map_t *arr = &storage->u.array;
    if (index >= arr->max_entries || !arr->values || !arr->valid) {
        return -1;
    }

    if (value_len < arr->value_size) {
        return -1;
    }

    size_t offset = (size_t)index * arr->value_size;
    uint32_t bitmap_byte = index / 8;
    uint8_t bitmap_bit = (uint8_t)(1 << (index % 8));

    /* Acquire writer lock to serialize concurrent writers */
    pthread_mutex_lock(&arr->writer_lock);

    /* Acquire seqlock for write (signals readers that write is in progress) */
    seqlock_write_begin(&arr->seqlock);

    /* Update value and validity */
    memcpy(arr->values + offset, value, arr->value_size);
    arr->valid[bitmap_byte] |= bitmap_bit;

    /* Release seqlock */
    seqlock_write_end(&arr->seqlock);

    /* Release writer lock */
    pthread_mutex_unlock(&arr->writer_lock);

    return 0;
}

/*
 * Hash map update with seqlock protection.
 *
 * This function updates a hash map entry while holding the seqlock,
 * ensuring that concurrent lock-free reads see consistent data.
 *
 * Writers are serialized via mutex to prevent concurrent write races.
 *
 * Returns:
 *   0 - Success (inserted or updated)
 *  -1 - Error (invalid arguments or table full)
 */
int mbpf_hash_map_update_locked(mbpf_program_t *prog, int map_idx,
                                 const void *key, size_t key_len,
                                 const void *value, size_t value_len) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps ||
        !key || !value) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_HASH) {
        return -1;
    }

    mbpf_hash_map_t *hash = &storage->u.hash;
    if (!hash->buckets || key_len < hash->key_size || value_len < hash->value_size) {
        return -1;
    }

    size_t bucket_size = 1 + hash->key_size + hash->value_size;

    /* FNV-1a hash function */
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < hash->key_size; i++) {
        h ^= ((const uint8_t *)key)[i];
        h *= 16777619u;
    }

    /* Acquire writer lock to serialize concurrent writers */
    pthread_mutex_lock(&hash->writer_lock);

    /* Acquire seqlock for write (signals readers that write is in progress) */
    seqlock_write_begin(&hash->seqlock);

    int result = -1;
    int32_t first_del = -1;

    /* Linear probing search */
    for (uint32_t i = 0; i < hash->max_entries; i++) {
        uint32_t idx = (h + i) % hash->max_entries;
        size_t off = idx * bucket_size;
        uint8_t status = hash->buckets[off];

        if (status == 0) {
            /* Empty slot - insert here or at first deleted */
            size_t insert_off = (first_del >= 0) ? (size_t)first_del : off;
            hash->buckets[insert_off] = 1;  /* Valid */
            memcpy(hash->buckets + insert_off + 1, key, hash->key_size);
            memcpy(hash->buckets + insert_off + 1 + hash->key_size, value, hash->value_size);
            hash->count++;
            result = 0;
            break;
        }

        if (status == 2 && first_del < 0) {
            first_del = (int32_t)off;  /* Remember first deleted slot */
        }

        if (status == 1) {
            /* Valid entry - check if key matches */
            if (memcmp(hash->buckets + off + 1, key, hash->key_size) == 0) {
                /* Key exists - update value */
                memcpy(hash->buckets + off + 1 + hash->key_size, value, hash->value_size);
                result = 0;
                break;
            }
        }
    }

    /* If we didn't find a slot but have a deleted slot, use it */
    if (result == -1 && first_del >= 0) {
        hash->buckets[first_del] = 1;  /* Valid */
        memcpy(hash->buckets + first_del + 1, key, hash->key_size);
        memcpy(hash->buckets + first_del + 1 + hash->key_size, value, hash->value_size);
        hash->count++;
        result = 0;
    }

    /* Release seqlock */
    seqlock_write_end(&hash->seqlock);

    /* Release writer lock */
    pthread_mutex_unlock(&hash->writer_lock);

    return result;
}

/*
 * Hash map delete with seqlock protection.
 *
 * Writers are serialized via mutex to prevent concurrent write races.
 *
 * Returns:
 *   0 - Success (key deleted)
 *   1 - Key not found
 *  -1 - Error (invalid arguments)
 */
int mbpf_hash_map_delete_locked(mbpf_program_t *prog, int map_idx,
                                 const void *key, size_t key_len) {
    if (!prog || map_idx < 0 || (uint32_t)map_idx >= prog->map_count || !prog->maps || !key) {
        return -1;
    }

    mbpf_map_storage_t *storage = &prog->maps[map_idx];
    if (storage->type != MBPF_MAP_TYPE_HASH) {
        return -1;
    }

    mbpf_hash_map_t *hash = &storage->u.hash;
    if (!hash->buckets || key_len < hash->key_size) {
        return -1;
    }

    size_t bucket_size = 1 + hash->key_size + hash->value_size;

    /* FNV-1a hash function */
    uint32_t h = 2166136261u;
    for (uint32_t i = 0; i < hash->key_size; i++) {
        h ^= ((const uint8_t *)key)[i];
        h *= 16777619u;
    }

    /* Acquire writer lock to serialize concurrent writers */
    pthread_mutex_lock(&hash->writer_lock);

    /* Acquire seqlock for write (signals readers that write is in progress) */
    seqlock_write_begin(&hash->seqlock);

    int result = 1;  /* Not found */

    /* Linear probing search */
    for (uint32_t i = 0; i < hash->max_entries; i++) {
        uint32_t idx = (h + i) % hash->max_entries;
        size_t off = idx * bucket_size;
        uint8_t status = hash->buckets[off];

        if (status == 0) {
            /* Empty slot - key not found */
            break;
        }

        if (status == 1) {
            /* Valid entry - check if key matches */
            if (memcmp(hash->buckets + off + 1, key, hash->key_size) == 0) {
                /* Mark as deleted (tombstone) */
                hash->buckets[off] = 2;
                hash->count--;
                result = 0;
                break;
            }
        }
    }

    /* Release seqlock */
    seqlock_write_end(&hash->seqlock);

    /* Release writer lock */
    pthread_mutex_unlock(&hash->writer_lock);

    return result;
}
