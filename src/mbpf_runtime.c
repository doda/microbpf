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
#include <sched.h>
#include <unistd.h>

/* Get the JS stdlib (defined in mbpf_stdlib.c) */
extern const JSSTDLibraryDef *mbpf_get_js_stdlib(void);

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
};

/* Internal structures */
struct mbpf_runtime {
    mbpf_runtime_config_t config;
    mbpf_program_t *programs;
    size_t program_count;
    uint32_t num_instances;     /* Number of instances per program */
    bool initialized;
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

    if (cfg) {
        rt->config = *cfg;
    } else {
        /* Set reasonable defaults */
        rt->config.default_heap_size = 16384;    /* 16KB */
        rt->config.default_max_steps = 100000;
        rt->config.default_max_helpers = 1000;
        rt->config.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ |
                                          MBPF_CAP_MAP_WRITE;
        rt->config.require_signatures = false;
        rt->config.debug_mode = false;
        rt->config.instance_mode = MBPF_INSTANCE_SINGLE;
        rt->config.instance_count = 1;
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

    inst->js_initialized = true;
    return MBPF_OK;
}

/*
 * Free resources for a single instance.
 */
static void free_instance(mbpf_instance_t *inst) {
    if (inst->js_initialized && inst->js_ctx) {
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

    /* Validate heap_size is at least the platform minimum */
    if (prog->manifest.heap_size < MBPF_MIN_HEAP_SIZE) {
        mbpf_manifest_free(&prog->manifest);
        free(prog);
        return MBPF_ERR_HEAP_TOO_SMALL;
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
            mbpf_manifest_free(&prog->manifest);
            free(prog);
            return err;
        }
    }

    /* Store bc_info from bytecode for reference */
    mbpf_bytecode_check(prog->bytecode, prog->bytecode_len, &prog->bc_info);

    /* Add to runtime's program list */
    prog->next = rt->programs;
    rt->programs = prog;
    rt->program_count++;

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

    /* TODO: Clean up associated maps when map subsystem is implemented.
     * Map cleanup policy:
     * - Shared maps (referenced by other programs) should not be freed
     * - Program-private maps should be freed
     * - Maps with MBPF_MAP_F_PERSIST flag may need special handling
     */

    mbpf_manifest_free(&prog->manifest);
    if (prog->bytecode) {
        free(prog->bytecode);
        prog->bytecode = NULL;
    }
    free(prog);

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

    /* Check for nested execution using atomic compare-and-swap */
    int expected = 0;
    if (!__atomic_compare_exchange_n(&inst->in_use, &expected, 1,
                                      0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        prog->stats.nested_dropped++;
        *out_rc = MBPF_NET_PASS;  /* Default safe value */
        return MBPF_ERR_NESTED_EXEC;
    }

    JSContext *ctx = inst->js_ctx;

    /* Get global object */
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsUndefined(global) || JS_IsException(global)) {
        prog->stats.exceptions++;
        *out_rc = MBPF_NET_PASS;
        __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
        return MBPF_OK;
    }

    /* Look up mbpf_prog function */
    JSValue prog_func = JS_GetPropertyStr(ctx, global, "mbpf_prog");
    if (JS_IsUndefined(prog_func) || !JS_IsFunction(ctx, prog_func)) {
        prog->stats.exceptions++;
        *out_rc = MBPF_NET_PASS;
        __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
        return MBPF_OK;
    }

    /* Check stack space: we need 3 slots (arg + function + this) */
    if (JS_StackCheck(ctx, 3)) {
        prog->stats.exceptions++;
        *out_rc = MBPF_NET_PASS;
        __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
        return MBPF_OK;
    }

    /* Create context object from ctx_blob based on hook type */
    JSValue ctx_arg = create_hook_ctx(ctx, hook, ctx_blob, ctx_len);

    /* Push in order: argument(s), function, this */
    JS_PushArg(ctx, ctx_arg);      /* ctx argument */
    JS_PushArg(ctx, prog_func);    /* function */
    JS_PushArg(ctx, JS_NULL);      /* this */

    prog->stats.invocations++;

    JSValue result = JS_Call(ctx, 1);  /* 1 argument */

    if (JS_IsException(result)) {
        prog->stats.exceptions++;
        JS_GetException(ctx);  /* Clear the exception */
        *out_rc = MBPF_NET_PASS;
        __atomic_store_n(&inst->in_use, 0, __ATOMIC_SEQ_CST);
        return MBPF_OK;
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

    *out_rc = MBPF_NET_PASS;  /* Default safe value */
    int programs_run = 0;

    /* Find and execute all attached programs for this hook */
    for (mbpf_program_t *prog = rt->programs; prog; prog = prog->next) {
        if (!prog->unloaded && prog->attached && prog->attached_hook == hook) {
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
