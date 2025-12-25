/*
 * microBPF Standard Library Wrapper
 *
 * This file includes the MQuickJS standard library definition needed
 * for running bytecode compiled by mqjs.
 *
 * The stdlib functions (js_print, js_gc, etc.) are stubbed since we
 * don't need full JS evaluation for bytecode loading - we only need
 * the atom tables and class definitions from the stdlib.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "mquickjs.h"

/*
 * Logging infrastructure for mbpf.log helper.
 * Uses thread-local storage to pass runtime configuration to js_print.
 */
typedef struct {
    void (*log_fn)(int level, const char *msg);
    int debug_mode;
    /* Rate limiting state */
    uint32_t log_count;
    time_t last_reset;
} mbpf_log_context_t;

static __thread mbpf_log_context_t *current_log_ctx = NULL;

/* Rate limit: max 100 logs per second in production mode */
#define MBPF_LOG_RATE_LIMIT 100

void mbpf_set_log_context(void *log_fn, int debug_mode) {
    static __thread mbpf_log_context_t ctx;
    ctx.log_fn = (void (*)(int, const char *))log_fn;
    ctx.debug_mode = debug_mode;
    ctx.log_count = 0;
    ctx.last_reset = 0;
    current_log_ctx = &ctx;
}

void mbpf_clear_log_context(void) {
    current_log_ctx = NULL;
}

/*
 * Parse log level prefix from message.
 * Returns the level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR) and sets *msg_start
 * to point past the prefix. If no valid prefix, returns 1 (INFO) and
 * leaves *msg_start unchanged.
 */
static int parse_log_level_prefix(const char *msg, const char **msg_start) {
    *msg_start = msg;

    if (strncmp(msg, "[DEBUG] ", 8) == 0) {
        *msg_start = msg + 8;
        return 0;
    }
    if (strncmp(msg, "[INFO] ", 7) == 0) {
        *msg_start = msg + 7;
        return 1;
    }
    if (strncmp(msg, "[WARN] ", 7) == 0) {
        *msg_start = msg + 7;
        return 2;
    }
    if (strncmp(msg, "[ERROR] ", 8) == 0) {
        *msg_start = msg + 8;
        return 3;
    }

    /* No recognized prefix, default to INFO */
    return 1;
}

/*
 * js_print implementation - called by console.log and used by mbpf.log.
 * In debug mode, logs all messages.
 * In production mode, applies rate limiting.
 *
 * When called via mbpf.log, the message will have a level prefix like
 * "[DEBUG] message" which is parsed to extract the actual level.
 */
static JSValue js_print(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    (void)this_val;

    if (!current_log_ctx || !current_log_ctx->log_fn) {
        return JS_UNDEFINED;
    }

    /* Rate limiting in production mode */
    if (!current_log_ctx->debug_mode) {
        time_t now = time(NULL);
        if (now != current_log_ctx->last_reset) {
            current_log_ctx->last_reset = now;
            current_log_ctx->log_count = 0;
        }
        if (current_log_ctx->log_count >= MBPF_LOG_RATE_LIMIT) {
            return JS_UNDEFINED;  /* Rate limited, silent drop */
        }
        current_log_ctx->log_count++;
    }

    /* Build log message from arguments */
    char msg[256];
    msg[0] = '\0';
    size_t offset = 0;

    for (int i = 0; i < argc && offset < sizeof(msg) - 1; i++) {
        if (i > 0 && offset < sizeof(msg) - 1) {
            msg[offset++] = ' ';
        }

        JSCStringBuf buf;
        const char *str = JS_ToCString(ctx, argv[i], &buf);
        if (str) {
            size_t len = strlen(str);
            if (len > sizeof(msg) - offset - 1) {
                len = sizeof(msg) - offset - 1;
            }
            memcpy(msg + offset, str, len);
            offset += len;
        }
    }
    msg[offset] = '\0';

    /* Parse level prefix from mbpf.log calls and extract actual message */
    const char *actual_msg;
    int level = parse_log_level_prefix(msg, &actual_msg);

    current_log_ctx->log_fn(level, actual_msg);

    return JS_UNDEFINED;
}

static JSValue js_gc(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    (void)ctx; (void)this_val; (void)argc; (void)argv;
    JS_GC(ctx);
    return JS_UNDEFINED;
}

static JSValue js_date_now(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    (void)ctx; (void)this_val; (void)argc; (void)argv;
    return JS_NewInt64(ctx, 0);
}

static JSValue js_performance_now(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    (void)ctx; (void)this_val; (void)argc; (void)argv;
    return JS_NewInt64(ctx, 0);
}

static JSValue js_load(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    (void)ctx; (void)this_val; (void)argc; (void)argv;
    return JS_ThrowTypeError(ctx, "load() not supported in microBPF");
}

static JSValue js_setTimeout(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    (void)ctx; (void)this_val; (void)argc; (void)argv;
    return JS_ThrowTypeError(ctx, "setTimeout() not supported in microBPF");
}

static JSValue js_clearTimeout(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    (void)ctx; (void)this_val; (void)argc; (void)argv;
    return JS_ThrowTypeError(ctx, "clearTimeout() not supported in microBPF");
}

/* Include the stdlib definition after the stub functions */
#include "mqjs_stdlib.h"

/* Export the js_stdlib for use in mbpf_runtime.c */
const JSSTDLibraryDef *mbpf_get_js_stdlib(void) {
    return &js_stdlib;
}
