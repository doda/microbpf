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
#include "mquickjs.h"

/* Stub implementations of the standard library functions.
 * These are referenced by mqjs_stdlib.h but we only need them
 * to exist for linking - the actual bytecode we load may not
 * use them all.
 */

static JSValue js_print(JSContext *ctx, JSValue *this_val, int argc, JSValue *argv) {
    (void)ctx; (void)this_val; (void)argc; (void)argv;
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
