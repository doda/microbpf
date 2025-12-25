/*
 * microBPF Typed Array Access Shim Implementation
 *
 * This implementation accesses MQuickJS internals to provide direct
 * typed array buffer access. It is pinned to a specific MQuickJS revision.
 *
 * MQuickJS version: commit from https://github.com/bellard/mquickjs
 */

#include "mbpf_typed_array.h"
#include "mquickjs_priv.h"

/*
 * Internal MQuickJS structures - replicated here for typed array access.
 * These MUST match the definitions in mquickjs.c exactly.
 * If MQuickJS is updated, these may need to be revised.
 */

/* Memory tag bits reserved at the start of every memory block */
#define MBPF_JS_MTAG_BITS 4

/* Memory block header macro */
#define MBPF_JS_MB_HEADER \
    JSWord gc_mark: 1; \
    JSWord mtag: (MBPF_JS_MTAG_BITS - 1)

/* Helper to compute padding for bitfield widths */
#define MBPF_JS_MB_PAD(n) (sizeof(JSWord) * 8 - (n))

/* JSByteArray - holds raw byte data */
typedef struct {
    MBPF_JS_MB_HEADER;
    JSWord size: MBPF_JS_MB_PAD(MBPF_JS_MTAG_BITS);
    uint8_t buf[];
} mbpf_JSByteArray;

/* JSArrayBuffer - wrapper for byte buffer */
typedef struct {
    JSValue byte_buffer; /* Points to JSByteArray */
} mbpf_JSArrayBuffer;

/* JSTypedArray - typed array view into an ArrayBuffer */
typedef struct {
    JSValue buffer; /* Corresponding array buffer (JSObject with JSArrayBuffer) */
    uint32_t len;   /* Length in elements */
    uint32_t offset; /* Offset in elements from start of buffer */
} mbpf_JSTypedArray;

/* JSObject - simplified for typed array access */
typedef struct {
    MBPF_JS_MB_HEADER;
    JSWord class_id: 8;
    JSWord extra_size: MBPF_JS_MB_PAD(MBPF_JS_MTAG_BITS + 8);

    JSValue proto;
    JSValue props;
    union {
        mbpf_JSArrayBuffer array_buffer;
        mbpf_JSTypedArray typed_array;
    } u;
} mbpf_JSObject;

bool mbpf_is_u8array(JSContext *ctx, JSValue val) {
    (void)ctx; /* Unused, but kept for API consistency */

    /* Check if it's an object pointer */
    if (!JS_IsPtr(val)) {
        return false;
    }

    /* Get the class ID */
    int class_id = JS_GetClassID(ctx, val);
    return class_id == JS_CLASS_UINT8_ARRAY;
}

size_t mbpf_u8array_len(JSContext *ctx, JSValue val) {
    if (!mbpf_is_u8array(ctx, val)) {
        return 0;
    }

    /* Access the typed array structure */
    mbpf_JSObject *p = (mbpf_JSObject *)JS_VALUE_TO_PTR(val);
    return (size_t)p->u.typed_array.len;
}

uint8_t *mbpf_u8array_data(JSContext *ctx, JSValue val) {
    if (!mbpf_is_u8array(ctx, val)) {
        return NULL;
    }

    /* Navigate through the object structures:
     * JSValue (Uint8Array) -> JSObject.typed_array -> buffer (ArrayBuffer JSValue)
     *                      -> JSObject.array_buffer.byte_buffer (JSByteArray JSValue)
     *                      -> JSByteArray.buf + offset
     */
    mbpf_JSObject *p = (mbpf_JSObject *)JS_VALUE_TO_PTR(val);
    JSValue buffer = p->u.typed_array.buffer;

    /* The buffer should be an ArrayBuffer object */
    if (!JS_IsPtr(buffer)) {
        return NULL;
    }

    mbpf_JSObject *p_buffer = (mbpf_JSObject *)JS_VALUE_TO_PTR(buffer);
    JSValue byte_buffer = p_buffer->u.array_buffer.byte_buffer;

    /* The byte_buffer should be a JSByteArray */
    if (!JS_IsPtr(byte_buffer)) {
        return NULL;
    }

    mbpf_JSByteArray *arr = (mbpf_JSByteArray *)JS_VALUE_TO_PTR(byte_buffer);

    /* Return pointer to the data at the appropriate offset */
    return arr->buf + p->u.typed_array.offset;
}
