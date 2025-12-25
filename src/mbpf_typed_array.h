/*
 * microBPF Typed Array Access Shim
 *
 * Provides stable API for accessing Uint8Array data from C without
 * depending on MQuickJS internal API changes.
 *
 * IMPORTANT: The pointer returned by mbpf_u8array_data() is ephemeral -
 * it is only valid until the next JS allocation (GC can move data).
 */

#ifndef MBPF_TYPED_ARRAY_H
#define MBPF_TYPED_ARRAY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "mquickjs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Check if a JSValue is a Uint8Array.
 *
 * @param ctx  The JS context
 * @param val  The value to check
 * @return     true if val is a Uint8Array, false otherwise
 */
bool mbpf_is_u8array(JSContext *ctx, JSValue val);

/*
 * Get the length (in elements) of a Uint8Array.
 *
 * @param ctx  The JS context
 * @param val  The Uint8Array value
 * @return     The length in bytes, or 0 if not a valid Uint8Array
 */
size_t mbpf_u8array_len(JSContext *ctx, JSValue val);

/*
 * Get a pointer to the data buffer of a Uint8Array.
 *
 * IMPORTANT: The returned pointer is EPHEMERAL - it is only valid until
 * the next JS allocation or GC operation. Do not store or cache this pointer.
 * Use it immediately and copy data if needed.
 *
 * @param ctx  The JS context
 * @param val  The Uint8Array value
 * @return     Pointer to the data buffer, or NULL if not a valid Uint8Array
 */
uint8_t *mbpf_u8array_data(JSContext *ctx, JSValue val);

#ifdef __cplusplus
}
#endif

#endif /* MBPF_TYPED_ARRAY_H */
