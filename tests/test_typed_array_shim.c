/*
 * microBPF Typed Array Shim Tests
 *
 * Tests for the typed array access shim:
 * 1. is_u8array(val) - verify correctly identifies Uint8Array
 * 2. u8array_len(val) - verify returns correct length
 * 3. u8array_data(val) - verify returns valid pointer
 * 4. Verify pointer is ephemeral (valid only until next allocation)
 */

#include "mbpf_typed_array.h"
#include "mquickjs.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Get the JS stdlib (defined in mbpf_stdlib.c) */
extern const JSSTDLibraryDef *mbpf_get_js_stdlib(void);

#define TEST(name) static int test_##name(void)
#define RUN_TEST(name) do { \
    printf("  " #name "... "); \
    fflush(stdout); \
    int result = test_##name(); \
    if (result == 0) { \
        printf("PASS\n"); \
        passed++; \
    } else { \
        printf("FAIL\n"); \
        failed++; \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("ASSERT FAILED: " #cond " at line %d\n", __LINE__); return -1; } } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Test heap size */
#define TEST_HEAP_SIZE (64 * 1024)

/* Create a JS context for testing */
static JSContext *create_test_context(void *heap, size_t heap_size) {
    return JS_NewContext(heap, heap_size, mbpf_get_js_stdlib());
}

/*===========================================================================
 * Test: is_u8array correctly identifies Uint8Array
 *===========================================================================*/
TEST(is_u8array_identifies_uint8array) {
    void *heap = malloc(TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(heap);

    JSContext *ctx = create_test_context(heap, TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(ctx);

    /* Create a Uint8Array using JS eval */
    JSValue result = JS_Eval(ctx, "new Uint8Array(10)", strlen("new Uint8Array(10)"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(result));

    /* Test is_u8array */
    bool is_u8 = mbpf_is_u8array(ctx, result);
    ASSERT(is_u8);

    JS_FreeContext(ctx);
    free(heap);
    return 0;
}

/*===========================================================================
 * Test: is_u8array returns false for non-Uint8Array types
 *===========================================================================*/
TEST(is_u8array_rejects_non_uint8array) {
    void *heap = malloc(TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(heap);

    JSContext *ctx = create_test_context(heap, TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(ctx);

    /* Test with a regular array */
    JSValue arr = JS_Eval(ctx, "[1, 2, 3]", strlen("[1, 2, 3]"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr));
    ASSERT(!mbpf_is_u8array(ctx, arr));

    /* Test with a number */
    JSValue num = JS_NewInt32(ctx, 42);
    ASSERT(!mbpf_is_u8array(ctx, num));

    /* Test with undefined */
    ASSERT(!mbpf_is_u8array(ctx, JS_UNDEFINED));

    /* Test with null */
    ASSERT(!mbpf_is_u8array(ctx, JS_NULL));

    /* Test with a string */
    JSValue str = JS_Eval(ctx, "'hello'", strlen("'hello'"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(str));
    ASSERT(!mbpf_is_u8array(ctx, str));

    /* Test with an object */
    JSValue obj = JS_Eval(ctx, "({})", strlen("({})"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(obj));
    ASSERT(!mbpf_is_u8array(ctx, obj));

    /* Test with Int32Array (should return false) */
    JSValue i32arr = JS_Eval(ctx, "new Int32Array(10)", strlen("new Int32Array(10)"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(i32arr));
    ASSERT(!mbpf_is_u8array(ctx, i32arr));

    JS_FreeContext(ctx);
    free(heap);
    return 0;
}

/*===========================================================================
 * Test: u8array_len returns correct length
 *===========================================================================*/
TEST(u8array_len_returns_correct_length) {
    void *heap = malloc(TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(heap);

    JSContext *ctx = create_test_context(heap, TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(ctx);

    /* Test with various sizes */
    JSValue arr10 = JS_Eval(ctx, "new Uint8Array(10)", strlen("new Uint8Array(10)"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr10));
    ASSERT_EQ(mbpf_u8array_len(ctx, arr10), 10u);

    JSValue arr100 = JS_Eval(ctx, "new Uint8Array(100)", strlen("new Uint8Array(100)"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr100));
    ASSERT_EQ(mbpf_u8array_len(ctx, arr100), 100u);

    JSValue arr0 = JS_Eval(ctx, "new Uint8Array(0)", strlen("new Uint8Array(0)"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr0));
    ASSERT_EQ(mbpf_u8array_len(ctx, arr0), 0u);

    JSValue arr1 = JS_Eval(ctx, "new Uint8Array(1)", strlen("new Uint8Array(1)"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr1));
    ASSERT_EQ(mbpf_u8array_len(ctx, arr1), 1u);

    JS_FreeContext(ctx);
    free(heap);
    return 0;
}

/*===========================================================================
 * Test: u8array_len returns 0 for non-Uint8Array
 *===========================================================================*/
TEST(u8array_len_returns_zero_for_invalid) {
    void *heap = malloc(TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(heap);

    JSContext *ctx = create_test_context(heap, TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(ctx);

    /* Test with undefined */
    ASSERT_EQ(mbpf_u8array_len(ctx, JS_UNDEFINED), 0u);

    /* Test with null */
    ASSERT_EQ(mbpf_u8array_len(ctx, JS_NULL), 0u);

    /* Test with a number */
    JSValue num = JS_NewInt32(ctx, 42);
    ASSERT_EQ(mbpf_u8array_len(ctx, num), 0u);

    /* Test with a regular array */
    JSValue arr = JS_Eval(ctx, "[1, 2, 3]", strlen("[1, 2, 3]"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr));
    ASSERT_EQ(mbpf_u8array_len(ctx, arr), 0u);

    JS_FreeContext(ctx);
    free(heap);
    return 0;
}

/*===========================================================================
 * Test: u8array_data returns valid pointer
 *===========================================================================*/
TEST(u8array_data_returns_valid_pointer) {
    void *heap = malloc(TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(heap);

    JSContext *ctx = create_test_context(heap, TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(ctx);

    /* Create a Uint8Array with specific values */
    JSValue arr = JS_Eval(ctx, "new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])", strlen("new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr));

    uint8_t *data = mbpf_u8array_data(ctx, arr);
    ASSERT_NOT_NULL(data);

    /* Verify the data */
    ASSERT_EQ(data[0], 0xDE);
    ASSERT_EQ(data[1], 0xAD);
    ASSERT_EQ(data[2], 0xBE);
    ASSERT_EQ(data[3], 0xEF);
    ASSERT_EQ(data[4], 0xCA);
    ASSERT_EQ(data[5], 0xFE);

    JS_FreeContext(ctx);
    free(heap);
    return 0;
}

/*===========================================================================
 * Test: u8array_data returns NULL for non-Uint8Array
 *===========================================================================*/
TEST(u8array_data_returns_null_for_invalid) {
    void *heap = malloc(TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(heap);

    JSContext *ctx = create_test_context(heap, TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(ctx);

    /* Test with undefined */
    ASSERT_NULL(mbpf_u8array_data(ctx, JS_UNDEFINED));

    /* Test with null */
    ASSERT_NULL(mbpf_u8array_data(ctx, JS_NULL));

    /* Test with a number */
    JSValue num = JS_NewInt32(ctx, 42);
    ASSERT_NULL(mbpf_u8array_data(ctx, num));

    /* Test with a regular array */
    JSValue arr = JS_Eval(ctx, "[1, 2, 3]", strlen("[1, 2, 3]"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr));
    ASSERT_NULL(mbpf_u8array_data(ctx, arr));

    JS_FreeContext(ctx);
    free(heap);
    return 0;
}

/*===========================================================================
 * Test: u8array_data can write to buffer
 *===========================================================================*/
TEST(u8array_data_allows_write) {
    void *heap = malloc(TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(heap);

    JSContext *ctx = create_test_context(heap, TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(ctx);

    /* Create a Uint8Array of zeros */
    JSValue arr = JS_Eval(ctx, "new Uint8Array(4)", strlen("new Uint8Array(4)"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr));

    /* Get the data pointer and write to it */
    uint8_t *data = mbpf_u8array_data(ctx, arr);
    ASSERT_NOT_NULL(data);

    data[0] = 0x11;
    data[1] = 0x22;
    data[2] = 0x33;
    data[3] = 0x44;

    /* Verify the data persists by getting the pointer again */
    uint8_t *data2 = mbpf_u8array_data(ctx, arr);
    ASSERT_EQ(data2[0], 0x11);
    ASSERT_EQ(data2[1], 0x22);
    ASSERT_EQ(data2[2], 0x33);
    ASSERT_EQ(data2[3], 0x44);

    JS_FreeContext(ctx);
    free(heap);
    return 0;
}

/*===========================================================================
 * Test: Subarray has correct offset
 *===========================================================================*/
TEST(u8array_subarray_offset) {
    void *heap = malloc(TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(heap);

    JSContext *ctx = create_test_context(heap, TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(ctx);

    /* Create a Uint8Array and a subarray */
    const char *subarray_code =
        "var parent = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);"
        "var sub = parent.subarray(3, 7);"  /* elements 3, 4, 5, 6 */
        "sub";
    JSValue result = JS_Eval(ctx, subarray_code, strlen(subarray_code), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(result));

    /* Verify length of subarray */
    ASSERT_EQ(mbpf_u8array_len(ctx, result), 4u);

    /* Get the data pointer and verify values (should be 3, 4, 5, 6) */
    uint8_t *data = mbpf_u8array_data(ctx, result);
    ASSERT_NOT_NULL(data);
    ASSERT_EQ(data[0], 3);
    ASSERT_EQ(data[1], 4);
    ASSERT_EQ(data[2], 5);
    ASSERT_EQ(data[3], 6);

    JS_FreeContext(ctx);
    free(heap);
    return 0;
}

/*===========================================================================
 * Test: Pointer is ephemeral (documented behavior)
 *
 * Note: This test documents the ephemeral nature of the pointer.
 * In MQuickJS, the GC can move objects, making previously obtained
 * pointers invalid. While we can't easily trigger a GC in a controlled
 * way in this test, we document the behavior.
 *===========================================================================*/
TEST(pointer_ephemeral_documented) {
    void *heap = malloc(TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(heap);

    JSContext *ctx = create_test_context(heap, TEST_HEAP_SIZE);
    ASSERT_NOT_NULL(ctx);

    /* Create a Uint8Array */
    JSValue arr = JS_Eval(ctx, "new Uint8Array([1, 2, 3, 4])", strlen("new Uint8Array([1, 2, 3, 4])"), "<test>", JS_EVAL_RETVAL);
    ASSERT(!JS_IsException(arr));

    /* Get the data pointer */
    uint8_t *data1 = mbpf_u8array_data(ctx, arr);
    ASSERT_NOT_NULL(data1);
    uint8_t val0 = data1[0];  /* Read immediately */

    /* The pointer is valid immediately after obtaining it */
    ASSERT_EQ(val0, 1);

    /* Trigger some allocations that might cause GC */
    for (int i = 0; i < 100; i++) {
        char code[64];
        snprintf(code, sizeof(code), "new Uint8Array(%d)", i + 1);
        JSValue tmp = JS_Eval(ctx, code, strlen(code), "<test>", JS_EVAL_RETVAL);
        (void)tmp;
    }

    /* Get the pointer again - it should still work (same object, just re-fetched) */
    uint8_t *data2 = mbpf_u8array_data(ctx, arr);
    ASSERT_NOT_NULL(data2);
    ASSERT_EQ(data2[0], 1);
    ASSERT_EQ(data2[1], 2);
    ASSERT_EQ(data2[2], 3);
    ASSERT_EQ(data2[3], 4);

    /* NOTE: data1 may no longer be valid after allocations,
     * but we can't easily test this because it would be UB.
     * The important thing is that re-fetching the pointer works. */

    JS_FreeContext(ctx);
    free(heap);
    return 0;
}

/*===========================================================================
 * Main
 *===========================================================================*/
int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Typed Array Shim Tests\n");
    printf("===============================\n");
    printf("\n");

    printf("is_u8array tests:\n");
    RUN_TEST(is_u8array_identifies_uint8array);
    RUN_TEST(is_u8array_rejects_non_uint8array);

    printf("\nu8array_len tests:\n");
    RUN_TEST(u8array_len_returns_correct_length);
    RUN_TEST(u8array_len_returns_zero_for_invalid);

    printf("\nu8array_data tests:\n");
    RUN_TEST(u8array_data_returns_valid_pointer);
    RUN_TEST(u8array_data_returns_null_for_invalid);
    RUN_TEST(u8array_data_allows_write);
    RUN_TEST(u8array_subarray_offset);

    printf("\nEphemeral pointer tests:\n");
    RUN_TEST(pointer_ephemeral_documented);

    printf("\n===============================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
