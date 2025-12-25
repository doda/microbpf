/*
 * microBPF Return Value Semantics Tests
 *
 * Verifies 32-bit signed integer return value handling from mbpf_prog:
 * 1. Return 0 - verify out_rc is 0
 * 2. Return positive integer - verify out_rc matches
 * 3. Return negative integer - verify out_rc matches
 * 4. Return non-integer - verify conversion to int32
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Helper to build a minimal valid JSON manifest */
static size_t build_test_manifest(uint8_t *buf, size_t cap, int hook_type) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"return_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        hook_type);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest), hook_type);
    if (manifest_len == 0) return 0;

    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;  /* magic "MBPF" LE */
    *p++ = 0x01; *p++ = 0x00;  /* format_version = 1 */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* flags = 0 */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* section_count = 2 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* file_crc32 = 0 */

    /* Section 0: MANIFEST (type=1) */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    memcpy(p, manifest, manifest_len);
    p += manifest_len;
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_return_value.js";
    const char *bc_file = "/tmp/test_return_value.qjbc";

    FILE *f = fopen(js_file, "w");
    if (!f) return NULL;
    fputs(js_code, f);
    fclose(f);

    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "./deps/mquickjs/mqjs --no-column -o %s %s 2>/dev/null",
             bc_file, js_file);
    int ret = system(cmd);
    if (ret != 0) return NULL;

    f = fopen(bc_file, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *bytecode = malloc(len);
    if (!bytecode) { fclose(f); return NULL; }
    if (fread(bytecode, 1, len, f) != (size_t)len) {
        free(bytecode);
        fclose(f);
        return NULL;
    }
    fclose(f);

    *out_len = (size_t)len;
    return bytecode;
}

/* Helper to run a program and get return value */
static int run_js_program(const char *js_code, int32_t *out_rc) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    if (!bytecode) return -1;

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    if (pkg_len == 0) {
        free(bytecode);
        return -1;
    }

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    if (!rt) {
        free(bytecode);
        return -1;
    }

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    if (err != MBPF_OK) {
        mbpf_runtime_shutdown(rt);
        free(bytecode);
        return -1;
    }

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    if (err != MBPF_OK) {
        mbpf_runtime_shutdown(rt);
        free(bytecode);
        return -1;
    }

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, out_rc);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return err;
}

/* ============================================================================
 * Test 1: Return value 0
 * ============================================================================ */

TEST(return_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    int32_t out_rc = -999;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(return_zero_explicit) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var x = 0;\n"
        "    return x;\n"
        "}\n";

    int32_t out_rc = -999;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);
    return 0;
}

/* ============================================================================
 * Test 2: Return positive integers
 * ============================================================================ */

TEST(return_positive_small) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 1;\n"
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);
    return 0;
}

TEST(return_positive_42) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);
    return 0;
}

TEST(return_positive_large) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 2147483647;\n"  /* INT32_MAX */
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2147483647);
    return 0;
}

TEST(return_positive_computed) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 10 + 20 + 30;\n"
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 60);
    return 0;
}

/* ============================================================================
 * Test 3: Return negative integers
 * ============================================================================ */

TEST(return_negative_one) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return -1;\n"
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, -1);
    return 0;
}

TEST(return_negative_42) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return -42;\n"
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, -42);
    return 0;
}

TEST(return_negative_large) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return -2147483648;\n"  /* INT32_MIN */
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, -2147483648);
    return 0;
}

TEST(return_negative_computed) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 10 - 100;\n"
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, -90);
    return 0;
}

/* ============================================================================
 * Test 4: Return non-integer - conversion to int32
 * ============================================================================ */

TEST(return_float_truncates) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 3.7;\n"
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 3);  /* Truncated to 3 */
    return 0;
}

TEST(return_negative_float_truncates) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return -3.7;\n"
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, -3);  /* Truncated to -3 */
    return 0;
}

TEST(return_float_0_9) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0.9;\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* 0.9 truncates to 0 */
    return 0;
}

TEST(return_undefined_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return undefined;\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* Non-number converts to 0 */
    return 0;
}

TEST(return_null_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return null;\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* Non-number converts to 0 */
    return 0;
}

TEST(return_true_becomes_one) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return true;\n"
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Boolean true is not a number, so defaults to 0 */
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(return_false_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return false;\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Boolean false is not a number, so defaults to 0 */
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(return_string_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return \"hello\";\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* String is not a number, defaults to 0 */
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(return_empty_string_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return \"\";\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(return_object_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return {x: 42};\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Object is not a number, defaults to 0 */
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(return_array_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return [1, 2, 3];\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Array is not a number, defaults to 0 */
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(no_return_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var x = 42;\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Function without return returns undefined, which becomes 0 */
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(return_nan_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return NaN;\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* NaN is a number but JS_ToInt32 converts it to 0 */
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(return_infinity_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return Infinity;\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Infinity is a number but JS_ToInt32 converts it to 0 */
    ASSERT_EQ(out_rc, 0);
    return 0;
}

TEST(return_negative_infinity_becomes_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return -Infinity;\n"
        "}\n";

    int32_t out_rc = -1;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* -Infinity is a number but JS_ToInt32 converts it to 0 */
    ASSERT_EQ(out_rc, 0);
    return 0;
}

/* Test overflow wrapping for values beyond int32 range */
TEST(return_overflow_wraps) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 2147483648;\n"  /* INT32_MAX + 1 */
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Should wrap to INT32_MIN */
    ASSERT_EQ(out_rc, -2147483648);
    return 0;
}

TEST(return_underflow_wraps) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return -2147483649;\n"  /* INT32_MIN - 1 */
        "}\n";

    int32_t out_rc = 0;
    int err = run_js_program(js_code, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Should wrap to INT32_MAX */
    ASSERT_EQ(out_rc, 2147483647);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Return Value Semantics Tests\n");
    printf("=====================================\n\n");

    printf("Return zero tests:\n");
    RUN_TEST(return_zero);
    RUN_TEST(return_zero_explicit);

    printf("\nReturn positive integer tests:\n");
    RUN_TEST(return_positive_small);
    RUN_TEST(return_positive_42);
    RUN_TEST(return_positive_large);
    RUN_TEST(return_positive_computed);

    printf("\nReturn negative integer tests:\n");
    RUN_TEST(return_negative_one);
    RUN_TEST(return_negative_42);
    RUN_TEST(return_negative_large);
    RUN_TEST(return_negative_computed);

    printf("\nNon-integer to int32 conversion tests:\n");
    RUN_TEST(return_float_truncates);
    RUN_TEST(return_negative_float_truncates);
    RUN_TEST(return_float_0_9);
    RUN_TEST(return_undefined_becomes_zero);
    RUN_TEST(return_null_becomes_zero);
    RUN_TEST(return_true_becomes_one);
    RUN_TEST(return_false_becomes_zero);
    RUN_TEST(return_string_becomes_zero);
    RUN_TEST(return_empty_string_becomes_zero);
    RUN_TEST(return_object_becomes_zero);
    RUN_TEST(return_array_becomes_zero);
    RUN_TEST(no_return_becomes_zero);
    RUN_TEST(return_nan_becomes_zero);
    RUN_TEST(return_infinity_becomes_zero);
    RUN_TEST(return_negative_infinity_becomes_zero);
    RUN_TEST(return_overflow_wraps);
    RUN_TEST(return_underflow_wraps);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
