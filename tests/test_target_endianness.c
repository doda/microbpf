/*
 * microBPF Target Endianness Tests
 *
 * Tests for target endianness (little vs big endian) handling:
 * - Compile bytecode for little-endian target
 * - Load on little-endian runtime - verify works
 * - Verify endianness mismatch is rejected
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include "mquickjs.h"
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

/* ============================================================================
 * Helper functions
 * ============================================================================ */

/* Build a JSON manifest with specified word size and endianness */
static size_t build_manifest_with_target(uint8_t *buf, size_t cap, int word_size, int endianness) {
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"test_endianness\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%d,\"endianness\":%d},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[]"
        "}", word_size, endianness);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and specified target */
static size_t build_mbpf_with_target(uint8_t *buf, size_t cap,
                                      const uint8_t *bytecode, size_t bc_len,
                                      int word_size, int endianness) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_target(manifest, sizeof(manifest), word_size, endianness);
    if (manifest_len == 0) return 0;

    /* Calculate offsets */
    uint32_t header_size = 20 + 2 * 16;  /* header + 2 section descriptors */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    /* magic */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;  /* "MBPF" LE */
    /* format_version = 1 */
    *p++ = 0x01; *p++ = 0x00;
    /* header_size */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    /* flags = 0 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* section_count = 2 */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* file_crc32 = 0 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 0: MANIFEST (type=1) */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Manifest section */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    /* Bytecode section */
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* Compile a JS program and return bytecode */
static uint8_t *compile_js(const char *js_code, size_t *out_len) {
    /* Write JS to temp file */
    const char *js_file = "/tmp/test_endianness.js";
    const char *bc_file = "/tmp/test_endianness.qjbc";

    FILE *f = fopen(js_file, "w");
    if (!f) return NULL;
    fputs(js_code, f);
    fclose(f);

    /* Compile using mqjs (native word size and endianness) */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "./deps/mquickjs/mqjs --no-column -o %s %s 2>/dev/null",
             bc_file, js_file);
    int ret = system(cmd);
    if (ret != 0) return NULL;

    /* Read bytecode */
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

/* ============================================================================
 * Test Cases
 * ============================================================================ */

/* Test: mbpf_runtime_endianness returns 0 (little) or 1 (big) */
TEST(runtime_endianness_returns_valid_value) {
    uint8_t end = mbpf_runtime_endianness();
    ASSERT(end == 0 || end == 1);
    return 0;
}

/* Test: mbpf_runtime_endianness is consistent */
TEST(runtime_endianness_consistent) {
    uint8_t end1 = mbpf_runtime_endianness();
    uint8_t end2 = mbpf_runtime_endianness();
    ASSERT_EQ(end1, end2);
    return 0;
}

/* Test: Runtime correctly detects little-endian on x86/x64 */
TEST(runtime_is_little_endian) {
    /* Most systems running this will be little-endian (x86/x64, ARM in LE mode) */
    uint8_t end = mbpf_runtime_endianness();
    /* Just verify the function works - the value depends on the actual platform */
    printf("(endianness=%s) ", end == 0 ? "little" : "big");
    return 0;
}

/* Test: Little-endian bytecode loads on little-endian runtime */
TEST(little_endian_bytecode_loads_on_little_endian_runtime) {
    if (mbpf_runtime_endianness() != 0) {
        /* Skip - runtime is not little-endian */
        printf("(skipped - big-endian runtime) ");
        return 0;
    }

    const char *js_code = "function mbpf_prog(ctx) { return 100; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with little-endian target (endianness=0) */
    uint8_t pkg[8192];
    uint8_t runtime_ws = mbpf_runtime_word_size();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, runtime_ws, 0);
    ASSERT(pkg_len > 0);

    /* Create runtime and load program */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT(prog != NULL);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Little-endian bytecode runs correctly on little-endian runtime */
TEST(little_endian_bytecode_runs_correctly) {
    if (mbpf_runtime_endianness() != 0) {
        printf("(skipped - big-endian runtime) ");
        return 0;
    }

    const char *js_code = "function mbpf_prog(ctx) { return 42; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with little-endian target */
    uint8_t pkg[8192];
    uint8_t runtime_ws = mbpf_runtime_word_size();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, runtime_ws, 0);
    ASSERT(pkg_len > 0);

    /* Create runtime, load, attach, and run */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Big-endian bytecode is rejected on little-endian runtime */
TEST(big_endian_rejected_on_little_endian_runtime) {
    if (mbpf_runtime_endianness() != 0) {
        printf("(skipped - big-endian runtime) ");
        return 0;
    }

    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with big-endian target (endianness=1) but on LE runtime */
    uint8_t pkg[8192];
    uint8_t runtime_ws = mbpf_runtime_word_size();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, runtime_ws, 1);
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_TARGET_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Little-endian bytecode is rejected on big-endian runtime */
TEST(little_endian_rejected_on_big_endian_runtime) {
    if (mbpf_runtime_endianness() != 1) {
        printf("(skipped - little-endian runtime) ");
        return 0;
    }

    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with little-endian target (endianness=0) but on BE runtime */
    uint8_t pkg[8192];
    uint8_t runtime_ws = mbpf_runtime_word_size();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, runtime_ws, 0);
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_TARGET_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Endianness mismatch is always rejected regardless of direction */
TEST(endianness_mismatch_always_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 123; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    uint8_t runtime_ws = mbpf_runtime_word_size();
    uint8_t runtime_end = mbpf_runtime_endianness();
    int wrong_end = (runtime_end == 0) ? 1 : 0;

    /* Build package with correct word size but wrong endianness */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, runtime_ws, wrong_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_TARGET_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Verify MBPF_ERR_TARGET_MISMATCH error code value */
TEST(target_mismatch_error_code) {
    ASSERT_EQ(MBPF_ERR_TARGET_MISMATCH, -27);
    return 0;
}

/* Test: Package with matching endianness loads */
TEST(matching_endianness_loads) {
    const char *js_code = "function mbpf_prog(ctx) { return 999; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with runtime's word size and endianness */
    uint8_t pkg[8192];
    uint8_t runtime_ws = mbpf_runtime_word_size();
    uint8_t runtime_end = mbpf_runtime_endianness();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, runtime_ws, runtime_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and load program */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT(prog != NULL);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Both endianness and word size are checked together */
TEST(both_endianness_and_word_size_checked) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    uint8_t runtime_ws = mbpf_runtime_word_size();
    uint8_t runtime_end = mbpf_runtime_endianness();
    int wrong_ws = (runtime_ws == 64) ? 32 : 64;
    int wrong_end = (runtime_end == 0) ? 1 : 0;

    /* Build package with BOTH wrong word size and wrong endianness */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, wrong_ws, wrong_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_TARGET_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Target Endianness Tests\n");
    printf("=================================\n");
    printf("Runtime word size: %u-bit\n", mbpf_runtime_word_size());
    printf("Runtime endianness: %s\n", mbpf_runtime_endianness() == 0 ? "little" : "big");
    printf("\n");

    printf("Runtime info tests:\n");
    RUN_TEST(runtime_endianness_returns_valid_value);
    RUN_TEST(runtime_endianness_consistent);
    RUN_TEST(runtime_is_little_endian);
    RUN_TEST(target_mismatch_error_code);

    printf("\nMatching endianness tests:\n");
    RUN_TEST(matching_endianness_loads);
    RUN_TEST(little_endian_bytecode_loads_on_little_endian_runtime);
    RUN_TEST(little_endian_bytecode_runs_correctly);

    printf("\nEndianness mismatch rejection tests:\n");
    RUN_TEST(endianness_mismatch_always_rejected);
    RUN_TEST(big_endian_rejected_on_little_endian_runtime);
    RUN_TEST(little_endian_rejected_on_big_endian_runtime);
    RUN_TEST(both_endianness_and_word_size_checked);

    printf("\n=================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
