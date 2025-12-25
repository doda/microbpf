/*
 * microBPF Program Attach Validation Tests
 *
 * Tests for validating hook type and context ABI version during attach:
 * - Attempt to attach program to mismatched hook type - verify rejection
 * - Attempt to attach program with incompatible hook_ctx_abi_version - verify rejection
 * - Attempt to attach same program twice to same hook - verify appropriate behavior
 * - Attach multiple programs to same hook - verify all execute
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
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Helper to build a minimal valid JSON manifest with specific hook type and ABI version */
static size_t build_test_manifest_with_abi(uint8_t *buf, size_t cap, int hook_type, int abi_version) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"attach_validation_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":%d,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        hook_type, abi_version, mbpf_runtime_word_size(), mbpf_runtime_endianness());
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and configurable manifest */
static size_t build_mbpf_package_with_abi(uint8_t *buf, size_t cap,
                                           const uint8_t *bytecode, size_t bc_len,
                                           int hook_type, int abi_version) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest_with_abi(manifest, sizeof(manifest), hook_type, abi_version);
    if (manifest_len == 0) return 0;

    /* Calculate offsets */
    uint32_t header_size = 20 + 2 * 16;  /* header + 2 section descriptors */
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
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Manifest section data */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    /* Bytecode section data */
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_attach_validation.js";
    const char *bc_file = "/tmp/test_attach_validation.qjbc";

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

/* ============================================================================
 * Test Cases - program-attach-validation
 * ============================================================================ */

/* Test 1: Attempt to attach program to mismatched hook type - verify rejection */
TEST(attach_hook_type_mismatch) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with TRACEPOINT hook type */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_abi(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Try to attach to TIMER hook (mismatched) */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    /* Try to attach to NET_RX hook (mismatched) */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    /* Correct hook should succeed */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 2: Attempt to attach program with incompatible hook_ctx_abi_version - verify rejection */
TEST(attach_abi_version_mismatch) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with ABI version 2 (runtime supports version 1) */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_abi(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT, 2);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Try to attach - should fail due to ABI mismatch */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_ABI_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 3: Verify ABI version 0 is rejected (invalid) */
TEST(attach_abi_version_zero_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with ABI version 0 (invalid) */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_abi(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Try to attach - should fail due to ABI mismatch (0 != 1) */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_ABI_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 4: Verify future ABI version (higher than supported) is rejected */
TEST(attach_abi_version_future_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with ABI version 99 (way in the future) */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_abi(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_NET_RX, 99);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Try to attach - should fail due to ABI mismatch */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_ERR_ABI_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 5: Attempt to attach same program twice to same hook */
TEST(attach_same_program_twice) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_abi(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* First attach succeeds */
    int err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Second attach to same hook fails */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_ALREADY_ATTACHED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 6: Attach multiple programs to same hook - verify all execute */
TEST(attach_multiple_programs_same_hook) {
    const char *js_code1 = "function mbpf_prog(ctx) { return 10; }\n";
    const char *js_code2 = "function mbpf_prog(ctx) { return 20; }\n";
    const char *js_code3 = "function mbpf_prog(ctx) { return 30; }\n";

    size_t bc_len1, bc_len2, bc_len3;
    uint8_t *bc1 = compile_js_to_bytecode(js_code1, &bc_len1);
    uint8_t *bc2 = compile_js_to_bytecode(js_code2, &bc_len2);
    uint8_t *bc3 = compile_js_to_bytecode(js_code3, &bc_len3);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);
    ASSERT_NOT_NULL(bc3);

    uint8_t pkg1[8192], pkg2[8192], pkg3[8192];
    size_t len1 = build_mbpf_package_with_abi(pkg1, sizeof(pkg1), bc1, bc_len1, MBPF_HOOK_TRACEPOINT, 1);
    size_t len2 = build_mbpf_package_with_abi(pkg2, sizeof(pkg2), bc2, bc_len2, MBPF_HOOK_TRACEPOINT, 1);
    size_t len3 = build_mbpf_package_with_abi(pkg3, sizeof(pkg3), bc3, bc_len3, MBPF_HOOK_TRACEPOINT, 1);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog1 = NULL, *prog2 = NULL, *prog3 = NULL;
    ASSERT_EQ(mbpf_program_load(rt, pkg1, len1, NULL, &prog1), MBPF_OK);
    ASSERT_EQ(mbpf_program_load(rt, pkg2, len2, NULL, &prog2), MBPF_OK);
    ASSERT_EQ(mbpf_program_load(rt, pkg3, len3, NULL, &prog3), MBPF_OK);

    /* Attach all three to same hook */
    ASSERT_EQ(mbpf_program_attach(rt, prog1, MBPF_HOOK_TRACEPOINT), MBPF_OK);
    ASSERT_EQ(mbpf_program_attach(rt, prog2, MBPF_HOOK_TRACEPOINT), MBPF_OK);
    ASSERT_EQ(mbpf_program_attach(rt, prog3, MBPF_HOOK_TRACEPOINT), MBPF_OK);

    /* Fire the hook */
    int32_t out_rc = 0;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);

    /* All three should have run (check invocation counts) */
    mbpf_stats_t stats1 = {0}, stats2 = {0}, stats3 = {0};
    mbpf_program_stats(prog1, &stats1);
    mbpf_program_stats(prog2, &stats2);
    mbpf_program_stats(prog3, &stats3);
    ASSERT_EQ(stats1.invocations, 1);
    ASSERT_EQ(stats2.invocations, 1);
    ASSERT_EQ(stats3.invocations, 1);

    /* Run again and verify counts */
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    mbpf_program_stats(prog1, &stats1);
    mbpf_program_stats(prog2, &stats2);
    mbpf_program_stats(prog3, &stats3);
    ASSERT_EQ(stats1.invocations, 2);
    ASSERT_EQ(stats2.invocations, 2);
    ASSERT_EQ(stats3.invocations, 2);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    free(bc3);
    return 0;
}

/* Test 7: Multiple programs on same hook, return values verified */
TEST(attach_multiple_programs_return_values) {
    const char *js_code1 = "function mbpf_prog(ctx) { return 1; }\n";
    const char *js_code2 = "function mbpf_prog(ctx) { return 2; }\n";

    size_t bc_len1, bc_len2;
    uint8_t *bc1 = compile_js_to_bytecode(js_code1, &bc_len1);
    uint8_t *bc2 = compile_js_to_bytecode(js_code2, &bc_len2);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);

    uint8_t pkg1[8192], pkg2[8192];
    size_t len1 = build_mbpf_package_with_abi(pkg1, sizeof(pkg1), bc1, bc_len1, MBPF_HOOK_NET_RX, 1);
    size_t len2 = build_mbpf_package_with_abi(pkg2, sizeof(pkg2), bc2, bc_len2, MBPF_HOOK_NET_RX, 1);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog1 = NULL, *prog2 = NULL;
    ASSERT_EQ(mbpf_program_load(rt, pkg1, len1, NULL, &prog1), MBPF_OK);
    ASSERT_EQ(mbpf_program_load(rt, pkg2, len2, NULL, &prog2), MBPF_OK);

    /* Attach both */
    ASSERT_EQ(mbpf_program_attach(rt, prog1, MBPF_HOOK_NET_RX), MBPF_OK);
    ASSERT_EQ(mbpf_program_attach(rt, prog2, MBPF_HOOK_NET_RX), MBPF_OK);

    /* Fire the hook */
    int32_t out_rc = 0;
    mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);

    /* The return value should be from one of the programs (1 or 2) */
    ASSERT(out_rc == 1 || out_rc == 2);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/* Test 8: Verify correct ABI version succeeds */
TEST(attach_correct_abi_version_succeeds) {
    const char *js_code = "function mbpf_prog(ctx) { return 42; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with correct ABI version (1) */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_abi(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Attach should succeed */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run and verify return value */
    int32_t out_rc = 0;
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 9: Verify hook_abi_version function returns correct values */
TEST(hook_abi_version_function) {
    /* All known hook types should return 1 (current version) */
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_TRACEPOINT), 1);
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_TIMER), 1);
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_NET_RX), 1);
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_NET_TX), 1);
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_SECURITY), 1);
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_CUSTOM), 1);

    /* Unknown hook type should return 0 */
    ASSERT_EQ(mbpf_hook_abi_version((mbpf_hook_type_t)99), 0);
    ASSERT_EQ(mbpf_hook_abi_version((mbpf_hook_type_t)0), 0);

    return 0;
}

/* Test 10: Attach to different hook types with mismatched ABI */
TEST(attach_different_hooks_abi_mismatch) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Test NET_RX with wrong ABI */
    uint8_t pkg_netrx[8192];
    size_t pkg_len = build_mbpf_package_with_abi(pkg_netrx, sizeof(pkg_netrx), bytecode, bc_len,
                                                  MBPF_HOOK_NET_RX, 5);
    mbpf_program_t *prog1 = NULL;
    ASSERT_EQ(mbpf_program_load(rt, pkg_netrx, pkg_len, NULL, &prog1), MBPF_OK);
    ASSERT_EQ(mbpf_program_attach(rt, prog1, MBPF_HOOK_NET_RX), MBPF_ERR_ABI_MISMATCH);

    /* Test TIMER with wrong ABI */
    uint8_t pkg_timer[8192];
    pkg_len = build_mbpf_package_with_abi(pkg_timer, sizeof(pkg_timer), bytecode, bc_len,
                                           MBPF_HOOK_TIMER, 3);
    mbpf_program_t *prog2 = NULL;
    ASSERT_EQ(mbpf_program_load(rt, pkg_timer, pkg_len, NULL, &prog2), MBPF_OK);
    ASSERT_EQ(mbpf_program_attach(rt, prog2, MBPF_HOOK_TIMER), MBPF_ERR_ABI_MISMATCH);

    /* Test SECURITY with wrong ABI */
    uint8_t pkg_sec[8192];
    pkg_len = build_mbpf_package_with_abi(pkg_sec, sizeof(pkg_sec), bytecode, bc_len,
                                           MBPF_HOOK_SECURITY, 2);
    mbpf_program_t *prog3 = NULL;
    ASSERT_EQ(mbpf_program_load(rt, pkg_sec, pkg_len, NULL, &prog3), MBPF_OK);
    ASSERT_EQ(mbpf_program_attach(rt, prog3, MBPF_HOOK_SECURITY), MBPF_ERR_ABI_MISMATCH);

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

    printf("microBPF Program Attach Validation Tests\n");
    printf("=========================================\n");

    printf("\nHook type mismatch tests:\n");
    RUN_TEST(attach_hook_type_mismatch);

    printf("\nABI version validation tests:\n");
    RUN_TEST(attach_abi_version_mismatch);
    RUN_TEST(attach_abi_version_zero_rejected);
    RUN_TEST(attach_abi_version_future_rejected);
    RUN_TEST(attach_correct_abi_version_succeeds);
    RUN_TEST(hook_abi_version_function);
    RUN_TEST(attach_different_hooks_abi_mismatch);

    printf("\nDuplicate attach tests:\n");
    RUN_TEST(attach_same_program_twice);

    printf("\nMultiple programs on same hook tests:\n");
    RUN_TEST(attach_multiple_programs_same_hook);
    RUN_TEST(attach_multiple_programs_return_values);

    printf("\n=========================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
