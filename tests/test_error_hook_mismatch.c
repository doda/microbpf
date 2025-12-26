/*
 * microBPF Hook Mismatch Error Tests
 *
 * Tests for appropriate error handling for hook mismatches:
 * - Attach NET_RX program to TIMER hook - verify error
 * - Attach program with wrong context ABI version - verify error
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
static size_t build_manifest_with_hook(uint8_t *buf, size_t cap, int hook_type, int abi_version) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"hook_mismatch_test\","
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
static size_t build_package_with_hook(uint8_t *buf, size_t cap,
                                      const uint8_t *bytecode, size_t bc_len,
                                      int hook_type, int abi_version) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_hook(manifest, sizeof(manifest), hook_type, abi_version);
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
    const char *js_file = "/tmp/test_hook_mismatch.js";
    const char *bc_file = "/tmp/test_hook_mismatch.qjbc";

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
 * Test Cases - Hook Type Mismatch
 * ============================================================================ */

/* Test 1: Attach NET_RX program to TIMER hook - verify MBPF_ERR_HOOK_MISMATCH */
TEST(net_rx_program_to_timer_hook) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with NET_RX hook type */
    uint8_t pkg[8192];
    size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                              MBPF_HOOK_NET_RX, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Try to attach to TIMER hook (mismatched from NET_RX) */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    /* Verify error message is informative */
    const char *msg = mbpf_error_string(MBPF_ERR_HOOK_MISMATCH);
    ASSERT_NOT_NULL(msg);
    ASSERT(strlen(msg) > 5);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 2: Attach NET_RX program to TRACEPOINT hook - verify error */
TEST(net_rx_program_to_tracepoint_hook) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with NET_RX hook type */
    uint8_t pkg[8192];
    size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                              MBPF_HOOK_NET_RX, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Try to attach to TRACEPOINT hook (mismatched from NET_RX) */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 3: Attach NET_RX program to SECURITY hook - verify error */
TEST(net_rx_program_to_security_hook) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with NET_RX hook type */
    uint8_t pkg[8192];
    size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                              MBPF_HOOK_NET_RX, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Try to attach to SECURITY hook (mismatched from NET_RX) */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 4: Attach TIMER program to NET_RX hook - verify error */
TEST(timer_program_to_net_rx_hook) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with TIMER hook type */
    uint8_t pkg[8192];
    size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                              MBPF_HOOK_TIMER, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Try to attach to NET_RX hook (mismatched from TIMER) */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 5: Correct hook type succeeds (NET_RX to NET_RX) */
TEST(net_rx_program_to_net_rx_hook) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with NET_RX hook type */
    uint8_t pkg[8192];
    size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                              MBPF_HOOK_NET_RX, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Correct hook should succeed */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - Context ABI Version Mismatch
 * ============================================================================ */

/* Test 6: Attach program with wrong context ABI version (v2 on v1 runtime) */
TEST(wrong_abi_version_v2) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with NET_RX hook type but ABI version 2 (runtime supports 1) */
    uint8_t pkg[8192];
    size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                              MBPF_HOOK_NET_RX, 2);
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

    /* Verify error message is informative */
    const char *msg = mbpf_error_string(MBPF_ERR_ABI_MISMATCH);
    ASSERT_NOT_NULL(msg);
    ASSERT(strlen(msg) > 5);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 7: Attach program with wrong context ABI version (v99 far future) */
TEST(wrong_abi_version_far_future) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with TIMER hook type but ABI version 99 */
    uint8_t pkg[8192];
    size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                              MBPF_HOOK_TIMER, 99);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Try to attach - should fail due to ABI mismatch */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_ERR_ABI_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 8: Attach program with ABI version 0 (invalid) */
TEST(wrong_abi_version_zero) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with TRACEPOINT hook type but ABI version 0 */
    uint8_t pkg[8192];
    size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
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

/* Test 9: Correct ABI version succeeds */
TEST(correct_abi_version) {
    const char *js_code = "function mbpf_prog(ctx) { return 42; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package with correct ABI version (1) */
    uint8_t pkg[8192];
    size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
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

    /* Verify program can run */
    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 10: All hook types with wrong ABI version */
TEST(all_hooks_wrong_abi_version) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_hook_type_t hooks[] = {
        MBPF_HOOK_TRACEPOINT,
        MBPF_HOOK_TIMER,
        MBPF_HOOK_NET_RX,
        MBPF_HOOK_NET_TX,
        MBPF_HOOK_SECURITY,
        MBPF_HOOK_CUSTOM
    };

    for (size_t i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
        uint8_t pkg[8192];
        size_t pkg_len = build_package_with_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  hooks[i], 5);  /* Wrong ABI version 5 */
        ASSERT(pkg_len > 0);

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_NOT_NULL(prog);

        /* Try to attach - should fail due to ABI mismatch */
        err = mbpf_program_attach(rt, prog, hooks[i]);
        ASSERT_EQ(err, MBPF_ERR_ABI_MISMATCH);
    }

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

    printf("microBPF Hook Mismatch Error Tests\n");
    printf("===================================\n");

    printf("\nHook type mismatch tests:\n");
    RUN_TEST(net_rx_program_to_timer_hook);
    RUN_TEST(net_rx_program_to_tracepoint_hook);
    RUN_TEST(net_rx_program_to_security_hook);
    RUN_TEST(timer_program_to_net_rx_hook);
    RUN_TEST(net_rx_program_to_net_rx_hook);

    printf("\nContext ABI version mismatch tests:\n");
    RUN_TEST(wrong_abi_version_v2);
    RUN_TEST(wrong_abi_version_far_future);
    RUN_TEST(wrong_abi_version_zero);
    RUN_TEST(correct_abi_version);
    RUN_TEST(all_hooks_wrong_abi_version);

    printf("\n===================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
