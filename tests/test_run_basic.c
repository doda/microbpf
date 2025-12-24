/*
 * microBPF Runtime Run Basic Tests
 *
 * Tests for mbpf_run to execute programs on hook invocation:
 * 1. Load and attach a simple program that returns 0
 * 2. Call mbpf_run with appropriate hook and context
 * 3. Verify out_rc contains the return value (0)
 * 4. Verify program's mbpf_prog function was called
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

/* Helper to build a minimal valid JSON manifest with specific hook type */
static size_t build_test_manifest(uint8_t *buf, size_t cap, int hook_type) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"run_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
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
    const char *js_file = "/tmp/test_run_basic.js";
    const char *bc_file = "/tmp/test_run_basic.qjbc";

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
 * Test Cases - runtime-run-basic
 * ============================================================================ */

/*
 * Test 1: Simple program returns 0
 *
 * Verification steps:
 * 1. Load and attach a simple program that returns 0
 * 2. Call mbpf_run with appropriate hook and context
 * 3. Verify out_rc contains the return value (0)
 */
TEST(run_simple_program_returns_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    /* Step 1: Load and attach */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Step 2: Call mbpf_run */
    int32_t out_rc = -999;  /* Set to unusual value to detect if it changes */
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);

    /* Step 3: Verify out_rc contains return value (0) */
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Verify mbpf_prog function was called by checking stats
 *
 * Verification step 4: Verify program's mbpf_prog function was called
 */
TEST(run_program_called_verified_by_stats) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Check stats before run */
    mbpf_stats_t stats_before = {0};
    mbpf_program_stats(prog, &stats_before);
    ASSERT_EQ(stats_before.invocations, 0);
    ASSERT_EQ(stats_before.successes, 0);

    /* Call mbpf_run */
    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);

    /* Check stats after run - proves mbpf_prog was called */
    mbpf_stats_t stats_after = {0};
    mbpf_program_stats(prog, &stats_after);
    ASSERT_EQ(stats_after.invocations, 1);  /* mbpf_prog was called once */
    ASSERT_EQ(stats_after.successes, 1);    /* Call succeeded */
    ASSERT_EQ(stats_after.exceptions, 0);   /* No exceptions */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 3: Program returns different values correctly */
TEST(run_program_returns_nonzero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    int32_t out_rc = 0;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 4: Program returns negative value */
TEST(run_program_returns_negative) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    int32_t out_rc = 0;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, -1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 5: mbpf_run with no attached programs returns default */
TEST(run_no_attached_programs) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);  /* Default is 0 */

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 6: mbpf_run with NULL runtime returns error */
TEST(run_null_runtime_error) {
    int32_t out_rc = 0;
    int err = mbpf_run(NULL, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);
    return 0;
}

/* Test 7: mbpf_run with NULL out_rc returns error */
TEST(run_null_outrc_error) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 8: Multiple runs update stats correctly */
TEST(run_multiple_times_stats) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 7;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Run 5 times */
    for (int i = 0; i < 5; i++) {
        int32_t out_rc = 0;
        int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, 7);
    }

    /* Verify invocation count */
    mbpf_stats_t stats = {0};
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 5);
    ASSERT_EQ(stats.successes, 5);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 9: Program on different hook type */
TEST(run_net_rx_hook) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 1;\n"  /* MBPF_NET_DROP */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_DROP);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 10: Detached program doesn't run */
TEST(run_detached_program_not_called) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 99;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Verify it runs when attached */
    int32_t out_rc = 0;
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(out_rc, 99);

    mbpf_stats_t stats = {0};
    mbpf_program_stats(prog, &stats);
    uint64_t invocations_before_detach = stats.invocations;

    /* Detach */
    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Run again - should return default, not call program */
    out_rc = -1;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    /* Verify invocation count did not increase */
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, invocations_before_detach);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Runtime Run Basic Tests\n");
    printf("=================================\n\n");

    printf("Core mbpf_run tests:\n");
    RUN_TEST(run_simple_program_returns_zero);
    RUN_TEST(run_program_called_verified_by_stats);
    RUN_TEST(run_program_returns_nonzero);
    RUN_TEST(run_program_returns_negative);

    printf("\nEdge case tests:\n");
    RUN_TEST(run_no_attached_programs);
    RUN_TEST(run_null_runtime_error);
    RUN_TEST(run_null_outrc_error);
    RUN_TEST(run_multiple_times_stats);

    printf("\nHook type tests:\n");
    RUN_TEST(run_net_rx_hook);
    RUN_TEST(run_detached_program_not_called);

    printf("\n=================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
