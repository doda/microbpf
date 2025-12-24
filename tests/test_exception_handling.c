/*
 * microBPF Exception Handling Tests
 *
 * Tests for the exception-handling task:
 * 1. Run program that throws an exception
 * 2. Verify exception is caught and doesn't crash runtime
 * 3. Verify policy-defined default is returned (e.g., PASS for NET_RX, DENY for SECURITY)
 * 4. Verify exception is counted in per-program stats
 * 5. Configure different default for different hook types
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

/* Helper to compile JavaScript to bytecode */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_exception.js";
    const char *bc_file = "/tmp/test_exception.qjbc";

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

/* Helper to build manifest with specific hook type */
static size_t build_manifest_for_hook(uint8_t *buf, size_t cap, int hook_type) {
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"exception_test\","
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

/* Build a complete .mbpf package */
static size_t build_mbpf_package_for_hook(uint8_t *buf, size_t cap,
                                           const uint8_t *bytecode, size_t bc_len,
                                           int hook_type) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_for_hook(manifest, sizeof(manifest), hook_type);
    if (manifest_len == 0) return 0;

    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 0: MANIFEST */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 1: BYTECODE */
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

/* ============================================================================
 * Test Cases
 * ============================================================================ */

/*
 * Test 1: Exception in NET_RX program returns PASS (default for network hooks)
 */
TEST(net_rx_exception_returns_pass) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Exception in NET_TX program returns PASS
 */
TEST(net_tx_exception_returns_pass) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_NET_TX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_TX);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_TX, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Exception in SECURITY program returns DENY (fail-safe)
 */
TEST(security_exception_returns_deny) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_SECURITY);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Exception in TIMER program returns 0 (observability, no decision impact)
 */
TEST(timer_exception_returns_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_TIMER);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Exception in TRACEPOINT program returns 0 (observability)
 */
TEST(tracepoint_exception_returns_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Exception is counted in per-program stats
 */
TEST(exception_counted_in_stats) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program 5 times */
    for (int i = 0; i < 5; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 5);
    ASSERT_EQ(stats.exceptions, 5);
    ASSERT_EQ(stats.successes, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Exception doesn't crash the runtime (can continue running after)
 */
TEST(exception_doesnt_crash_runtime) {
    const char *throwing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(throwing_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times - should not crash */
    for (int i = 0; i < 10; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_NET_PASS);
    }

    /* Runtime should still be functional */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 10);
    ASSERT_EQ(stats.exceptions, 10);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Custom exception default callback for testing */
static int32_t custom_exception_default(mbpf_hook_type_t hook_type) {
    /* Return 42 for NET_RX, 99 for everything else */
    if (hook_type == MBPF_HOOK_NET_RX) {
        return 42;
    }
    return 99;
}

/*
 * Test 8: Custom exception default callback works
 */
TEST(custom_exception_callback) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    /* Configure runtime with custom exception callback */
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG,
        .exception_default_fn = custom_exception_default
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Should get the custom value 42 from our callback */
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Built-in mbpf_hook_exception_default function returns correct values
 */
TEST(builtin_exception_defaults) {
    /* NET_RX and NET_TX should return PASS (0) */
    ASSERT_EQ(mbpf_hook_exception_default(MBPF_HOOK_NET_RX), MBPF_NET_PASS);
    ASSERT_EQ(mbpf_hook_exception_default(MBPF_HOOK_NET_TX), MBPF_NET_PASS);

    /* SECURITY should return DENY (1) */
    ASSERT_EQ(mbpf_hook_exception_default(MBPF_HOOK_SECURITY), MBPF_SEC_DENY);

    /* Observability hooks should return 0 */
    ASSERT_EQ(mbpf_hook_exception_default(MBPF_HOOK_TIMER), 0);
    ASSERT_EQ(mbpf_hook_exception_default(MBPF_HOOK_TRACEPOINT), 0);
    ASSERT_EQ(mbpf_hook_exception_default(MBPF_HOOK_CUSTOM), 0);

    return 0;
}

/*
 * Test 10: Different hook types get different exception defaults
 */
TEST(different_hook_types_different_defaults) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Test NET_RX returns PASS on exception */
    {
        uint8_t pkg[8192];
        size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                      MBPF_HOOK_NET_RX);
        ASSERT(pkg_len > 0);

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
        ASSERT_EQ(err, MBPF_OK);

        err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
        ASSERT_EQ(err, MBPF_OK);

        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_NET_PASS);

        mbpf_program_detach(rt, prog, MBPF_HOOK_NET_RX);
        mbpf_program_unload(rt, prog);
    }

    /* Test SECURITY returns DENY on exception */
    {
        uint8_t pkg[8192];
        size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                      MBPF_HOOK_SECURITY);
        ASSERT(pkg_len > 0);

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
        ASSERT_EQ(err, MBPF_OK);

        err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
        ASSERT_EQ(err, MBPF_OK);

        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_SECURITY, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_SEC_DENY);

        mbpf_program_detach(rt, prog, MBPF_HOOK_SECURITY);
        mbpf_program_unload(rt, prog);
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Runtime error (accessing undefined) also counts as exception
 */
TEST(runtime_error_is_exception) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return undefined_variable.foo;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.exceptions, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Type error also counts as exception
 */
TEST(type_error_is_exception) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    null.foo();\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_for_hook(pkg, sizeof(pkg), bytecode, bc_len,
                                                  MBPF_HOOK_SECURITY);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);  /* Security hook fail-safe */

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.exceptions, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Exception Handling Tests\n");
    printf("=================================\n\n");

    printf("Hook-specific exception defaults:\n");
    RUN_TEST(net_rx_exception_returns_pass);
    RUN_TEST(net_tx_exception_returns_pass);
    RUN_TEST(security_exception_returns_deny);
    RUN_TEST(timer_exception_returns_zero);
    RUN_TEST(tracepoint_exception_returns_zero);

    printf("\nException counting and stats:\n");
    RUN_TEST(exception_counted_in_stats);

    printf("\nRuntime stability:\n");
    RUN_TEST(exception_doesnt_crash_runtime);

    printf("\nCustom exception callback:\n");
    RUN_TEST(custom_exception_callback);

    printf("\nBuilt-in defaults API:\n");
    RUN_TEST(builtin_exception_defaults);

    printf("\nMultiple hook types:\n");
    RUN_TEST(different_hook_types_different_defaults);

    printf("\nDifferent exception types:\n");
    RUN_TEST(runtime_error_is_exception);
    RUN_TEST(type_error_is_exception);

    printf("\n=================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
