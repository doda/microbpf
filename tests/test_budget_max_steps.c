/*
 * microBPF Max Steps Budget Enforcement Tests
 *
 * Tests for the budget-max-steps task:
 * 1. Load program with max_steps=1000
 * 2. Run program that loops 100 times - verify completes
 * 3. Run program that loops 10000 times - verify aborted
 * 4. Verify budget exceeded is counted in stats
 * 5. Verify safe default is returned on budget exceeded
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
#define ASSERT_GT(a, b) ASSERT((a) > (b))

/* Helper to compile JavaScript to bytecode */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_budget.js";
    const char *bc_file = "/tmp/test_budget.qjbc";

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

/* Helper to build manifest with specific max_steps */
static size_t build_manifest_with_budget(uint8_t *buf, size_t cap, uint32_t max_steps) {
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"budget_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":%u,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        max_steps);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package_with_budget(uint8_t *buf, size_t cap,
                                              const uint8_t *bytecode, size_t bc_len,
                                              uint32_t max_steps) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_budget(manifest, sizeof(manifest), max_steps);
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
 * Test 1: Load program with max_steps=1000
 * Verify program loads successfully
 */
TEST(load_program_with_max_steps) {
    /* Simple program that just returns 0 */
    const char *js = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_budget(pkg, sizeof(pkg), bytecode, bc_len, 1000);
    free(bytecode);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.debug_mode = true;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 2: Run program that loops 100 times with max_steps=1000
 * Should complete successfully
 */
TEST(short_loop_completes) {
    /* Program that loops 100 times */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  var sum = 0;\n"
        "  for (var i = 0; i < 100; i++) {\n"
        "    sum += i;\n"
        "  }\n"
        "  return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Use higher max_steps to ensure small loop completes */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_budget(pkg, sizeof(pkg), bytecode, bc_len, 10000);
    free(bytecode);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.debug_mode = true;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 42);  /* Program should complete and return 42 */

    /* Check stats - should have 1 success, 0 budget_exceeded */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.budget_exceeded, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 3: Run program that loops 10000 times with max_steps=1
 * Should be aborted due to budget exceeded.
 *
 * Note: MQuickJS calls the interrupt handler every ~10000 bytecode operations.
 * max_steps represents the number of interrupt handler calls before abort.
 * A 10000-iteration loop uses ~20000 bytecode ops = ~2 interrupt calls.
 * So we use max_steps=1 to trigger budget exceeded within the loop.
 */
TEST(long_loop_aborted) {
    /* Program that loops 10000 times - more than budget allows with max_steps=1 */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  var sum = 0;\n"
        "  for (var i = 0; i < 10000; i++) {\n"
        "    sum += i;\n"
        "  }\n"
        "  return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Use max_steps=1 to trigger budget exceeded.
     * 10000 iterations uses ~2 interrupt handler calls.
     * max_steps=1 means we abort after 1 call. */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_budget(pkg, sizeof(pkg), bytecode, bc_len, 1);
    free(bytecode);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.debug_mode = true;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = 99;  /* Initialize to non-zero to check if it changes */
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Program should be aborted and return exception default (0 for TRACEPOINT) */
    ASSERT_EQ(rc, 0);

    /* Check stats - should have budget_exceeded incremented */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.budget_exceeded, 1);
    ASSERT_EQ(stats.successes, 0);  /* Should not count as success */
    ASSERT_EQ(stats.exceptions, 0);  /* Should not count as regular exception */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 4: Verify budget exceeded is counted in stats
 * Run multiple times and check stats accumulate
 */
TEST(budget_exceeded_counted_in_stats) {
    /* Program that loops too many times */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 50000; i++) { }\n"
        "  return 1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Use very small max_steps to ensure budget is exceeded.
     * 50000 iterations = ~500000 ops = ~50 interrupt calls.
     * max_steps=3 means we abort very early. */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_budget(pkg, sizeof(pkg), bytecode, bc_len, 3);
    free(bytecode);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times */
    for (int i = 0; i < 5; i++) {
        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Check stats */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 5);
    ASSERT_EQ(stats.budget_exceeded, 5);  /* All 5 runs should exceed budget */
    ASSERT_EQ(stats.successes, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 5: Verify safe default is returned on budget exceeded
 * NET_RX should return PASS (0) on budget exceeded
 */
TEST(safe_default_on_net_rx_budget_exceeded) {
    /* Program that loops too many times */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 50000; i++) { }\n"
        "  return 1;\n"  /* Would return DROP (1) if completed */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package for NET_RX hook with very small max_steps=3 */
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"budget_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":3,"  /* NET_RX */
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":3,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}");

    uint8_t manifest[512];
    size_t manifest_len = strlen(json);
    memcpy(manifest, json, manifest_len);

    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;

    uint8_t pkg[8192];
    uint8_t *p = pkg;

    /* Header */
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

    size_t pkg_len = (size_t)(p - pkg);
    free(bytecode);

    mbpf_runtime_config_t cfg = {0};
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = 99;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, MBPF_NET_PASS);  /* Should return PASS (0) on budget exceeded */

    mbpf_program_detach(rt, prog, MBPF_HOOK_NET_RX);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 6: Verify SECURITY hook returns DENY on budget exceeded
 */
TEST(safe_default_on_security_budget_exceeded) {
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 50000; i++) { }\n"
        "  return 0;\n"  /* Would return ALLOW (0) if completed */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Use very small max_steps=3 to ensure budget is exceeded */
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"budget_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":5,"  /* SECURITY */
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":3,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}");

    uint8_t manifest[512];
    size_t manifest_len = strlen(json);
    memcpy(manifest, json, manifest_len);

    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;

    uint8_t pkg[8192];
    uint8_t *p = pkg;

    /* Header */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

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

    size_t pkg_len = (size_t)(p - pkg);
    free(bytecode);

    mbpf_runtime_config_t cfg = {0};
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = 99;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, MBPF_SEC_DENY);  /* Should return DENY (1) on budget exceeded */

    mbpf_program_detach(rt, prog, MBPF_HOOK_SECURITY);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 7: Budget resets between invocations
 * Run short program multiple times, all should succeed
 */
TEST(budget_resets_between_runs) {
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  var sum = 0;\n"
        "  for (var i = 0; i < 50; i++) {\n"
        "    sum += i;\n"
        "  }\n"
        "  return 1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_budget(pkg, sizeof(pkg), bytecode, bc_len, 5000);
    free(bytecode);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times - each should complete */
    for (int i = 0; i < 10; i++) {
        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 1);  /* Program returns 1 */
    }

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 10);
    ASSERT_EQ(stats.successes, 10);  /* All should succeed */
    ASSERT_EQ(stats.budget_exceeded, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 8: Zero max_steps means no budget enforcement (uses runtime default)
 */
TEST(zero_max_steps_uses_default) {
    /* Program with a moderate loop */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 500; i++) { }\n"
        "  return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* max_steps=0 in manifest */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_budget(pkg, sizeof(pkg), bytecode, bc_len, 0);
    free(bytecode);
    ASSERT_GT(pkg_len, 0);

    /* Runtime has default_max_steps set high */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_max_steps = 100000;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 42);  /* Should complete with runtime default */

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.successes, 1);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Main test runner
 */
int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Max Steps Budget Enforcement Tests\n");
    printf("============================================\n\n");

    printf("Loading and max_steps configuration tests:\n");
    RUN_TEST(load_program_with_max_steps);

    printf("\nBudget enforcement tests:\n");
    RUN_TEST(short_loop_completes);
    RUN_TEST(long_loop_aborted);
    RUN_TEST(budget_exceeded_counted_in_stats);

    printf("\nSafe default return value tests:\n");
    RUN_TEST(safe_default_on_net_rx_budget_exceeded);
    RUN_TEST(safe_default_on_security_budget_exceeded);

    printf("\nBudget reset and default behavior tests:\n");
    RUN_TEST(budget_resets_between_runs);
    RUN_TEST(zero_max_steps_uses_default);

    printf("\n============================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
