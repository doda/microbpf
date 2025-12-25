/*
 * microBPF Max Helpers Budget Enforcement Tests
 *
 * Tests for the budget-max-helpers task:
 * 1. Load program with max_helpers=10
 * 2. Run program that calls 5 helpers - verify completes
 * 3. Run program that calls 20 helpers - verify aborted
 * 4. Verify helper count includes all helper types
 * 5. Verify safe default returned on limit exceeded
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
    const char *js_file = "/tmp/test_helpers.js";
    const char *bc_file = "/tmp/test_helpers.qjbc";

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

/* Helper to build manifest with specific max_helpers */
static size_t build_manifest_with_helpers_budget(uint8_t *buf, size_t cap, uint32_t max_helpers) {
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"helpers_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":%u},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        max_helpers);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package_with_helpers_budget(uint8_t *buf, size_t cap,
                                              const uint8_t *bytecode, size_t bc_len,
                                              uint32_t max_helpers) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_helpers_budget(manifest, sizeof(manifest), max_helpers);
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
 * Test 1: Load program with max_helpers=10
 * Verify program loads successfully
 */
TEST(load_program_with_max_helpers) {
    /* Simple program that just returns 0 */
    const char *js = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_helpers_budget(pkg, sizeof(pkg), bytecode, bc_len, 10);
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
 * Test 2: Run program that calls 5 helpers with max_helpers=10
 * Should complete successfully
 */
TEST(few_helper_calls_complete) {
    /* Program that calls mbpf.log() 5 times */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  mbpf.log(1, 'call 1');\n"
        "  mbpf.log(1, 'call 2');\n"
        "  mbpf.log(1, 'call 3');\n"
        "  mbpf.log(1, 'call 4');\n"
        "  mbpf.log(1, 'call 5');\n"
        "  return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* max_helpers=10, program calls 5 helpers, should complete */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_helpers_budget(pkg, sizeof(pkg), bytecode, bc_len, 10);
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
 * Test 3: Run program that calls 20 helpers with max_helpers=10
 * Should be aborted due to helper budget exceeded
 */
TEST(many_helper_calls_aborted) {
    /* Program that calls mbpf.log() 20 times */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 20; i++) {\n"
        "    mbpf.log(1, 'iteration ' + i);\n"
        "  }\n"
        "  return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* max_helpers=10, program calls 20 helpers, should abort */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_helpers_budget(pkg, sizeof(pkg), bytecode, bc_len, 10);
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
 * Test 4: Verify helper count includes different helper types
 * Test with mbpf.log, mbpf.u64LoadLE, and mbpf.u64StoreLE
 */
TEST(helper_count_includes_all_types) {
    /* Program that calls different helper types */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  var buf = new Uint8Array(8);\n"
        "  var out = [0, 0];\n"
        "  mbpf.log(1, 'test1');\n"       /* helper 1 */
        "  mbpf.log(1, 'test2');\n"       /* helper 2 */
        "  mbpf.u64StoreLE(buf, 0, [42, 0]);\n"  /* helper 3 */
        "  mbpf.u64LoadLE(buf, 0, out);\n"       /* helper 4 */
        "  mbpf.log(1, 'test3');\n"       /* helper 5 */
        "  mbpf.u64StoreLE(buf, 0, [100, 0]);\n" /* helper 6 - exceeds limit of 5 */
        "  return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* max_helpers=5, program calls 6 different helpers, should abort */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_helpers_budget(pkg, sizeof(pkg), bytecode, bc_len, 5);
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

    int32_t rc = 99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Should abort after 6th helper call */
    ASSERT_EQ(rc, 0);

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.budget_exceeded, 1);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 5: Verify safe default is returned on helper budget exceeded
 * NET_RX should return PASS (0) on helper budget exceeded
 */
TEST(safe_default_on_net_rx_helper_exceeded) {
    /* Program that calls too many helpers */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 20; i++) {\n"
        "    mbpf.log(1, 'call ' + i);\n"
        "  }\n"
        "  return 1;\n"  /* Would return DROP (1) if completed */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package for NET_RX hook with max_helpers=5 */
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"helpers_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":3,"  /* NET_RX */
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":5},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());

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
 * Test 6: Helper budget resets between invocations
 * Run program multiple times that calls just under limit, all should succeed
 */
TEST(helper_budget_resets_between_runs) {
    /* Program that calls 5 helpers */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  mbpf.log(1, 'a');\n"
        "  mbpf.log(1, 'b');\n"
        "  mbpf.log(1, 'c');\n"
        "  mbpf.log(1, 'd');\n"
        "  mbpf.log(1, 'e');\n"
        "  return 1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* max_helpers=5, program calls exactly 5 helpers each time */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_helpers_budget(pkg, sizeof(pkg), bytecode, bc_len, 5);
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
 * Test 7: Zero max_helpers means no helper budget enforcement (uses runtime default)
 */
TEST(zero_max_helpers_uses_default) {
    /* Program with many helper calls */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 50; i++) {\n"
        "    mbpf.log(1, 'msg');\n"
        "  }\n"
        "  return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* max_helpers=0 in manifest means use runtime default */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_helpers_budget(pkg, sizeof(pkg), bytecode, bc_len, 0);
    free(bytecode);
    ASSERT_GT(pkg_len, 0);

    /* Runtime has default_max_helpers set high */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_max_helpers = 1000;
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
 * Test 8: SECURITY hook returns DENY on helper budget exceeded
 */
TEST(safe_default_on_security_helper_exceeded) {
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 20; i++) {\n"
        "    mbpf.log(1, 'call');\n"
        "  }\n"
        "  return 0;\n"  /* Would return ALLOW (0) if completed */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package for SECURITY hook with max_helpers=5 */
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"helpers_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":5,"  /* SECURITY */
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":5},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());

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
 * Main test runner
 */
int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Max Helpers Budget Enforcement Tests\n");
    printf("==============================================\n\n");

    printf("Loading and max_helpers configuration tests:\n");
    RUN_TEST(load_program_with_max_helpers);

    printf("\nHelper budget enforcement tests:\n");
    RUN_TEST(few_helper_calls_complete);
    RUN_TEST(many_helper_calls_aborted);
    RUN_TEST(helper_count_includes_all_types);

    printf("\nSafe default return value tests:\n");
    RUN_TEST(safe_default_on_net_rx_helper_exceeded);
    RUN_TEST(safe_default_on_security_helper_exceeded);

    printf("\nHelper budget reset and default behavior tests:\n");
    RUN_TEST(helper_budget_resets_between_runs);
    RUN_TEST(zero_max_helpers_uses_default);

    printf("\n==============================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
