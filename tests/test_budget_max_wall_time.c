/*
 * microBPF Max Wall Time Budget Enforcement Tests
 *
 * Tests for the budget-max-wall-time task:
 * 1. Load program with max_wall_time_us=1000 (1ms)
 * 2. Run fast program - verify completes
 * 3. Run slow program (busy loop) - verify aborted within time limit
 * 4. Verify timing overhead is acceptable
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

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
#define ASSERT_LT(a, b) ASSERT((a) < (b))

/* Helper to compile JavaScript to bytecode */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_wall_time.js";
    const char *bc_file = "/tmp/test_wall_time.qjbc";

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

/* Helper to build manifest with specific max_wall_time_us */
static size_t build_manifest_with_wall_time(uint8_t *buf, size_t cap,
                                             uint32_t max_wall_time_us,
                                             uint32_t max_steps) {
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"wall_time_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":%u,\"max_helpers\":1000,\"max_wall_time_us\":%u},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        max_steps, max_wall_time_us);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package_with_wall_time(uint8_t *buf, size_t cap,
                                                 const uint8_t *bytecode, size_t bc_len,
                                                 uint32_t max_wall_time_us,
                                                 uint32_t max_steps) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_wall_time(manifest, sizeof(manifest),
                                                         max_wall_time_us, max_steps);
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
 * Test 1: Load program with max_wall_time_us=1000
 * Verify program loads successfully
 */
TEST(load_program_with_max_wall_time) {
    /* Simple program that just returns 0 */
    const char *js = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_wall_time(pkg, sizeof(pkg), bytecode, bc_len,
                                                        1000, 0);  /* 1ms wall time, no step limit */
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
 * Test 2: Run fast program - verify completes
 * A simple return should complete well within 1ms
 */
TEST(fast_program_completes) {
    /* Simple program that returns immediately */
    const char *js = "function mbpf_prog(ctx) { return 42; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* 1ms wall time, high step limit */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_wall_time(pkg, sizeof(pkg), bytecode, bc_len,
                                                        1000, 100000);
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
 * Test 3: Run slow program (busy loop) - verify aborted within time limit
 * This is the key test: an infinite loop should be terminated by wall time budget
 */
TEST(slow_loop_aborted) {
    /* Program with a very long loop - essentially infinite in practical terms.
     * The interrupt handler checks wall time periodically, so we use a loop
     * that will definitely take more than 100us (0.1ms) to complete. */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  var sum = 0;\n"
        "  for (var i = 0; i < 1000000000; i++) {\n"
        "    sum += i;\n"
        "  }\n"
        "  return sum;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* 100us wall time (very short), no step limit (0 uses default) */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_wall_time(pkg, sizeof(pkg), bytecode, bc_len,
                                                        100, 0);
    free(bytecode);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.debug_mode = true;
    cfg.default_max_steps = 0;  /* Disable step limit to test wall time only */
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Measure actual time spent */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int32_t rc = 99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);

    clock_gettime(CLOCK_MONOTONIC, &end);

    uint64_t elapsed_us = (uint64_t)(end.tv_sec - start.tv_sec) * 1000000ULL +
                          (uint64_t)(end.tv_nsec - start.tv_nsec) / 1000ULL;

    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);  /* Should return exception default (0 for TRACEPOINT) */

    /* Check stats - budget_exceeded should be incremented */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.budget_exceeded, 1);
    ASSERT_EQ(stats.successes, 0);

    /* Verify timing overhead is acceptable: execution should have stopped
     * within a reasonable time. The interrupt handler is called periodically,
     * so there is some latency. We allow up to 100ms (which is very generous). */
    ASSERT_LT(elapsed_us, 100000);  /* Should complete in under 100ms */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 4: Verify timing overhead is acceptable
 * Fast programs should complete quickly, not be delayed by wall time checks
 */
TEST(timing_overhead_acceptable) {
    /* Very simple program */
    const char *js = "function mbpf_prog(ctx) { return 1; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Large wall time budget (10ms), high step limit */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_wall_time(pkg, sizeof(pkg), bytecode, bc_len,
                                                        10000, 100000);
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

    /* Run many times and measure total time */
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int runs = 100;
    for (int i = 0; i < runs; i++) {
        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 1);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    uint64_t elapsed_us = (uint64_t)(end.tv_sec - start.tv_sec) * 1000000ULL +
                          (uint64_t)(end.tv_nsec - start.tv_nsec) / 1000ULL;

    /* 100 runs should complete in under 100ms (1ms per run average) */
    ASSERT_LT(elapsed_us, 100000);

    mbpf_program_stats(prog, NULL);  /* Just to verify no crash */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 5: Zero max_wall_time_us means no wall time limit
 */
TEST(zero_wall_time_no_limit) {
    /* Program with moderate loop */
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

    /* 0 means no wall time limit, high step limit */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_wall_time(pkg, sizeof(pkg), bytecode, bc_len,
                                                        0, 100000);
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

    int32_t rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 42);

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
 * Test 6: Wall time budget resets between invocations
 */
TEST(wall_time_resets_between_runs) {
    /* Simple program */
    const char *js = "function mbpf_prog(ctx) { return 1; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* 5ms wall time, high step limit */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_wall_time(pkg, sizeof(pkg), bytecode, bc_len,
                                                        5000, 100000);
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

    /* Run multiple times with small delays between */
    for (int i = 0; i < 10; i++) {
        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 1);

        /* Small sleep to accumulate wall time between runs */
        struct timespec ts = {0, 1000000};  /* 1ms */
        nanosleep(&ts, NULL);
    }

    /* All should succeed - wall time resets for each run */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 10);
    ASSERT_EQ(stats.successes, 10);
    ASSERT_EQ(stats.budget_exceeded, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 7: Safe default returned on wall time exceeded (NET_RX returns PASS)
 */
TEST(safe_default_on_net_rx_wall_time_exceeded) {
    /* Long loop program */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 1000000000; i++) { }\n"
        "  return 1;\n"  /* Would return DROP if completed */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package for NET_RX hook with short wall time (100us) */
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"wall_time_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":3,"  /* NET_RX */
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":0,\"max_helpers\":1000,\"max_wall_time_us\":100},"
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
    cfg.default_max_steps = 0;  /* Disable step limit */
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
    ASSERT_EQ(rc, MBPF_NET_PASS);  /* Should return PASS (0) on wall time exceeded */

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.budget_exceeded, 1);

    mbpf_program_detach(rt, prog, MBPF_HOOK_NET_RX);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 8: SECURITY hook returns DENY on wall time exceeded
 */
TEST(safe_default_on_security_wall_time_exceeded) {
    /* Long loop program */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 1000000000; i++) { }\n"
        "  return 0;\n"  /* Would return ALLOW if completed */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build package for SECURITY hook with short wall time */
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"wall_time_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":5,"  /* SECURITY */
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":0,\"max_helpers\":1000,\"max_wall_time_us\":100},"
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
    cfg.default_max_steps = 0;  /* Disable step limit */
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
    ASSERT_EQ(rc, MBPF_SEC_DENY);  /* Should return DENY (1) on wall time exceeded */

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

    printf("microBPF Max Wall Time Budget Enforcement Tests\n");
    printf("================================================\n\n");

    printf("Loading and configuration tests:\n");
    RUN_TEST(load_program_with_max_wall_time);

    printf("\nWall time enforcement tests:\n");
    RUN_TEST(fast_program_completes);
    RUN_TEST(slow_loop_aborted);
    RUN_TEST(timing_overhead_acceptable);

    printf("\nBoundary condition tests:\n");
    RUN_TEST(zero_wall_time_no_limit);
    RUN_TEST(wall_time_resets_between_runs);

    printf("\nSafe default return value tests:\n");
    RUN_TEST(safe_default_on_net_rx_wall_time_exceeded);
    RUN_TEST(safe_default_on_security_wall_time_exceeded);

    printf("\n================================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
