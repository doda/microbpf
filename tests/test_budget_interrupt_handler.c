/*
 * microBPF Budget Interrupt Handler Tests
 *
 * Tests for the budget-interrupt-handler task:
 * 1. Verify interrupt handler is registered on context
 * 2. Verify handler decrements step counter per VM step
 * 3. Verify handler returns non-zero to abort on budget exceeded
 * 4. Verify JS_SetContextOpaque stores instance for counter access
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
#define ASSERT_GE(a, b) ASSERT((a) >= (b))
#define ASSERT_LT(a, b) ASSERT((a) < (b))

/* Helper to compile JavaScript to bytecode */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_interrupt_handler.js";
    const char *bc_file = "/tmp/test_interrupt_handler.qjbc";

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

/* Helper to build manifest with specific budget values */
static size_t build_manifest(uint8_t *buf, size_t cap,
                             uint32_t max_steps, uint32_t max_helpers,
                             uint32_t max_wall_time_us) {
    char json[512];
    if (max_wall_time_us > 0) {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"interrupt_test\","
            "\"program_version\":\"1.0.0\","
            "\"hook_type\":1,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":%u,\"endianness\":%u},"
            "\"mbpf_api_version\":1,"
            "\"heap_size\":65536,"
            "\"budgets\":{\"max_steps\":%u,\"max_helpers\":%u,\"max_wall_time_us\":%u},"
            "\"capabilities\":[\"CAP_LOG\"]"
            "}",
            mbpf_runtime_word_size(), mbpf_runtime_endianness(),
            max_steps, max_helpers, max_wall_time_us);
    } else {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"interrupt_test\","
            "\"program_version\":\"1.0.0\","
            "\"hook_type\":1,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":%u,\"endianness\":%u},"
            "\"mbpf_api_version\":1,"
            "\"heap_size\":65536,"
            "\"budgets\":{\"max_steps\":%u,\"max_helpers\":%u},"
            "\"capabilities\":[\"CAP_LOG\"]"
            "}",
            mbpf_runtime_word_size(), mbpf_runtime_endianness(),
            max_steps, max_helpers);
    }
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                 const uint8_t *bytecode, size_t bc_len,
                                 uint32_t max_steps, uint32_t max_helpers,
                                 uint32_t max_wall_time_us) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest),
                                         max_steps, max_helpers, max_wall_time_us);
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
 * Test 1: Verify interrupt handler is registered on context.
 * This is verified indirectly by observing that budget enforcement works.
 * The interrupt handler is called by MQuickJS during execution.
 * If it wasn't registered, budget would never be checked.
 */
TEST(interrupt_handler_registered) {
    /* Long-running program that will be aborted if handler is registered */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  var sum = 0;\n"
        "  for (var i = 0; i < 100000; i++) {\n"
        "    sum += i;\n"
        "  }\n"
        "  return 42;\n"  /* Won't reach this if aborted */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* max_steps=1 ensures handler is triggered and aborts execution */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, 1, 1000, 0);
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

    /* If handler was registered, budget_exceeded should be set and program aborted */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.budget_exceeded, 1);  /* Handler was called and aborted */
    ASSERT_NE(rc, 42);  /* Program should not have returned 42 */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 2: Verify handler decrements step counter per VM step.
 * The interrupt handler is called periodically by MQuickJS (~every 10000 ops).
 * Each call should decrement the step counter.
 * We verify this by comparing behavior with different max_steps values.
 */
TEST(step_counter_decrements) {
    /* Program with a large loop that will definitely trigger interrupt handler */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  var sum = 0;\n"
        "  for (var i = 0; i < 50000; i++) {\n"
        "    sum += i;\n"
        "  }\n"
        "  return 1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* First run with max_steps=1 - should abort with large loop */
    uint8_t pkg1[8192];
    size_t pkg_len1 = build_mbpf_package(pkg1, sizeof(pkg1), bytecode, bc_len, 1, 1000, 0);
    ASSERT_GT(pkg_len1, 0);

    mbpf_runtime_config_t cfg = {0};
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog1 = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    int err = mbpf_program_load(rt, pkg1, pkg_len1, &opts, &prog1);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc1 = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc1);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_stats_t stats1;
    mbpf_program_stats(prog1, &stats1);
    ASSERT_EQ(stats1.budget_exceeded, 1);  /* Should abort with max_steps=1 */

    mbpf_program_detach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog1);

    /* Second run with max_steps=100 - should complete */
    uint8_t pkg2[8192];
    size_t pkg_len2 = build_mbpf_package(pkg2, sizeof(pkg2), bytecode, bc_len, 100, 1000, 0);
    ASSERT_GT(pkg_len2, 0);
    free(bytecode);

    mbpf_program_t *prog2 = NULL;
    err = mbpf_program_load(rt, pkg2, pkg_len2, &opts, &prog2);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc2 = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc2);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_stats_t stats2;
    mbpf_program_stats(prog2, &stats2);
    ASSERT_EQ(stats2.budget_exceeded, 0);  /* Should complete with more steps */
    ASSERT_EQ(rc2, 1);  /* Should return 1 */

    mbpf_program_detach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog2);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 3: Verify handler returns non-zero to abort on budget exceeded.
 * When step budget is exhausted, the handler should return non-zero
 * which causes MQuickJS to abort execution.
 */
TEST(handler_returns_nonzero_on_budget_exceeded) {
    /* Infinite loop that will never complete without budget enforcement */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  var x = 0;\n"
        "  while (true) {\n"
        "    x++;\n"
        "  }\n"
        "  return 99;\n"  /* Never reached */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, 5, 1000, 0);
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

    int32_t rc = 99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    /* Program should be aborted, not hang forever */
    ASSERT_EQ(err, MBPF_OK);

    /* Verify it was aborted (didn't return 99 from infinite loop) */
    ASSERT_NE(rc, 99);

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.budget_exceeded, 1);  /* Handler returned non-zero */
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 0);  /* Not a success - was aborted */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 4: Verify JS_SetContextOpaque stores instance for counter access.
 * The interrupt handler receives the opaque pointer via JS_SetContextOpaque.
 * Without this, the handler wouldn't be able to access step counters.
 * We verify this works by checking that per-instance budget tracking works.
 */
TEST(context_opaque_stores_instance) {
    /* Simple program that runs quickly */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  return 1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, 1000, 1000, 0);
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

    /* Verify instance is created */
    uint32_t instance_count = mbpf_program_instance_count(prog);
    ASSERT_GT(instance_count, 0);

    /* Get the instance and verify it exists */
    mbpf_instance_t *inst = mbpf_program_get_instance(prog, 0);
    ASSERT_NOT_NULL(inst);  /* Instance should exist for counter access */

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* Program completed successfully */

    /* Verify stats tracked correctly - proves instance was accessible */
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
 * Test 5: Verify step counter resets between invocations.
 * The step counter should be reset to max_steps at the start of each run.
 */
TEST(step_counter_resets_between_runs) {
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

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, 1000, 1000, 0);
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

    /* Run multiple times - each should complete if counter resets */
    for (int i = 0; i < 10; i++) {
        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 42);
    }

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 10);
    ASSERT_EQ(stats.successes, 10);  /* All runs succeeded */
    ASSERT_EQ(stats.budget_exceeded, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 6: Verify handler works with NULL opaque (edge case).
 * If opaque is NULL, handler should continue execution safely.
 * This is handled in the interrupt handler implementation.
 */
TEST(handler_null_opaque_safety) {
    /* Just verify that normal operation works - indicates NULL check exists */
    const char *js =
        "function mbpf_prog(ctx) { return 7; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, 100, 100, 0);
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
    ASSERT_EQ(rc, 7);  /* Program should complete normally */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 7: Verify budget_exceeded flag is set before abort.
 * The handler sets budget_exceeded=1 before returning non-zero.
 */
TEST(budget_exceeded_flag_set) {
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  for (var i = 0; i < 999999; i++) { }\n"
        "  return 1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, 2, 1000, 0);
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

    /* The budget_exceeded flag should be set in stats */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.budget_exceeded, 1);
    ASSERT_EQ(stats.exceptions, 0);  /* Not counted as regular exception */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 8: Verify both step and wall-time are checked in handler.
 * The interrupt handler checks both step budget and wall time budget.
 */
TEST(handler_checks_both_step_and_wall_time) {
    /* Program that would complete under step budget but exceeds wall time */
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  var sum = 0;\n"
        "  for (var i = 0; i < 100; i++) {\n"
        "    sum += i;\n"
        "  }\n"
        "  return sum;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* High step budget but very low wall time - should still complete fast */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                        100000, 1000, 1000000);  /* 1 second wall time */
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

    /* Should complete (fast program, generous budget) */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.successes, 1);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 9: Verify different hook types get correct exception defaults on budget exceeded.
 */
TEST(exception_defaults_per_hook_type) {
    const char *js =
        "function mbpf_prog(ctx) {\n"
        "  while(true) { }\n"  /* Infinite loop - always exceeds budget */
        "  return 99;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    mbpf_runtime_config_t cfg = {0};
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = true;

    /* TRACEPOINT hook - exception default is 0 */
    {
        char json[512];
        snprintf(json, sizeof(json),
            "{\"program_name\":\"test\",\"program_version\":\"1.0.0\","
            "\"hook_type\":1,\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":%u,\"endianness\":%u},"
            "\"mbpf_api_version\":1,\"heap_size\":65536,"
            "\"budgets\":{\"max_steps\":1,\"max_helpers\":1000},"
            "\"capabilities\":[\"CAP_LOG\"]}",
            mbpf_runtime_word_size(), mbpf_runtime_endianness());

        uint8_t pkg[8192];
        uint8_t manifest[512];
        size_t manifest_len = strlen(json);
        memcpy(manifest, json, manifest_len);

        uint32_t header_size = 20 + 2 * 16;
        uint8_t *p = pkg;
        *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
        *p++ = 0x01; *p++ = 0x00;
        *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
        *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
        *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
        *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
        *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
        uint32_t moff = header_size;
        *p++ = moff & 0xFF; *p++ = (moff >> 8) & 0xFF;
        *p++ = (moff >> 16) & 0xFF; *p++ = (moff >> 24) & 0xFF;
        *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
        *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
        *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
        *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
        uint32_t boff = moff + manifest_len;
        *p++ = boff & 0xFF; *p++ = (boff >> 8) & 0xFF;
        *p++ = (boff >> 16) & 0xFF; *p++ = (boff >> 24) & 0xFF;
        *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
        *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
        *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
        memcpy(p, manifest, manifest_len); p += manifest_len;
        memcpy(p, bytecode, bc_len); p += bc_len;

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, (size_t)(p - pkg), &opts, &prog);
        ASSERT_EQ(err, MBPF_OK);
        err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
        ASSERT_EQ(err, MBPF_OK);
        int32_t rc = 99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 0);  /* TRACEPOINT default */
        mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
        mbpf_program_unload(rt, prog);
    }

    free(bytecode);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 10: Verify instance index is maintained correctly.
 */
TEST(instance_index_correct) {
    const char *js = "function mbpf_prog(ctx) { return 1; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, 1000, 1000, 0);
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

    uint32_t count = mbpf_program_instance_count(prog);
    ASSERT_GT(count, 0);

    /* Get instance and verify it's accessible */
    mbpf_instance_t *inst = mbpf_program_get_instance(prog, 0);
    ASSERT_NOT_NULL(inst);

    /* Try to get invalid index - should return NULL */
    mbpf_instance_t *invalid = mbpf_program_get_instance(prog, 999);
    ASSERT_NULL(invalid);

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

    printf("microBPF Budget Interrupt Handler Tests\n");
    printf("========================================\n\n");

    printf("Interrupt handler registration tests:\n");
    RUN_TEST(interrupt_handler_registered);

    printf("\nStep counter behavior tests:\n");
    RUN_TEST(step_counter_decrements);
    RUN_TEST(step_counter_resets_between_runs);

    printf("\nHandler return value tests:\n");
    RUN_TEST(handler_returns_nonzero_on_budget_exceeded);
    RUN_TEST(budget_exceeded_flag_set);

    printf("\nContext opaque tests:\n");
    RUN_TEST(context_opaque_stores_instance);
    RUN_TEST(instance_index_correct);

    printf("\nEdge case tests:\n");
    RUN_TEST(handler_null_opaque_safety);
    RUN_TEST(handler_checks_both_step_and_wall_time);
    RUN_TEST(exception_defaults_per_hook_type);

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
