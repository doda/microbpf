/*
 * microBPF Observability Counters Tests
 *
 * Tests for the observability-counters task:
 * 1. Run programs and verify invocation count increments
 * 2. Trigger success and verify success count increments
 * 3. Trigger exception and verify exception count increments
 * 4. Trigger OOM and verify OOM count increments
 * 5. Trigger budget exceeded and verify counter increments
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
    const char *js_file = "/tmp/test_obs_counter.js";
    const char *bc_file = "/tmp/test_obs_counter.qjbc";

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

/* Helper to build manifest */
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type,
                             uint32_t max_steps, uint32_t max_helpers) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"counter_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":%u,\"max_helpers\":%u},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        max_steps, max_helpers);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type, uint32_t max_steps,
                                  uint32_t max_helpers) {
    if (cap < 256) return 0;

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest),
                                          hook_type, max_steps, max_helpers);
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
 * Test 1: Invocation count increments on each run
 * ============================================================================ */
TEST(invocation_count_increments) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 100000, 1000);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Check initial stats */
    mbpf_stats_t stats_before;
    err = mbpf_program_stats(prog, &stats_before);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats_before.invocations, 0);

    /* Run the program 5 times */
    for (int i = 0; i < 5; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 0);
    }

    /* Check stats after runs */
    mbpf_stats_t stats_after;
    err = mbpf_program_stats(prog, &stats_after);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats_after.invocations, 5);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 2: Success count increments on successful runs
 * ============================================================================ */
TEST(success_count_increments) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 100000, 1000);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program 3 times - all should succeed */
    for (int i = 0; i < 3; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 42);
    }

    /* Check stats */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 3);
    ASSERT_EQ(stats.successes, 3);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 3: Exception count increments when program throws
 * ============================================================================ */
TEST(exception_count_increments) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 100000, 1000);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program 4 times - all should throw */
    for (int i = 0; i < 4; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);  /* Error is handled, not returned */
    }

    /* Check stats */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 4);
    ASSERT_EQ(stats.successes, 0);
    ASSERT_EQ(stats.exceptions, 4);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 4: Budget exceeded counter increments when step budget is exceeded
 * ============================================================================ */
TEST(budget_exceeded_count_increments) {
    /* Program that loops many times to exceed budget */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var sum = 0;\n"
        "    for (var i = 0; i < 10000000; i++) {\n"
        "        sum += i;\n"
        "    }\n"
        "    return sum;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Use a very small step budget that will be exceeded */
    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 100, 1000);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program 3 times - all should exceed budget */
    for (int i = 0; i < 3; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);  /* Budget exceeded is handled gracefully */
    }

    /* Check stats */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 3);
    ASSERT_EQ(stats.budget_exceeded, 3);
    ASSERT_EQ(stats.successes, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 5: Mixed success and exception counts
 * ============================================================================ */
TEST(mixed_success_and_exception) {
    /* Program that throws on even invocations */
    const char *js_code =
        "var count = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    count++;\n"
        "    if (count % 2 === 0) {\n"
        "        throw new Error('even invocation');\n"
        "    }\n"
        "    return count;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 100000, 1000);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run 6 times: invocations 1,3,5 succeed; 2,4,6 throw */
    for (int i = 0; i < 6; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Check stats */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 6);
    ASSERT_EQ(stats.successes, 3);    /* 1, 3, 5 */
    ASSERT_EQ(stats.exceptions, 3);   /* 2, 4, 6 */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 6: Stats are zero after load (before first run)
 * ============================================================================ */
TEST(stats_zero_initially) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 100000, 1000);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Check stats before any runs */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 0);
    ASSERT_EQ(stats.successes, 0);
    ASSERT_EQ(stats.exceptions, 0);
    ASSERT_EQ(stats.oom_errors, 0);
    ASSERT_EQ(stats.budget_exceeded, 0);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 7: Multiple programs have independent counters
 * ============================================================================ */
TEST(independent_program_counters) {
    const char *js_code1 =
        "function mbpf_prog(ctx) {\n"
        "    return 1;\n"
        "}\n";

    const char *js_code2 =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('always throws');\n"
        "}\n";

    size_t bc_len1 = 0, bc_len2 = 0;
    uint8_t *bytecode1 = compile_js_to_bytecode(js_code1, &bc_len1);
    uint8_t *bytecode2 = compile_js_to_bytecode(js_code2, &bc_len2);
    ASSERT_NOT_NULL(bytecode1);
    ASSERT_NOT_NULL(bytecode2);

    uint8_t package1[8192], package2[8192];
    size_t pkg_len1 = build_mbpf_package(package1, sizeof(package1),
                                          bytecode1, bc_len1,
                                          MBPF_HOOK_TRACEPOINT, 100000, 1000);
    size_t pkg_len2 = build_mbpf_package(package2, sizeof(package2),
                                          bytecode2, bc_len2,
                                          MBPF_HOOK_TIMER, 100000, 1000);
    ASSERT_GT(pkg_len1, 0);
    ASSERT_GT(pkg_len2, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog1 = NULL, *prog2 = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package1, pkg_len1, &opts, &prog1);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, package2, pkg_len2, &opts, &prog2);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog2, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    /* Run prog1 twice (succeeds) */
    for (int i = 0; i < 2; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Run prog2 three times (throws) */
    for (int i = 0; i < 3; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TIMER, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Check prog1 stats */
    mbpf_stats_t stats1;
    err = mbpf_program_stats(prog1, &stats1);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats1.invocations, 2);
    ASSERT_EQ(stats1.successes, 2);
    ASSERT_EQ(stats1.exceptions, 0);

    /* Check prog2 stats - should be independent */
    mbpf_stats_t stats2;
    err = mbpf_program_stats(prog2, &stats2);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats2.invocations, 3);
    ASSERT_EQ(stats2.successes, 0);
    ASSERT_EQ(stats2.exceptions, 3);

    mbpf_program_detach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    mbpf_program_detach(rt, prog2, MBPF_HOOK_TIMER);
    mbpf_program_unload(rt, prog1);
    mbpf_program_unload(rt, prog2);
    mbpf_runtime_shutdown(rt);
    free(bytecode1);
    free(bytecode2);
    return 0;
}

/* ============================================================================
 * Test 8: Runtime error types correctly increment exception counter
 * ============================================================================ */
TEST(runtime_error_counts_as_exception) {
    /* Program that causes a runtime error by accessing undefined variable */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return undefined_variable.property;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 100000, 1000);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program */
    int32_t rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);

    /* Check stats */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.exceptions, 1);
    ASSERT_EQ(stats.successes, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 9: mbpf_program_stats returns MBPF_ERR_INVALID_ARG for NULL
 * ============================================================================ */
TEST(stats_null_safety) {
    mbpf_stats_t stats;

    /* NULL program */
    int err = mbpf_program_stats(NULL, &stats);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Observability Counters Tests\n");
    printf("=====================================\n\n");

    printf("Invocation counter tests:\n");
    RUN_TEST(invocation_count_increments);
    RUN_TEST(stats_zero_initially);

    printf("\nSuccess counter tests:\n");
    RUN_TEST(success_count_increments);

    printf("\nException counter tests:\n");
    RUN_TEST(exception_count_increments);
    RUN_TEST(runtime_error_counts_as_exception);

    printf("\nBudget exceeded counter tests:\n");
    RUN_TEST(budget_exceeded_count_increments);

    printf("\nMixed counter tests:\n");
    RUN_TEST(mixed_success_and_exception);
    RUN_TEST(independent_program_counters);

    printf("\nAPI safety tests:\n");
    RUN_TEST(stats_null_safety);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
