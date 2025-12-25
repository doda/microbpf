/*
 * microBPF Failure Isolation Tests
 *
 * Tests for the failure-isolation security task:
 * 1. Run program that throws exceptions repeatedly
 * 2. Verify kernel/runtime remains stable
 * 3. Verify other programs continue to execute
 * 4. Verify shared state (maps) is not corrupted
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
    const char *js_file = "/tmp/test_failure_isolation.js";
    const char *bc_file = "/tmp/test_failure_isolation.qjbc";

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

/* Helper to build manifest with specific hook type and optional array map */
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type, int include_map) {
    char json[1024];
    if (include_map) {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"failure_test\","
            "\"program_version\":\"1.0.0\","
            "\"hook_type\":%d,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":64,\"endianness\":0},"
            "\"mbpf_api_version\":1,"
            "\"heap_size\":65536,"
            "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
            "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
            "\"maps\":[{\"name\":\"shared\",\"type\":1,\"key_size\":4,\"value_size\":4,\"max_entries\":10,\"flags\":0}]"
            "}",
            hook_type);
    } else {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"failure_test\","
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
    }
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type, int include_map) {
    if (cap < 256) return 0;

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest), hook_type, include_map);
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
 * Test 1: Repeated exceptions don't crash the runtime
 * ============================================================================ */

TEST(repeated_exceptions_no_crash) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional failure');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_NET_RX, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run 100 times with repeated exceptions */
    for (int i = 0; i < 100; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_NET_PASS);
    }

    /* Verify stats show 100 exceptions */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 100);
    ASSERT_EQ(stats.exceptions, 100);
    ASSERT_EQ(stats.successes, 0);

    /* Runtime is still functional - can shutdown cleanly */
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 2: Different exception types all handled safely
 * ============================================================================ */

TEST(various_exception_types_stable) {
    const char *exception_codes[] = {
        /* Explicit throw */
        "function mbpf_prog(ctx) { throw new Error('error'); }",
        /* Type error */
        "function mbpf_prog(ctx) { null.foo(); }",
        /* Reference error */
        "function mbpf_prog(ctx) { return undefined_var.bar; }",
        /* Range error */
        "function mbpf_prog(ctx) { var a = new Array(-1); return 0; }",
        /* Syntax-like runtime error */
        "function mbpf_prog(ctx) { return ({}).toString.call(null); }",
    };
    int num_codes = sizeof(exception_codes) / sizeof(exception_codes[0]);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    for (int i = 0; i < num_codes; i++) {
        size_t bc_len;
        uint8_t *bytecode = compile_js_to_bytecode(exception_codes[i], &bc_len);
        ASSERT_NOT_NULL(bytecode);

        uint8_t pkg[8192];
        size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                             MBPF_HOOK_NET_RX, 0);
        ASSERT(pkg_len > 0);

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
        ASSERT_EQ(err, MBPF_OK);

        err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
        ASSERT_EQ(err, MBPF_OK);

        /* Run 10 times */
        for (int j = 0; j < 10; j++) {
            int32_t out_rc = -1;
            err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
            ASSERT_EQ(err, MBPF_OK);
            ASSERT_EQ(out_rc, MBPF_NET_PASS);
        }

        mbpf_program_detach(rt, prog, MBPF_HOOK_NET_RX);
        mbpf_program_unload(rt, prog);
        free(bytecode);
    }

    /* Runtime still functional after various exceptions */
    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * Test 3: Failing program doesn't affect other programs
 * ============================================================================ */

TEST(failing_program_doesnt_affect_others) {
    /* First program always throws */
    const char *failing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('always fail');\n"
        "}\n";

    /* Second program always succeeds and returns 42 */
    const char *good_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    size_t fail_bc_len, good_bc_len;
    uint8_t *fail_bytecode = compile_js_to_bytecode(failing_code, &fail_bc_len);
    uint8_t *good_bytecode = compile_js_to_bytecode(good_code, &good_bc_len);
    ASSERT_NOT_NULL(fail_bytecode);
    ASSERT_NOT_NULL(good_bytecode);

    uint8_t fail_pkg[8192], good_pkg[8192];
    size_t fail_pkg_len = build_mbpf_package(fail_pkg, sizeof(fail_pkg),
                                              fail_bytecode, fail_bc_len,
                                              MBPF_HOOK_TRACEPOINT, 0);
    size_t good_pkg_len = build_mbpf_package(good_pkg, sizeof(good_pkg),
                                              good_bytecode, good_bc_len,
                                              MBPF_HOOK_TIMER, 0);
    ASSERT(fail_pkg_len > 0);
    ASSERT(good_pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *fail_prog = NULL, *good_prog = NULL;
    int err = mbpf_program_load(rt, fail_pkg, fail_pkg_len, NULL, &fail_prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, good_pkg, good_pkg_len, NULL, &good_prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, fail_prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, good_prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    /* Interleave executions - failing and good */
    for (int i = 0; i < 50; i++) {
        /* Run failing program */
        int32_t out_rc = -1;
        mbpf_ctx_tracepoint_v1_t tp_ctx = { .abi_version = 1 };
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &tp_ctx, sizeof(tp_ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, 0);  /* TRACEPOINT default on exception */

        /* Run good program - should still work fine */
        out_rc = -1;
        mbpf_ctx_timer_v1_t timer_ctx = { .abi_version = 1 };
        err = mbpf_run(rt, MBPF_HOOK_TIMER, &timer_ctx, sizeof(timer_ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, 42);
    }

    /* Verify stats for both programs */
    mbpf_stats_t fail_stats, good_stats;
    mbpf_program_stats(fail_prog, &fail_stats);
    mbpf_program_stats(good_prog, &good_stats);

    ASSERT_EQ(fail_stats.invocations, 50);
    ASSERT_EQ(fail_stats.exceptions, 50);
    ASSERT_EQ(good_stats.invocations, 50);
    ASSERT_EQ(good_stats.successes, 50);
    ASSERT_EQ(good_stats.exceptions, 0);

    mbpf_runtime_shutdown(rt);
    free(fail_bytecode);
    free(good_bytecode);
    return 0;
}

/* ============================================================================
 * Test 4: Exception doesn't corrupt shared map state
 * ============================================================================ */

TEST(exception_doesnt_corrupt_map) {
    /* Program that initializes map, writes during exception path, verifies after */
    const char *write_and_verify =
        "var initialized = false;\n"
        "var verifyMode = false;\n"
        "var callCount = 0;\n"
        "function mbpf_init() {\n"
        "    /* Initialize map with known pattern */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var buf = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "        maps.shared.update(i, buf);\n"
        "    }\n"
        "    initialized = true;\n"
        "}\n"
        "function mbpf_prog(ctx) {\n"
        "    callCount++;\n"
        "    if (!initialized) return -100;\n"
        "    \n"
        "    /* On calls 1-10, write to slot 0 then throw */\n"
        "    if (callCount <= 10) {\n"
        "        var buf = new Uint8Array([callCount, 0x22, 0x33, 0x44]);\n"
        "        maps.shared.update(0, buf);\n"
        "        throw new Error('intentional failure');\n"
        "    }\n"
        "    \n"
        "    /* On call 11, verify map state */\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    /* Slot 0 should have value from last successful write (10) */\n"
        "    if (!maps.shared.lookup(0, outBuf)) return -1;\n"
        "    if (outBuf[0] !== 10) return -2;\n"
        "    if (outBuf[1] !== 0x22) return -3;\n"
        "    /* Slots 1-4 should still have original pattern */\n"
        "    for (var i = 1; i < 5; i++) {\n"
        "        if (!maps.shared.lookup(i, outBuf)) return -10 - i;\n"
        "        if (outBuf[0] !== 0xAA) return -20 - i;\n"
        "        if (outBuf[1] !== 0xBB) return -30 - i;\n"
        "    }\n"
        "    return 0;  /* All verified */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(write_and_verify, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run 10 times - each writes to map then throws */
    for (int i = 0; i < 10; i++) {
        int32_t out_rc = -1;
        mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        /* Exception returns default (0 for TRACEPOINT) */
        ASSERT_EQ(out_rc, 0);
    }

    /* Run 11th time - verify map state */
    int32_t out_rc = -999;
    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* Map data is intact */

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 11);
    ASSERT_EQ(stats.exceptions, 10);
    ASSERT_EQ(stats.successes, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 5: Runtime init/shutdown cycles remain stable after failures
 * ============================================================================ */

TEST(runtime_stable_across_cycles) {
    const char *failing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('boom');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(failing_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_NET_RX, 0);
    ASSERT(pkg_len > 0);

    /* Run multiple init/shutdown cycles with failures */
    for (int cycle = 0; cycle < 5; cycle++) {
        mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
        ASSERT_NOT_NULL(rt);

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
        ASSERT_EQ(err, MBPF_OK);

        err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
        ASSERT_EQ(err, MBPF_OK);

        /* Trigger failures */
        for (int i = 0; i < 20; i++) {
            int32_t out_rc = -1;
            err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
            ASSERT_EQ(err, MBPF_OK);
        }

        mbpf_runtime_shutdown(rt);
    }

    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 6: Multiple failing programs don't interfere with each other
 * ============================================================================ */

TEST(multiple_failing_programs_isolated) {
    const char *fail1 =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('fail1');\n"
        "}\n";
    const char *fail2 =
        "function mbpf_prog(ctx) {\n"
        "    throw new TypeError('fail2');\n"
        "}\n";
    const char *fail3 =
        "function mbpf_prog(ctx) {\n"
        "    return undefined_var.foo;\n"
        "}\n";

    size_t bc1_len, bc2_len, bc3_len;
    uint8_t *bc1 = compile_js_to_bytecode(fail1, &bc1_len);
    uint8_t *bc2 = compile_js_to_bytecode(fail2, &bc2_len);
    uint8_t *bc3 = compile_js_to_bytecode(fail3, &bc3_len);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);
    ASSERT_NOT_NULL(bc3);

    uint8_t pkg1[8192], pkg2[8192], pkg3[8192];
    size_t pkg1_len = build_mbpf_package(pkg1, sizeof(pkg1), bc1, bc1_len,
                                          MBPF_HOOK_NET_RX, 0);
    size_t pkg2_len = build_mbpf_package(pkg2, sizeof(pkg2), bc2, bc2_len,
                                          MBPF_HOOK_NET_TX, 0);
    size_t pkg3_len = build_mbpf_package(pkg3, sizeof(pkg3), bc3, bc3_len,
                                          MBPF_HOOK_TRACEPOINT, 0);
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);
    ASSERT(pkg3_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog1 = NULL, *prog2 = NULL, *prog3 = NULL;
    int err;

    err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog1);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, pkg2, pkg2_len, NULL, &prog2);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, pkg3, pkg3_len, NULL, &prog3);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog1, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog2, MBPF_HOOK_NET_TX);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog3, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run all three failing programs many times */
    for (int i = 0; i < 30; i++) {
        int32_t out_rc;

        out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_NET_PASS);

        out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_TX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_NET_PASS);

        out_rc = -1;
        mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, 0);
    }

    /* Each program should have its own isolated stats */
    mbpf_stats_t s1, s2, s3;
    mbpf_program_stats(prog1, &s1);
    mbpf_program_stats(prog2, &s2);
    mbpf_program_stats(prog3, &s3);

    ASSERT_EQ(s1.invocations, 30);
    ASSERT_EQ(s1.exceptions, 30);
    ASSERT_EQ(s2.invocations, 30);
    ASSERT_EQ(s2.exceptions, 30);
    ASSERT_EQ(s3.invocations, 30);
    ASSERT_EQ(s3.exceptions, 30);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    free(bc3);
    return 0;
}

/* ============================================================================
 * Test 7: Stress test with high volume of exceptions
 * ============================================================================ */

TEST(high_volume_exceptions_stable) {
    const char *failing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('stress test');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(failing_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_NET_RX, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run 1000 times with exceptions */
    for (int i = 0; i < 1000; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_NET_PASS);
    }

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1000);
    ASSERT_EQ(stats.exceptions, 1000);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 8: Interleaved success and failure is stable
 * ============================================================================ */

TEST(interleaved_success_failure) {
    /* Program that fails on odd calls, succeeds on even */
    const char *interleaved_code =
        "var call_count = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    call_count++;\n"
        "    if (call_count % 2 === 1) {\n"
        "        throw new Error('odd call');\n"
        "    }\n"
        "    return call_count;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(interleaved_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run 100 times */
    for (int i = 0; i < 100; i++) {
        int32_t out_rc = -999;
        mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);

        if ((i + 1) % 2 == 1) {
            /* Odd call - exception, default return */
            ASSERT_EQ(out_rc, 0);
        } else {
            /* Even call - success, returns call_count */
            ASSERT_EQ(out_rc, i + 1);
        }
    }

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 100);
    ASSERT_EQ(stats.exceptions, 50);
    ASSERT_EQ(stats.successes, 50);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 9: Exception after map operations doesn't leak resources
 * ============================================================================ */

TEST(exception_after_map_ops_no_leak) {
    const char *map_then_throw =
        "function mbpf_prog(ctx) {\n"
        "    /* Perform many map operations */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var buf = new Uint8Array([i, i+1, i+2, i+3]);\n"
        "        maps.shared.update(i, buf);\n"
        "        var out = new Uint8Array(4);\n"
        "        maps.shared.lookup(i, out);\n"
        "    }\n"
        "    throw new Error('after map ops');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(map_then_throw, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run many times - should not leak memory */
    for (int i = 0; i < 200; i++) {
        int32_t out_rc = -1;
        mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 200);
    ASSERT_EQ(stats.exceptions, 200);

    /* Clean shutdown without crashes */
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 10: Security hook failures return safe default (DENY)
 * ============================================================================ */

TEST(security_hook_failure_returns_deny) {
    const char *security_fail =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('security failure');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(security_fail, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_SECURITY, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    /* Run many times - should always return DENY for security fail-safe */
    for (int i = 0; i < 50; i++) {
        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_SECURITY, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_SEC_DENY);
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Failure Isolation Tests\n");
    printf("================================\n\n");

    printf("Repeated exception stability:\n");
    RUN_TEST(repeated_exceptions_no_crash);
    RUN_TEST(various_exception_types_stable);

    printf("\nProgram isolation:\n");
    RUN_TEST(failing_program_doesnt_affect_others);
    RUN_TEST(multiple_failing_programs_isolated);

    printf("\nMap state integrity:\n");
    RUN_TEST(exception_doesnt_corrupt_map);
    RUN_TEST(exception_after_map_ops_no_leak);

    printf("\nRuntime stability:\n");
    RUN_TEST(runtime_stable_across_cycles);
    RUN_TEST(high_volume_exceptions_stable);
    RUN_TEST(interleaved_success_failure);

    printf("\nSecurity hook fail-safe:\n");
    RUN_TEST(security_hook_failure_returns_deny);

    printf("\n================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
