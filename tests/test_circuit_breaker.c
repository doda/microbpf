/*
 * microBPF Circuit Breaker Tests
 *
 * Tests for the circuit-breaker security task:
 * 1. Configure circuit breaker threshold (e.g., 10 failures)
 * 2. Trigger 10 failures on same program
 * 3. Verify program is temporarily disabled
 * 4. Verify program re-enables after cooldown period
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

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
#define ASSERT_TRUE(x) ASSERT((x) != 0)
#define ASSERT_FALSE(x) ASSERT((x) == 0)

/* Helper to compile JavaScript to bytecode */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_circuit_breaker.js";
    const char *bc_file = "/tmp/test_circuit_breaker.qjbc";

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
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"circuit_test\","
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
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type) {
    if (cap < 256) return 0;

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest), hook_type);
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
 * Test 1: Configure circuit breaker threshold
 * ============================================================================ */

TEST(configure_circuit_breaker_threshold) {
    mbpf_runtime_config_t cfg = {0};
    cfg.circuit_breaker_threshold = 10;
    cfg.circuit_breaker_cooldown_us = 1000000;  /* 1 second */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    /* Verify runtime is functional with circuit breaker configured */
    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * Test 2: Trigger threshold number of failures
 * ============================================================================ */

TEST(trigger_threshold_failures) {
    const char *failing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional failure');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(failing_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.circuit_breaker_threshold = 10;
    cfg.circuit_breaker_cooldown_us = 1000000;  /* 1 second */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Trigger exactly 10 failures */
    for (int i = 0; i < 10; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_NET_PASS);  /* Exception returns fail-safe default */
    }

    /* Verify stats show 10 exceptions */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 10);
    ASSERT_EQ(stats.exceptions, 10);
    ASSERT_EQ(stats.circuit_breaker_trips, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 3: Verify program is temporarily disabled
 * ============================================================================ */

TEST(program_temporarily_disabled) {
    const char *failing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional failure');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(failing_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.circuit_breaker_threshold = 5;
    cfg.circuit_breaker_cooldown_us = 10000000;  /* 10 seconds - long enough */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Circuit should not be open initially */
    ASSERT_FALSE(mbpf_program_circuit_open(prog));

    /* Trigger 5 failures to trip the circuit breaker */
    for (int i = 0; i < 5; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Circuit should now be open */
    ASSERT_TRUE(mbpf_program_circuit_open(prog));

    /* Further invocations should be skipped */
    for (int i = 0; i < 10; i++) {
        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_NET_PASS);  /* Returns default */
    }

    /* Verify stats: 5 actual invocations, 10 skipped */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 5);
    ASSERT_EQ(stats.exceptions, 5);
    ASSERT_EQ(stats.circuit_breaker_trips, 1);
    ASSERT_EQ(stats.circuit_breaker_skipped, 10);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 4: Verify program re-enables after cooldown period
 * ============================================================================ */

TEST(program_reenables_after_cooldown) {
    const char *failing_code =
        "var fail_count = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    fail_count++;\n"
        "    if (fail_count <= 5) {\n"
        "        throw new Error('initial failures');\n"
        "    }\n"
        "    return 42;  /* succeed after cooldown */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(failing_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.circuit_breaker_threshold = 5;
    cfg.circuit_breaker_cooldown_us = 100000;  /* 100ms cooldown */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Trigger 5 failures to trip the circuit breaker */
    for (int i = 0; i < 5; i++) {
        int32_t out_rc = -1;
        mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Circuit should be open */
    ASSERT_TRUE(mbpf_program_circuit_open(prog));

    /* Invocations should be skipped */
    int32_t out_rc = -999;
    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* default for TRACEPOINT */

    /* Wait for cooldown to expire (150ms to be safe) */
    usleep(150000);

    /* Circuit should now be closed */
    ASSERT_FALSE(mbpf_program_circuit_open(prog));

    /* Program should run again and succeed (fail_count > 5 now) */
    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);  /* program now succeeds */

    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    /* 5 failures + 1 skip + 1 success = invocations should be 6 (5 + 1 after cooldown) */
    ASSERT_EQ(stats.invocations, 6);
    ASSERT_EQ(stats.exceptions, 5);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.circuit_breaker_trips, 1);
    ASSERT_EQ(stats.circuit_breaker_skipped, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 5: Success resets consecutive failure counter
 * ============================================================================ */

TEST(success_resets_failure_counter) {
    const char *alternating_code =
        "var count = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    count++;\n"
        "    if (count % 2 === 1) {\n"
        "        throw new Error('odd call fails');\n"
        "    }\n"
        "    return 0;  /* even calls succeed */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(alternating_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.circuit_breaker_threshold = 3;  /* Low threshold */
    cfg.circuit_breaker_cooldown_us = 10000000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run 20 times - alternating fail/success should never trip circuit */
    for (int i = 0; i < 20; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Circuit should NOT be open - successes reset the counter */
    ASSERT_FALSE(mbpf_program_circuit_open(prog));

    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 20);
    ASSERT_EQ(stats.exceptions, 10);  /* 10 odd calls failed */
    ASSERT_EQ(stats.successes, 10);   /* 10 even calls succeeded */
    ASSERT_EQ(stats.circuit_breaker_trips, 0);  /* Never tripped */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 6: Manual circuit reset
 * ============================================================================ */

TEST(manual_circuit_reset) {
    const char *failing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('always fail');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(failing_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.circuit_breaker_threshold = 5;
    cfg.circuit_breaker_cooldown_us = 10000000;  /* Long cooldown */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Trip the circuit */
    for (int i = 0; i < 5; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    ASSERT_TRUE(mbpf_program_circuit_open(prog));

    /* Manually reset the circuit */
    err = mbpf_program_circuit_reset(prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Circuit should be closed now */
    ASSERT_FALSE(mbpf_program_circuit_open(prog));

    /* Program should run again (but will fail again) */
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 6);  /* 5 + 1 after reset */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 7: Circuit breaker disabled when threshold is 0
 * ============================================================================ */

TEST(circuit_breaker_disabled_when_zero) {
    const char *failing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('always fail');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(failing_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    /* No circuit breaker configuration */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run 100 times - should never trip circuit */
    for (int i = 0; i < 100; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Circuit should never be open */
    ASSERT_FALSE(mbpf_program_circuit_open(prog));

    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 100);
    ASSERT_EQ(stats.exceptions, 100);
    ASSERT_EQ(stats.circuit_breaker_trips, 0);
    ASSERT_EQ(stats.circuit_breaker_skipped, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 8: Multiple programs have independent circuit breakers
 * ============================================================================ */

TEST(independent_circuit_breakers) {
    const char *failing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('fail');\n"
        "}\n";
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
                                              MBPF_HOOK_NET_RX);
    size_t good_pkg_len = build_mbpf_package(good_pkg, sizeof(good_pkg),
                                              good_bytecode, good_bc_len,
                                              MBPF_HOOK_NET_TX);
    ASSERT(fail_pkg_len > 0);
    ASSERT(good_pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.circuit_breaker_threshold = 5;
    cfg.circuit_breaker_cooldown_us = 10000000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *fail_prog = NULL, *good_prog = NULL;
    int err = mbpf_program_load(rt, fail_pkg, fail_pkg_len, NULL, &fail_prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, good_pkg, good_pkg_len, NULL, &good_prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, fail_prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, good_prog, MBPF_HOOK_NET_TX);
    ASSERT_EQ(err, MBPF_OK);

    /* Trip failing program's circuit */
    for (int i = 0; i < 5; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Failing program's circuit is open */
    ASSERT_TRUE(mbpf_program_circuit_open(fail_prog));

    /* Good program's circuit is still closed */
    ASSERT_FALSE(mbpf_program_circuit_open(good_prog));

    /* Good program still works */
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_TX, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_stats_t fail_stats, good_stats;
    mbpf_program_stats(fail_prog, &fail_stats);
    mbpf_program_stats(good_prog, &good_stats);

    ASSERT_EQ(fail_stats.circuit_breaker_trips, 1);
    ASSERT_EQ(good_stats.circuit_breaker_trips, 0);

    mbpf_runtime_shutdown(rt);
    free(fail_bytecode);
    free(good_bytecode);
    return 0;
}

/* ============================================================================
 * Test 9: Different failure types all trigger circuit breaker
 * ============================================================================ */

TEST(different_failure_types_trigger_circuit) {
    /* Use budget exceeded as failure type */
    const char *budget_exceed_code =
        "function mbpf_prog(ctx) {\n"
        "    while(true) {}  /* infinite loop - budget exceeded */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(budget_exceed_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.default_max_steps = 100;  /* Low step budget */
    cfg.circuit_breaker_threshold = 3;
    cfg.circuit_breaker_cooldown_us = 10000000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Trigger 3 budget exceeded failures */
    for (int i = 0; i < 3; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Circuit should be open */
    ASSERT_TRUE(mbpf_program_circuit_open(prog));

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.budget_exceeded, 3);
    ASSERT_EQ(stats.circuit_breaker_trips, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 10: Security hook with circuit breaker returns DENY when open
 * ============================================================================ */

TEST(security_hook_circuit_returns_deny) {
    const char *failing_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('security fail');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(failing_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_SECURITY);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.circuit_breaker_threshold = 3;
    cfg.circuit_breaker_cooldown_us = 10000000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    /* Trip the circuit */
    for (int i = 0; i < 3; i++) {
        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_SECURITY, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_SEC_DENY);  /* Exception returns DENY */
    }

    ASSERT_TRUE(mbpf_program_circuit_open(prog));

    /* Further invocations should return DENY (security fail-safe) */
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);  /* Circuit open returns DENY */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Circuit Breaker Tests\n");
    printf("==============================\n\n");

    printf("Configuration tests:\n");
    RUN_TEST(configure_circuit_breaker_threshold);

    printf("\nTripping tests:\n");
    RUN_TEST(trigger_threshold_failures);
    RUN_TEST(program_temporarily_disabled);

    printf("\nCooldown tests:\n");
    RUN_TEST(program_reenables_after_cooldown);

    printf("\nReset tests:\n");
    RUN_TEST(success_resets_failure_counter);
    RUN_TEST(manual_circuit_reset);

    printf("\nEdge cases:\n");
    RUN_TEST(circuit_breaker_disabled_when_zero);
    RUN_TEST(independent_circuit_breakers);
    RUN_TEST(different_failure_types_trigger_circuit);

    printf("\nHook-specific behavior:\n");
    RUN_TEST(security_hook_circuit_returns_deny);

    printf("\n==============================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
