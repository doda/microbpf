/*
 * microBPF Trace Logging Tests
 *
 * Tests for the observability-trace-logs task:
 * 1. Enable trace logging in runtime config
 * 2. Run programs and verify trace output
 * 3. Trigger many events and verify rate limiting kicks in
 * 4. Verify rate limit is configurable
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

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
#define ASSERT_GT(a, b) ASSERT((a) > (b))
#define ASSERT_GE(a, b) ASSERT((a) >= (b))
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Captured log messages for verification */
static char captured_logs[64][512];
static int log_count = 0;

static void capture_log_fn(int level, const char *msg) {
    (void)level;
    if (log_count < 64) {
        strncpy(captured_logs[log_count], msg, sizeof(captured_logs[0]) - 1);
        captured_logs[log_count][sizeof(captured_logs[0]) - 1] = '\0';
        log_count++;
    }
}

static void reset_captured_logs(void) {
    log_count = 0;
    memset(captured_logs, 0, sizeof(captured_logs));
}

/* Check if any log contains the given substring */
static bool log_contains(const char *substring) {
    for (int i = 0; i < log_count; i++) {
        if (strstr(captured_logs[i], substring) != NULL) {
            return true;
        }
    }
    return false;
}

/* Count logs containing a substring */
static int count_logs_containing(const char *substring) {
    int count = 0;
    for (int i = 0; i < log_count; i++) {
        if (strstr(captured_logs[i], substring) != NULL) {
            count++;
        }
    }
    return count;
}

/* Helper to compile JavaScript to bytecode */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_trace.js";
    const char *bc_file = "/tmp/test_trace.qjbc";

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
static size_t build_manifest(uint8_t *buf, size_t cap) {
    char json[512];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"trace_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(),
        mbpf_runtime_endianness());
    if (len < 0 || (size_t)len > cap) return 0;
    memcpy(buf, json, len);
    return (size_t)len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len) {
    if (cap < 256) return 0;

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest));
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
 * Test 1: Trace logging disabled by default
 * ============================================================================ */
TEST(trace_disabled_by_default) {
    reset_captured_logs();

    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package), bytecode, bc_len);
    ASSERT_GT(pkg_len, 0);

    /* Create runtime without trace logging */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 65536;
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.log_fn = capture_log_fn;
    cfg.trace_enabled = false;  /* Trace disabled */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);

    /* No trace logs should be captured when trace_enabled is false */
    ASSERT(!log_contains("[TRACE]"));

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 2: Trace logging enabled produces output
 * ============================================================================ */
TEST(trace_enabled_produces_output) {
    reset_captured_logs();

    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package), bytecode, bc_len);
    ASSERT_GT(pkg_len, 0);

    /* Create runtime with trace logging enabled */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 65536;
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.log_fn = capture_log_fn;
    cfg.trace_enabled = true;
    cfg.trace_rate_limit_per_sec = 0;  /* Unlimited */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify program_load trace log */
    ASSERT(log_contains("[TRACE]"));
    ASSERT(log_contains("program_load"));
    ASSERT(log_contains("trace_test"));

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify program_attach trace log */
    ASSERT(log_contains("program_attach"));

    int32_t rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 42);

    /* Verify run trace logs */
    ASSERT(log_contains("run_on_instance"));
    ASSERT(log_contains("success"));

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Verify program_detach trace log */
    ASSERT(log_contains("program_detach"));

    mbpf_program_unload(rt, prog);

    /* Verify program_unload trace log */
    ASSERT(log_contains("program_unload"));

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 3: Trace logging shows exception events
 * ============================================================================ */
TEST(trace_shows_exception) {
    reset_captured_logs();

    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('test exception');\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package), bytecode, bc_len);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 65536;
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.log_fn = capture_log_fn;
    cfg.trace_enabled = true;
    cfg.trace_rate_limit_per_sec = 0;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify exception trace log */
    ASSERT(log_contains("exception"));

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 4: Rate limiting restricts trace output
 * ============================================================================ */
TEST(rate_limiting_restricts_output) {
    reset_captured_logs();

    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package), bytecode, bc_len);
    ASSERT_GT(pkg_len, 0);

    /* Create runtime with trace logging and low rate limit */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 65536;
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.log_fn = capture_log_fn;
    cfg.trace_enabled = true;
    cfg.trace_rate_limit_per_sec = 5;  /* Only 5 messages per second */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Reset logs to count only run traces */
    reset_captured_logs();

    /* Run many times - should be rate limited */
    for (int i = 0; i < 20; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* With rate limit of 5/sec, we should have <= 10 trace logs
     * (5 for "run_on_instance" + 5 for "success")
     * But since all runs happen in same second, we get exactly 5 total */
    int trace_count = count_logs_containing("[TRACE]");

    /* Should be rate limited - not 40 logs (2 per run * 20 runs) */
    ASSERT(trace_count <= 10);
    ASSERT(trace_count >= 1);  /* At least some logs should appear */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 5: Configurable rate limit - higher limit
 * ============================================================================ */
TEST(configurable_rate_limit_high) {
    reset_captured_logs();

    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package), bytecode, bc_len);
    ASSERT_GT(pkg_len, 0);

    /* Create runtime with high rate limit */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 65536;
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.log_fn = capture_log_fn;
    cfg.trace_enabled = true;
    cfg.trace_rate_limit_per_sec = 100;  /* 100 messages per second */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Reset logs to count only run traces */
    reset_captured_logs();

    /* Run 10 times */
    for (int i = 0; i < 10; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* With rate limit of 100/sec, all 20 logs should appear (2 per run) */
    int trace_count = count_logs_containing("[TRACE]");
    ASSERT_EQ(trace_count, 20);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 6: Unlimited rate (rate_limit = 0)
 * ============================================================================ */
TEST(unlimited_rate_when_zero) {
    reset_captured_logs();

    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package), bytecode, bc_len);
    ASSERT_GT(pkg_len, 0);

    /* Create runtime with no rate limit (0 = unlimited) */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 65536;
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.log_fn = capture_log_fn;
    cfg.trace_enabled = true;
    cfg.trace_rate_limit_per_sec = 0;  /* Unlimited */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Reset logs to count only run traces */
    reset_captured_logs();

    /* Run 15 times */
    for (int i = 0; i < 15; i++) {
        int32_t rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* With unlimited rate, all 30 logs should appear (2 per run) */
    int trace_count = count_logs_containing("[TRACE]");
    ASSERT_EQ(trace_count, 30);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test 7: Multiple programs have separate trace logs
 * ============================================================================ */
TEST(multiple_programs_traced) {
    reset_captured_logs();

    const char *js_code1 =
        "function mbpf_prog(ctx) {\n"
        "    return 1;\n"
        "}\n";

    const char *js_code2 =
        "function mbpf_prog(ctx) {\n"
        "    return 2;\n"
        "}\n";

    size_t bc_len1 = 0, bc_len2 = 0;
    uint8_t *bytecode1 = compile_js_to_bytecode(js_code1, &bc_len1);
    uint8_t *bytecode2 = compile_js_to_bytecode(js_code2, &bc_len2);
    ASSERT_NOT_NULL(bytecode1);
    ASSERT_NOT_NULL(bytecode2);

    uint8_t package1[8192], package2[8192];
    size_t pkg_len1 = build_mbpf_package(package1, sizeof(package1), bytecode1, bc_len1);
    size_t pkg_len2 = build_mbpf_package(package2, sizeof(package2), bytecode2, bc_len2);
    ASSERT_GT(pkg_len1, 0);
    ASSERT_GT(pkg_len2, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 65536;
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;
    cfg.log_fn = capture_log_fn;
    cfg.trace_enabled = true;
    cfg.trace_rate_limit_per_sec = 0;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
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
    err = mbpf_program_attach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);

    /* Both programs should have trace logs */
    int load_count = count_logs_containing("program_load");
    ASSERT_EQ(load_count, 2);

    mbpf_program_detach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    mbpf_program_detach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog1);
    mbpf_program_unload(rt, prog2);
    mbpf_runtime_shutdown(rt);
    free(bytecode1);
    free(bytecode2);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Trace Logging Tests\n");
    printf("============================\n\n");

    printf("Basic trace logging tests:\n");
    RUN_TEST(trace_disabled_by_default);
    RUN_TEST(trace_enabled_produces_output);
    RUN_TEST(trace_shows_exception);

    printf("\nRate limiting tests:\n");
    RUN_TEST(rate_limiting_restricts_output);
    RUN_TEST(configurable_rate_limit_high);
    RUN_TEST(unlimited_rate_when_zero);

    printf("\nMultiple program tests:\n");
    RUN_TEST(multiple_programs_traced);

    printf("\n============================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
