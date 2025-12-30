/*
 * microBPF Helper Log Tests
 *
 * Tests for mbpf.log(level, msg) helper:
 * 1. Call mbpf.log(0, 'test message') from program
 * 2. Verify log output appears in debug mode
 * 3. Verify log is rate-limited or no-op in production mode
 * 4. Test different log levels
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

/* Log capture buffer for test verification */
static char captured_logs[8192];
static size_t captured_log_offset = 0;
static int captured_log_count = 0;
static int last_log_level = -1;
static int captured_levels[256];  /* Track levels of each log */

static void reset_log_capture(void) {
    captured_logs[0] = '\0';
    captured_log_offset = 0;
    captured_log_count = 0;
    last_log_level = -1;
    memset(captured_levels, -1, sizeof(captured_levels));
}

static void test_log_fn(int level, const char *msg) {
    last_log_level = level;
    if (captured_log_count < 256) {
        captured_levels[captured_log_count] = level;
    }
    captured_log_count++;
    size_t len = strlen(msg);
    if (captured_log_offset + len + 2 < sizeof(captured_logs)) {
        memcpy(captured_logs + captured_log_offset, msg, len);
        captured_log_offset += len;
        captured_logs[captured_log_offset++] = '\n';
        captured_logs[captured_log_offset] = '\0';
    }
}

/* Helper to build a basic manifest */
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"log_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness());
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

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest), hook_type);
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
    const char *js_file = "/tmp/test_log.js";
    const char *bc_file = "/tmp/test_log.qjbc";

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
 * Test Cases - helper-log
 * ============================================================================ */

/*
 * Test 1: Call mbpf.log(0, 'test message') from program
 *
 * Verification: mbpf.log function exists and can be called
 */
TEST(log_function_exists) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf === 'undefined') return -1;\n"
        "    if (typeof mbpf.log !== 'function') return -2;\n"
        "    mbpf.log(0, 'test message');\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 1;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);  /* Function exists and can be called */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Verify log output appears in debug mode
 *
 * Verification: When debug_mode is true, logs are captured
 */
TEST(log_output_in_debug_mode) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.log(1, 'hello from mbpf');\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 1;  /* Enable debug mode */
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    /* Verify log was captured */
    ASSERT(captured_log_count > 0);
    ASSERT(strstr(captured_logs, "hello from mbpf") != NULL);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Verify log is rate-limited in production mode
 *
 * Verification: In production mode (debug_mode=false), excessive logs are dropped
 */
TEST(log_rate_limited_in_production) {
    /* Program logs 200 times, which exceeds rate limit of 100/sec */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    for (var i = 0; i < 200; i++) {\n"
        "        mbpf.log(1, 'log ' + i);\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 0;  /* Production mode - rate limiting enabled */
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    /* Verify rate limiting: should have at most 100 logs */
    ASSERT(captured_log_count <= 100);
    /* But should have some logs */
    ASSERT(captured_log_count > 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Test different log levels - DEBUG (0)
 *
 * Verification: Level 0 logs are passed to callback with level=0
 */
TEST(log_level_debug) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.log(0, 'debug message');\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 1;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    /* Verify level 0 (DEBUG) was passed to callback */
    ASSERT_EQ(last_log_level, 0);
    ASSERT(strstr(captured_logs, "debug message") != NULL);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Test different log levels - INFO (1)
 *
 * Verification: Level 1 logs are passed to callback with level=1
 */
TEST(log_level_info) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.log(1, 'info message');\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 1;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    /* Verify level 1 (INFO) was passed to callback */
    ASSERT_EQ(last_log_level, 1);
    ASSERT(strstr(captured_logs, "info message") != NULL);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Test different log levels - WARN (2)
 *
 * Verification: Level 2 logs are passed to callback with level=2
 */
TEST(log_level_warn) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.log(2, 'warn message');\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 1;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    /* Verify level 2 (WARN) was passed to callback */
    ASSERT_EQ(last_log_level, 2);
    ASSERT(strstr(captured_logs, "warn message") != NULL);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Test different log levels - ERROR (3)
 *
 * Verification: Level 3 logs are passed to callback with level=3
 */
TEST(log_level_error) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.log(3, 'error message');\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 1;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    /* Verify level 3 (ERROR) was passed to callback */
    ASSERT_EQ(last_log_level, 3);
    ASSERT(strstr(captured_logs, "error message") != NULL);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Verify debug mode logs are not rate limited
 *
 * Verification: When debug_mode is true, all logs are captured
 */
TEST(debug_mode_not_rate_limited) {
    /* Program logs 200 times */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    for (var i = 0; i < 200; i++) {\n"
        "        mbpf.log(1, 'log ' + i);\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 1;  /* Debug mode - no rate limiting */
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    /* Verify all 200 logs were captured in debug mode */
    ASSERT_EQ(captured_log_count, 200);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Log with invalid level clamps to valid range
 *
 * Verification: Levels < 0 become DEBUG (0), levels > 3 become ERROR (3)
 */
TEST(log_level_clamping) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.log(-5, 'negative level');\n"
        "    mbpf.log(100, 'too high level');\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 1;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    /* Verify both logs were captured with clamped levels */
    ASSERT_EQ(captured_log_count, 2);
    /* First should be DEBUG (clamped from -5) - level 0 */
    ASSERT_EQ(captured_levels[0], 0);
    ASSERT(strstr(captured_logs, "negative level") != NULL);
    /* Second should be ERROR (clamped from 100) - level 3 */
    ASSERT_EQ(captured_levels[1], 3);
    ASSERT(strstr(captured_logs, "too high level") != NULL);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Log with undefined message
 *
 * Verification: undefined message is converted to empty string
 */
TEST(log_undefined_message) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.log(1);\n"  /* No message argument */
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.debug_mode = 1;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);  /* Should not crash */

    /* Verify log was captured with INFO level (1) */
    ASSERT_EQ(captured_log_count, 1);
    ASSERT_EQ(last_log_level, 1);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Helper Log Tests\n");
    printf("=========================\n\n");

    printf("Basic functionality tests:\n");
    RUN_TEST(log_function_exists);
    RUN_TEST(log_output_in_debug_mode);

    printf("\nLog level tests:\n");
    RUN_TEST(log_level_debug);
    RUN_TEST(log_level_info);
    RUN_TEST(log_level_warn);
    RUN_TEST(log_level_error);

    printf("\nRate limiting tests:\n");
    RUN_TEST(log_rate_limited_in_production);
    RUN_TEST(debug_mode_not_rate_limited);

    printf("\nEdge case tests:\n");
    RUN_TEST(log_level_clamping);
    RUN_TEST(log_undefined_message);

    printf("\n=========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
