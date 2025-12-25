/*
 * microBPF Console Debug Mode Tests
 *
 * Tests for optional console.log in debug mode:
 * 1. Enable debug mode in runtime config
 * 2. Call console.log('test') from program
 * 3. Verify output appears (mapped to mbpf.log)
 * 4. Disable debug mode and verify console.log unavailable
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

static void reset_log_capture(void) {
    captured_logs[0] = '\0';
    captured_log_offset = 0;
    captured_log_count = 0;
    last_log_level = -1;
}

static void test_log_fn(int level, const char *msg) {
    last_log_level = level;
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
        "\"program_name\":\"console_test\","
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
    const char *js_file = "/tmp/test_console.js";
    const char *bc_file = "/tmp/test_console.qjbc";

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
 * Test Cases - console.log debug mode
 * ============================================================================ */

/*
 * Test 1: Enable debug mode in runtime config
 *
 * Verification: Debug mode can be enabled in runtime config
 */
TEST(debug_mode_enabled) {
    mbpf_runtime_config_t cfg = {0};
    cfg.debug_mode = 1;  /* Enable debug mode */
    cfg.log_fn = test_log_fn;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;
    cfg.allowed_capabilities = MBPF_CAP_LOG;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    /* Runtime created successfully with debug mode */
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 2: Call console.log('test') from program in debug mode
 *
 * Verification: console.log works and produces output in debug mode
 */
TEST(console_log_in_debug_mode) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof console === 'undefined') return -1;\n"
        "    if (typeof console.log !== 'function') return -2;\n"
        "    console.log('test message from console');\n"
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
    cfg.allowed_capabilities = MBPF_CAP_LOG;

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
    ASSERT_EQ(rc, 0);  /* console exists and log is a function */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Verify output appears (mapped to mbpf.log)
 *
 * Verification: console.log output is captured via log_fn
 */
TEST(console_log_output_appears) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    console.log('hello from console.log');\n"
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
    cfg.allowed_capabilities = MBPF_CAP_LOG;

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

    /* Verify log was captured - console.log maps to mbpf.log (INFO level = 1) */
    ASSERT(captured_log_count > 0);
    ASSERT(strstr(captured_logs, "hello from console.log") != NULL);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Disable debug mode and verify console.log unavailable
 *
 * Verification: console is undefined in non-debug mode
 */
TEST(console_unavailable_without_debug) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof console === 'undefined') return 1;\n"  /* Success: console is undefined */
        "    return -1;\n"  /* Failure: console should be undefined */
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
    cfg.debug_mode = 0;  /* Disable debug mode - production mode */
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;
    cfg.allowed_capabilities = MBPF_CAP_LOG;

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
    ASSERT_EQ(rc, 1);  /* console should be undefined */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: mbpf.log still works without debug mode
 *
 * Verification: mbpf.log is available even in production mode
 */
TEST(mbpf_log_works_without_debug) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf === 'undefined') return -1;\n"
        "    if (typeof mbpf.log !== 'function') return -2;\n"
        "    mbpf.log(1, 'log from mbpf.log');\n"
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
    cfg.debug_mode = 0;  /* Production mode */
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;
    cfg.allowed_capabilities = MBPF_CAP_LOG;

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
    ASSERT_EQ(rc, 0);  /* mbpf.log exists and works */

    /* Verify log was captured */
    ASSERT(captured_log_count > 0);
    ASSERT(strstr(captured_logs, "log from mbpf.log") != NULL);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: console.log with multiple arguments in debug mode
 *
 * Verification: console.log handles multiple arguments
 */
TEST(console_log_multiple_args) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    console.log('value1', 'value2', 123);\n"
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
    cfg.debug_mode = 1;  /* Debug mode */
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;
    cfg.allowed_capabilities = MBPF_CAP_LOG;

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

    /* Verify log contains all values */
    ASSERT(captured_log_count > 0);
    ASSERT(strstr(captured_logs, "value1") != NULL);
    ASSERT(strstr(captured_logs, "value2") != NULL);
    ASSERT(strstr(captured_logs, "123") != NULL);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: console.log calling in production mode throws or is no-op
 *
 * Verification: Calling console.log when console is undefined throws
 */
TEST(console_log_call_in_production_throws) {
    /* This test verifies that trying to call console.log in production mode
     * causes an error (since console is undefined) */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        console.log('should not work');\n"
        "        return -1;\n"  /* Should not reach here */
        "    } catch (e) {\n"
        "        return 1;\n"  /* Exception caught as expected */
        "    }\n"
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
    cfg.debug_mode = 0;  /* Production mode */
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;
    cfg.allowed_capabilities = MBPF_CAP_LOG;

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
    ASSERT_EQ(rc, 1);  /* Exception caught as expected */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Default debug_mode is false
 *
 * Verification: Without explicit debug_mode, console is unavailable
 */
TEST(default_debug_mode_is_false) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof console === 'undefined') return 1;\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};  /* debug_mode is 0 by default */
    cfg.log_fn = test_log_fn;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;
    cfg.allowed_capabilities = MBPF_CAP_LOG;
    /* Note: cfg.debug_mode is not explicitly set - defaults to 0 */

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* console should be undefined by default */

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

    printf("microBPF Console Debug Mode Tests\n");
    printf("==================================\n\n");

    printf("Debug mode configuration tests:\n");
    RUN_TEST(debug_mode_enabled);
    RUN_TEST(default_debug_mode_is_false);

    printf("\nConsole.log in debug mode tests:\n");
    RUN_TEST(console_log_in_debug_mode);
    RUN_TEST(console_log_output_appears);
    RUN_TEST(console_log_multiple_args);

    printf("\nConsole.log unavailable in production mode tests:\n");
    RUN_TEST(console_unavailable_without_debug);
    RUN_TEST(console_log_call_in_production_throws);
    RUN_TEST(mbpf_log_works_without_debug);

    printf("\n==================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
