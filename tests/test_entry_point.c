/*
 * microBPF Entry Point Tests
 *
 * Tests for mbpf_prog entry function:
 * - Load program defining mbpf_prog function
 * - Run program and verify mbpf_prog is invoked with ctx
 * - Load program without mbpf_prog - verify load fails
 * - Verify custom entry_symbol from manifest is honored
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

/* Helper to build a minimal valid JSON manifest */
static size_t build_test_manifest(uint8_t *buf, size_t cap, const char *entry_symbol) {
    char json[1024];
    int len;
    if (entry_symbol) {
        len = snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"entry_test\","
            "\"program_version\":\"1.0.0\","
            "\"hook_type\":1,"
            "\"hook_ctx_abi_version\":1,"
            "\"entry_symbol\":\"%s\","
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":64,\"endianness\":0},"
            "\"mbpf_api_version\":1,"
            "\"heap_size\":65536,"
            "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
            "\"capabilities\":[\"CAP_LOG\"]"
            "}", entry_symbol);
    } else {
        len = snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"entry_test\","
            "\"program_version\":\"1.0.0\","
            "\"hook_type\":1,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":64,\"endianness\":0},"
            "\"mbpf_api_version\":1,"
            "\"heap_size\":65536,"
            "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
            "\"capabilities\":[\"CAP_LOG\"]"
            "}");
    }
    if (len <= 0 || (size_t)len >= sizeof(json)) return 0;
    if ((size_t)len > cap) return 0;
    memcpy(buf, json, len);
    return (size_t)len;
}

/* Build a complete .mbpf package with bytecode */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  const char *entry_symbol) {
    if (cap < 256) return 0;

    uint8_t manifest[1024];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest), entry_symbol);
    if (manifest_len == 0) return 0;

    /* Calculate offsets */
    uint32_t header_size = 20 + 2 * 16;  /* header + 2 section descriptors */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    /* magic "MBPF" in little-endian: 0x4D425046 */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    /* format_version = 1 */
    *p++ = 0x01; *p++ = 0x00;
    /* header_size */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    /* flags = 0 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* section_count = 2 */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* file_crc32 = 0 (disabled) */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 0: MANIFEST (type=1) */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
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
    const char *js_file = "/tmp/test_entry_point.js";
    const char *bc_file = "/tmp/test_entry_point.qjbc";

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
 * Test Cases - entry-point-mbpf-prog
 * ============================================================================ */

/* Test 1: Load program defining mbpf_prog function - verify it loads */
TEST(load_with_mbpf_prog) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 2: Run program and verify mbpf_prog is invoked with ctx */
TEST(mbpf_prog_called_with_ctx) {
    /* Program that returns ctx.tracepoint_id if ctx exists, -1 otherwise */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx && ctx.tracepoint_id !== undefined) {\n"
        "        return ctx.tracepoint_id;\n"
        "    }\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Create tracepoint context with tracepoint_id = 42 */
    mbpf_ctx_tracepoint_v1_t ctx = {0};
    ctx.abi_version = 1;
    ctx.tracepoint_id = 42;
    ctx.timestamp = 1000;
    ctx.cpu = 0;
    ctx.pid = 1234;
    ctx.data_len = 0;
    ctx.flags = 0;
    ctx.data = NULL;
    ctx.read_fn = NULL;

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);  /* Should return tracepoint_id from ctx */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 3: Load program without mbpf_prog - verify load fails */
TEST(load_without_mbpf_prog_fails) {
    /* Program with a different function name */
    const char *js_code =
        "function my_handler(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* Default entry_symbol is "mbpf_prog", but our code doesn't define it */
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Should fail because mbpf_prog is not defined */
    ASSERT_EQ(err, MBPF_ERR_MISSING_ENTRY);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 4: Verify custom entry_symbol from manifest is honored */
TEST(custom_entry_symbol_honored) {
    /* Program with custom entry function */
    const char *js_code =
        "function my_custom_handler(ctx) {\n"
        "    if (ctx && ctx.tracepoint_id !== undefined) {\n"
        "        return ctx.tracepoint_id + 100;\n"
        "    }\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* Specify custom entry_symbol in manifest */
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, "my_custom_handler");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Create tracepoint context with tracepoint_id = 7 */
    mbpf_ctx_tracepoint_v1_t ctx = {0};
    ctx.abi_version = 1;
    ctx.tracepoint_id = 7;
    ctx.timestamp = 2000;
    ctx.cpu = 1;
    ctx.pid = 5678;
    ctx.data_len = 0;
    ctx.flags = 0;
    ctx.data = NULL;
    ctx.read_fn = NULL;

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 107);  /* Should return tracepoint_id + 100 = 7 + 100 = 107 */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 5: Custom entry_symbol that doesn't exist fails load */
TEST(custom_entry_symbol_missing_fails) {
    /* Program with mbpf_prog, but manifest requests different entry */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* Request entry_symbol that doesn't exist in bytecode */
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, "nonexistent_handler");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Should fail because nonexistent_handler is not defined */
    ASSERT_EQ(err, MBPF_ERR_MISSING_ENTRY);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 6: Stats show mbpf_prog was invoked */
TEST(stats_show_invocation) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times with NULL context (consistent with test_run_basic behavior) */
    int32_t out_rc;
    for (int i = 0; i < 5; i++) {
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Check stats */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 5);
    ASSERT_EQ(stats.successes, 5);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 7: mbpf_prog returning non-zero value */
TEST(mbpf_prog_return_value) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = {0};
    ctx.abi_version = 1;

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 8: mbpf_prog accesses ctx properties */
TEST(mbpf_prog_accesses_ctx_properties) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    // Return sum of multiple properties\n"
        "    return ctx.tracepoint_id + ctx.cpu + ctx.pid;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = {0};
    ctx.abi_version = 1;
    ctx.tracepoint_id = 10;
    ctx.cpu = 5;
    ctx.pid = 100;

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 115);  /* 10 + 5 + 100 = 115 */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(void) {
    int passed = 0, failed = 0;

    printf("microBPF Entry Point Tests\n");
    printf("==========================\n\n");

    printf("Load and validation tests:\n");
    RUN_TEST(load_with_mbpf_prog);
    RUN_TEST(load_without_mbpf_prog_fails);
    RUN_TEST(custom_entry_symbol_honored);
    RUN_TEST(custom_entry_symbol_missing_fails);

    printf("\nExecution tests:\n");
    RUN_TEST(mbpf_prog_called_with_ctx);
    RUN_TEST(mbpf_prog_return_value);
    RUN_TEST(mbpf_prog_accesses_ctx_properties);
    RUN_TEST(stats_show_invocation);

    printf("\n==========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
