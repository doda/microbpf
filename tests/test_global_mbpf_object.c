/*
 * microBPF Global mbpf Object Tests
 *
 * Tests for the global mbpf object and all its helpers:
 * 1. Verify mbpf object is accessible in global scope
 * 2. Verify mbpf.apiVersion property exists
 * 3. Verify mbpf.log function exists
 * 4. Verify mbpf.u64LoadLE and mbpf.u64StoreLE exist
 * 5. Verify optional helpers present based on config
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

/* Helper to build a manifest with specified capabilities */
static size_t build_manifest_with_caps(uint8_t *buf, size_t cap, int hook_type, const char *caps) {
    char json[4096];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"global_mbpf_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[%s]"
        "}",
        hook_type, caps);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package_with_caps(uint8_t *buf, size_t cap,
                                            const uint8_t *bytecode, size_t bc_len,
                                            int hook_type, const char *caps) {
    if (cap < 256) return 0;

    uint8_t manifest[4096];
    size_t manifest_len = build_manifest_with_caps(manifest, sizeof(manifest), hook_type, caps);
    if (manifest_len == 0) return 0;

    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

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

    return (size_t)(p - buf);
}

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_global_mbpf.js";
    const char *bc_file = "/tmp/test_global_mbpf.qjbc";

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
 * Test Cases - global-mbpf-object
 * ============================================================================ */

/*
 * Test 1: Verify mbpf object is accessible in global scope
 */
TEST(mbpf_object_in_global_scope) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof globalThis.mbpf === 'undefined') return -1;\n"
        "    if (typeof mbpf === 'undefined') return -2;\n"
        "    if (typeof mbpf !== 'object') return -3;\n"
        "    if (mbpf === null) return -4;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Verify mbpf.apiVersion property exists
 */
TEST(mbpf_api_version_exists) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (!mbpf.hasOwnProperty('apiVersion')) return -1;\n"
        "    if (typeof mbpf.apiVersion !== 'number') return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Verify mbpf.log function exists (when CAP_LOG granted)
 */
TEST(mbpf_log_exists_with_cap) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.log !== 'function') return -1;\n"
        "    mbpf.log(1, 'test log message');\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Verify mbpf.log is not present without CAP_LOG
 */
TEST(mbpf_log_absent_without_cap) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.log === 'function') return -1;\n"
        "    if (typeof mbpf.log !== 'undefined') return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    /* No CAP_LOG capability - use empty capabilities */
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Verify mbpf.u64LoadLE exists
 */
TEST(mbpf_u64LoadLE_exists) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.u64LoadLE !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Verify mbpf.u64StoreLE exists
 */
TEST(mbpf_u64StoreLE_exists) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.u64StoreLE !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Verify mbpf.nowNs exists when CAP_TIME granted
 */
TEST(mbpf_nowNs_exists_with_cap) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.nowNs !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_TIME;
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
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Verify mbpf.nowNs absent without CAP_TIME
 */
TEST(mbpf_nowNs_absent_without_cap) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.nowNs !== 'undefined') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Verify mbpf.emit exists when CAP_EMIT granted
 */
TEST(mbpf_emit_exists_with_cap) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.emit !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "\"CAP_EMIT\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_EMIT;
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
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Verify mbpf.emit absent without CAP_EMIT
 */
TEST(mbpf_emit_absent_without_cap) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.emit !== 'undefined') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Verify mbpf.stats exists when CAP_STATS granted
 */
TEST(mbpf_stats_exists_with_cap) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.stats !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_STATS;
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
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Verify mbpf.stats absent without CAP_STATS
 */
TEST(mbpf_stats_absent_without_cap) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.stats !== 'undefined') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: Verify all base helpers present regardless of capabilities
 */
TEST(base_helpers_always_present) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* These should always be present */\n"
        "    if (typeof mbpf.apiVersion !== 'number') return -1;\n"
        "    if (typeof mbpf.u64LoadLE !== 'function') return -2;\n"
        "    if (typeof mbpf.u64StoreLE !== 'function') return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    /* No capabilities at all */
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 14: Verify all helpers present with full capabilities
 */
TEST(all_helpers_with_full_caps) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Check all helpers present */\n"
        "    if (typeof mbpf.apiVersion !== 'number') return -1;\n"
        "    if (typeof mbpf.u64LoadLE !== 'function') return -2;\n"
        "    if (typeof mbpf.u64StoreLE !== 'function') return -3;\n"
        "    if (typeof mbpf.log !== 'function') return -4;\n"
        "    if (typeof mbpf.nowNs !== 'function') return -5;\n"
        "    if (typeof mbpf.emit !== 'function') return -6;\n"
        "    if (typeof mbpf.stats !== 'function') return -7;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    /* All capabilities */
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "\"CAP_LOG\",\"CAP_TIME\",\"CAP_EMIT\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME | MBPF_CAP_EMIT | MBPF_CAP_STATS;
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
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 15: Verify mbpf accessible from mbpf_init
 */
TEST(mbpf_accessible_in_init) {
    const char *js_code =
        "var initAccessible = false;\n"
        "function mbpf_init() {\n"
        "    if (typeof mbpf === 'object' && mbpf !== null) {\n"
        "        initAccessible = true;\n"
        "    }\n"
        "}\n"
        "function mbpf_prog(ctx) {\n"
        "    return initAccessible ? 0 : -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_caps(pkg, sizeof(pkg),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

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

    printf("microBPF Global mbpf Object Tests\n");
    printf("==================================\n\n");

    printf("Global scope tests:\n");
    RUN_TEST(mbpf_object_in_global_scope);
    RUN_TEST(mbpf_accessible_in_init);

    printf("\nCore properties:\n");
    RUN_TEST(mbpf_api_version_exists);

    printf("\nCore helpers (always present):\n");
    RUN_TEST(mbpf_u64LoadLE_exists);
    RUN_TEST(mbpf_u64StoreLE_exists);
    RUN_TEST(base_helpers_always_present);

    printf("\nCAP_LOG-gated helpers:\n");
    RUN_TEST(mbpf_log_exists_with_cap);
    RUN_TEST(mbpf_log_absent_without_cap);

    printf("\nCAP_TIME-gated helpers:\n");
    RUN_TEST(mbpf_nowNs_exists_with_cap);
    RUN_TEST(mbpf_nowNs_absent_without_cap);

    printf("\nCAP_EMIT-gated helpers:\n");
    RUN_TEST(mbpf_emit_exists_with_cap);
    RUN_TEST(mbpf_emit_absent_without_cap);

    printf("\nCAP_STATS-gated helpers:\n");
    RUN_TEST(mbpf_stats_exists_with_cap);
    RUN_TEST(mbpf_stats_absent_without_cap);

    printf("\nFull capabilities test:\n");
    RUN_TEST(all_helpers_with_full_caps);

    printf("\n==================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
