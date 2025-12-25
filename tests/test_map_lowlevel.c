/*
 * microBPF Low-Level Map Helper Tests
 *
 * Tests for optional low-level map helpers:
 * 1. Call mbpf.mapLookup(mapId, keyBytes, outValueBytes) - verify works
 * 2. Call mbpf.mapUpdate(mapId, keyBytes, valueBytes, flags) - verify works
 * 3. Call mbpf.mapDelete(mapId, keyBytes) - verify works
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

/* Helper to build a manifest with array map */
static size_t build_manifest_with_array(uint8_t *buf, size_t cap, int hook_type,
                                         uint32_t value_size, uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"lowlevel_map_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"myarray\",\"type\":1,\"key_size\":0,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(), value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with hash map */
static size_t build_manifest_with_hash(uint8_t *buf, size_t cap, int hook_type,
                                        uint32_t key_size, uint32_t value_size,
                                        uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"lowlevel_map_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"myhash\",\"type\":2,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(), key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with array map */
static size_t build_mbpf_package_array(uint8_t *buf, size_t cap,
                                        const uint8_t *bytecode, size_t bc_len,
                                        int hook_type,
                                        uint32_t value_size, uint32_t max_entries) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_array(manifest, sizeof(manifest),
                                                     hook_type, value_size, max_entries);
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

/* Build a complete .mbpf package with hash map */
static size_t build_mbpf_package_hash(uint8_t *buf, size_t cap,
                                       const uint8_t *bytecode, size_t bc_len,
                                       int hook_type,
                                       uint32_t key_size, uint32_t value_size,
                                       uint32_t max_entries) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash(manifest, sizeof(manifest),
                                                    hook_type, key_size, value_size,
                                                    max_entries);
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

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_map_lowlevel.js";
    const char *bc_file = "/tmp/test_map_lowlevel.qjbc";

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
 * Test Cases - Low-Level Map Helpers
 * ============================================================================ */

/*
 * Test 1: mbpf.mapLookup exists
 */
TEST(mapLookup_exists) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.mapLookup !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_array(pkg, sizeof(pkg),
                                               bytecode, bc_len,
                                               MBPF_HOOK_TRACEPOINT, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 2: mbpf.mapUpdate exists
 */
TEST(mapUpdate_exists) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.mapUpdate !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_array(pkg, sizeof(pkg),
                                               bytecode, bc_len,
                                               MBPF_HOOK_TRACEPOINT, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 3: mbpf.mapDelete exists
 */
TEST(mapDelete_exists) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.mapDelete !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_array(pkg, sizeof(pkg),
                                               bytecode, bc_len,
                                               MBPF_HOOK_TRACEPOINT, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 4: Array map lookup returns false initially
 */
TEST(array_lookup_returns_false_initially) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    var found = mbpf.mapLookup(0, 0, outBuf);\n"
        "    if (found !== false) return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_array(pkg, sizeof(pkg),
                                               bytecode, bc_len,
                                               MBPF_HOOK_TRACEPOINT, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 5: Array map update and lookup
 */
TEST(array_update_then_lookup) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var value = new Uint8Array([0xAB, 0xCD, 0xEF, 0x12]);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    \n"
        "    // Update at index 0\n"
        "    var ok = mbpf.mapUpdate(0, 0, value, 0);\n"
        "    if (!ok) return -1;\n"
        "    \n"
        "    // Lookup at index 0\n"
        "    var found = mbpf.mapLookup(0, 0, outBuf);\n"
        "    if (!found) return -2;\n"
        "    \n"
        "    // Verify value\n"
        "    if (outBuf[0] !== 0xAB || outBuf[1] !== 0xCD ||\n"
        "        outBuf[2] !== 0xEF || outBuf[3] !== 0x12) return -3;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_array(pkg, sizeof(pkg),
                                               bytecode, bc_len,
                                               MBPF_HOOK_TRACEPOINT, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 6: Array map delete
 */
TEST(array_delete) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var value = new Uint8Array([0x11, 0x22, 0x33, 0x44]);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    \n"
        "    // Update at index 5\n"
        "    mbpf.mapUpdate(0, 5, value, 0);\n"
        "    \n"
        "    // Verify it exists\n"
        "    if (!mbpf.mapLookup(0, 5, outBuf)) return -1;\n"
        "    \n"
        "    // Delete it\n"
        "    if (!mbpf.mapDelete(0, 5)) return -2;\n"
        "    \n"
        "    // Verify it's gone\n"
        "    if (mbpf.mapLookup(0, 5, outBuf)) return -3;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_array(pkg, sizeof(pkg),
                                               bytecode, bc_len,
                                               MBPF_HOOK_TRACEPOINT, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 7: Hash map lookup returns false initially
 */
TEST(hash_lookup_returns_false_initially) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    var found = mbpf.mapLookup(0, key, outBuf);\n"
        "    if (found !== false) return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_hash(pkg, sizeof(pkg),
                                              bytecode, bc_len,
                                              MBPF_HOOK_TRACEPOINT, 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 8: Hash map update and lookup
 */
TEST(hash_update_then_lookup) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var value = new Uint8Array(16);\n"
        "    for (var i = 0; i < 16; i++) value[i] = i + 0x10;\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    \n"
        "    // Update with key\n"
        "    var ok = mbpf.mapUpdate(0, key, value, 0);\n"
        "    if (!ok) return -1;\n"
        "    \n"
        "    // Lookup with same key\n"
        "    var found = mbpf.mapLookup(0, key, outBuf);\n"
        "    if (!found) return -2;\n"
        "    \n"
        "    // Verify value\n"
        "    for (var i = 0; i < 16; i++) {\n"
        "        if (outBuf[i] !== i + 0x10) return -3 - i;\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_hash(pkg, sizeof(pkg),
                                              bytecode, bc_len,
                                              MBPF_HOOK_TRACEPOINT, 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 9: Hash map delete
 */
TEST(hash_delete) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);\n"
        "    var value = new Uint8Array(16);\n"
        "    for (var i = 0; i < 16; i++) value[i] = 0xFF;\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    \n"
        "    // Update with key\n"
        "    mbpf.mapUpdate(0, key, value, 0);\n"
        "    \n"
        "    // Verify it exists\n"
        "    if (!mbpf.mapLookup(0, key, outBuf)) return -1;\n"
        "    \n"
        "    // Delete it\n"
        "    if (!mbpf.mapDelete(0, key)) return -2;\n"
        "    \n"
        "    // Verify it's gone\n"
        "    if (mbpf.mapLookup(0, key, outBuf)) return -3;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_hash(pkg, sizeof(pkg),
                                              bytecode, bc_len,
                                              MBPF_HOOK_TRACEPOINT, 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 10: Update flags work correctly
 */
TEST(update_flags) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var value1 = new Uint8Array([0x11, 0x11, 0x11, 0x11]);\n"
        "    var value2 = new Uint8Array([0x22, 0x22, 0x22, 0x22]);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    \n"
        "    // Create only - should succeed (entry doesn't exist)\n"
        "    if (!mbpf.mapUpdate(0, 0, value1, 1)) return -1;\n"
        "    \n"
        "    // Create only - should fail (entry exists)\n"
        "    if (mbpf.mapUpdate(0, 0, value2, 1)) return -2;\n"
        "    \n"
        "    // Verify original value\n"
        "    mbpf.mapLookup(0, 0, outBuf);\n"
        "    if (outBuf[0] !== 0x11) return -3;\n"
        "    \n"
        "    // Update only - should succeed (entry exists)\n"
        "    if (!mbpf.mapUpdate(0, 0, value2, 2)) return -4;\n"
        "    \n"
        "    // Verify updated value\n"
        "    mbpf.mapLookup(0, 0, outBuf);\n"
        "    if (outBuf[0] !== 0x22) return -5;\n"
        "    \n"
        "    // Update only on new entry - should fail\n"
        "    if (mbpf.mapUpdate(0, 1, value1, 2)) return -6;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_array(pkg, sizeof(pkg),
                                               bytecode, bc_len,
                                               MBPF_HOOK_TRACEPOINT, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test 11: Range and type errors
 */
TEST(errors) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    \n"
        "    // Invalid mapId\n"
        "    try {\n"
        "        mbpf.mapLookup(99, 0, outBuf);\n"
        "        return -1;  // Should have thrown\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -2;\n"
        "    }\n"
        "    \n"
        "    // Index out of bounds\n"
        "    try {\n"
        "        mbpf.mapLookup(0, 999, outBuf);\n"
        "        return -3;  // Should have thrown\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -4;\n"
        "    }\n"
        "    \n"
        "    // Type error - array map needs numeric index\n"
        "    try {\n"
        "        mbpf.mapLookup(0, 'invalid', outBuf);\n"
        "        return -5;  // Should have thrown\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof TypeError)) return -6;\n"
        "    }\n"
        "    \n"
        "    // Buffer too small\n"
        "    var smallBuf = new Uint8Array(1);\n"
        "    try {\n"
        "        mbpf.mapLookup(0, 0, smallBuf);\n"
        "        return -7;  // Should have thrown\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -8;\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_array(pkg, sizeof(pkg),
                                               bytecode, bc_len,
                                               MBPF_HOOK_TRACEPOINT, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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

/* Helper to build a manifest with LRU map */
static size_t build_manifest_with_lru(uint8_t *buf, size_t cap, int hook_type,
                                       uint32_t key_size, uint32_t value_size,
                                       uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"lowlevel_lru_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"mylru\",\"type\":3,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(), key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with LRU map */
static size_t build_mbpf_package_lru(uint8_t *buf, size_t cap,
                                      const uint8_t *bytecode, size_t bc_len,
                                      int hook_type,
                                      uint32_t key_size, uint32_t value_size,
                                      uint32_t max_entries) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_lru(manifest, sizeof(manifest),
                                                   hook_type, key_size, value_size,
                                                   max_entries);
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

/*
 * Test: LRU map basic update and lookup using low-level helpers
 */
TEST(lru_update_then_lookup) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([1, 2, 3, 4]);\n"
        "    var value = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    \n"
        "    // Update (insert) key->value\n"
        "    var updated = mbpf.mapUpdate(0, key, value, 0);\n"
        "    if (!updated) return -1;\n"
        "    \n"
        "    // Lookup should succeed\n"
        "    var found = mbpf.mapLookup(0, key, outBuf);\n"
        "    if (!found) return -2;\n"
        "    if (outBuf[0] !== 0xAA) return -3;\n"
        "    if (outBuf[1] !== 0xBB) return -4;\n"
        "    if (outBuf[2] !== 0xCC) return -5;\n"
        "    if (outBuf[3] !== 0xDD) return -6;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_lru(pkg, sizeof(pkg),
                                             bytecode, bc_len,
                                             MBPF_HOOK_TRACEPOINT,
                                             4, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test: LRU eviction via low-level helpers
 *
 * Fill the LRU map to capacity, then insert one more.
 * The oldest entry should be evicted.
 */
TEST(lru_eviction) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    \n"
        "    // Insert 3 keys into LRU map with max_entries=3\n"
        "    var key1 = new Uint8Array([1, 0, 0, 0]);\n"
        "    var key2 = new Uint8Array([2, 0, 0, 0]);\n"
        "    var key3 = new Uint8Array([3, 0, 0, 0]);\n"
        "    var val1 = new Uint8Array([0x11, 0x11, 0x11, 0x11]);\n"
        "    var val2 = new Uint8Array([0x22, 0x22, 0x22, 0x22]);\n"
        "    var val3 = new Uint8Array([0x33, 0x33, 0x33, 0x33]);\n"
        "    \n"
        "    mbpf.mapUpdate(0, key1, val1, 0);  // key1 is oldest\n"
        "    mbpf.mapUpdate(0, key2, val2, 0);\n"
        "    mbpf.mapUpdate(0, key3, val3, 0);  // key3 is newest\n"
        "    \n"
        "    // All three should exist\n"
        "    if (!mbpf.mapLookup(0, key1, outBuf)) return -1;\n"
        "    if (!mbpf.mapLookup(0, key2, outBuf)) return -2;\n"
        "    if (!mbpf.mapLookup(0, key3, outBuf)) return -3;\n"
        "    \n"
        "    // Insert 4th key - this should evict key1 (oldest after lookups refreshed order)\n"
        "    // But since we just looked up key1, key2, key3 in order, key1 is now newest!\n"
        "    // So we need to think about LRU order after lookups:\n"
        "    // After inserts: key3 (head) -> key2 -> key1 (tail)\n"
        "    // After lookup(key1): key1 (head) -> key3 -> key2 (tail)\n"
        "    // After lookup(key2): key2 (head) -> key1 -> key3 (tail)\n"
        "    // After lookup(key3): key3 (head) -> key2 -> key1 (tail)\n"
        "    // So key1 is now the oldest again\n"
        "    var key4 = new Uint8Array([4, 0, 0, 0]);\n"
        "    var val4 = new Uint8Array([0x44, 0x44, 0x44, 0x44]);\n"
        "    mbpf.mapUpdate(0, key4, val4, 0);  // Should evict key1\n"
        "    \n"
        "    // key1 should be gone (evicted)\n"
        "    if (mbpf.mapLookup(0, key1, outBuf)) return -4;  // Should NOT find key1\n"
        "    \n"
        "    // key2, key3, key4 should still exist\n"
        "    if (!mbpf.mapLookup(0, key2, outBuf)) return -5;\n"
        "    if (!mbpf.mapLookup(0, key3, outBuf)) return -6;\n"
        "    if (!mbpf.mapLookup(0, key4, outBuf)) return -7;\n"
        "    if (outBuf[0] !== 0x44) return -8;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_lru(pkg, sizeof(pkg),
                                             bytecode, bc_len,
                                             MBPF_HOOK_TRACEPOINT,
                                             4, 4, 3);  /* max_entries=3 */
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test: LRU delete via low-level helpers
 */
TEST(lru_delete) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([1, 2, 3, 4]);\n"
        "    var value = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    \n"
        "    // Insert key\n"
        "    mbpf.mapUpdate(0, key, value, 0);\n"
        "    \n"
        "    // Verify it exists\n"
        "    if (!mbpf.mapLookup(0, key, outBuf)) return -1;\n"
        "    \n"
        "    // Delete it\n"
        "    var deleted = mbpf.mapDelete(0, key);\n"
        "    if (!deleted) return -2;\n"
        "    \n"
        "    // Verify it's gone\n"
        "    if (mbpf.mapLookup(0, key, outBuf)) return -3;\n"
        "    \n"
        "    // Delete again should return false\n"
        "    if (mbpf.mapDelete(0, key)) return -4;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_lru(pkg, sizeof(pkg),
                                             bytecode, bc_len,
                                             MBPF_HOOK_TRACEPOINT,
                                             4, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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
 * Test: LRU lookup refreshes access order
 *
 * Verify that looking up an entry moves it to MRU position,
 * protecting it from eviction.
 */
TEST(lru_lookup_refreshes_order) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    \n"
        "    // Insert 3 keys into LRU map with max_entries=3\n"
        "    var key1 = new Uint8Array([1, 0, 0, 0]);\n"
        "    var key2 = new Uint8Array([2, 0, 0, 0]);\n"
        "    var key3 = new Uint8Array([3, 0, 0, 0]);\n"
        "    var val1 = new Uint8Array([0x11, 0x11, 0x11, 0x11]);\n"
        "    var val2 = new Uint8Array([0x22, 0x22, 0x22, 0x22]);\n"
        "    var val3 = new Uint8Array([0x33, 0x33, 0x33, 0x33]);\n"
        "    \n"
        "    mbpf.mapUpdate(0, key1, val1, 0);  // key1 is oldest\n"
        "    mbpf.mapUpdate(0, key2, val2, 0);\n"
        "    mbpf.mapUpdate(0, key3, val3, 0);  // key3 is newest\n"
        "    \n"
        "    // LRU order now: key3 (head) -> key2 -> key1 (tail)\n"
        "    // Access key1 to refresh it, making key2 the oldest\n"
        "    mbpf.mapLookup(0, key1, outBuf);\n"
        "    // LRU order now: key1 (head) -> key3 -> key2 (tail)\n"
        "    \n"
        "    // Insert 4th key - this should evict key2 (now oldest)\n"
        "    var key4 = new Uint8Array([4, 0, 0, 0]);\n"
        "    var val4 = new Uint8Array([0x44, 0x44, 0x44, 0x44]);\n"
        "    mbpf.mapUpdate(0, key4, val4, 0);\n"
        "    \n"
        "    // key2 should be gone (evicted), key1 should still exist\n"
        "    if (mbpf.mapLookup(0, key2, outBuf)) return -1;  // key2 should be evicted\n"
        "    if (!mbpf.mapLookup(0, key1, outBuf)) return -2;  // key1 should exist\n"
        "    if (outBuf[0] !== 0x11) return -3;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_lru(pkg, sizeof(pkg),
                                             bytecode, bc_len,
                                             MBPF_HOOK_TRACEPOINT,
                                             4, 4, 3);  /* max_entries=3 */
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
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

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0, failed = 0;

    printf("microBPF Low-Level Map Helper Tests\n");
    printf("====================================\n\n");

    printf("Helper existence tests:\n");
    RUN_TEST(mapLookup_exists);
    RUN_TEST(mapUpdate_exists);
    RUN_TEST(mapDelete_exists);

    printf("\nArray map tests:\n");
    RUN_TEST(array_lookup_returns_false_initially);
    RUN_TEST(array_update_then_lookup);
    RUN_TEST(array_delete);

    printf("\nHash map tests:\n");
    RUN_TEST(hash_lookup_returns_false_initially);
    RUN_TEST(hash_update_then_lookup);
    RUN_TEST(hash_delete);

    printf("\nLRU map tests:\n");
    RUN_TEST(lru_update_then_lookup);
    RUN_TEST(lru_eviction);
    RUN_TEST(lru_delete);
    RUN_TEST(lru_lookup_refreshes_order);

    printf("\nFlag and error tests:\n");
    RUN_TEST(update_flags);
    RUN_TEST(errors);

    printf("\n====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
