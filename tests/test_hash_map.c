/*
 * microBPF Hash Map Tests
 *
 * Tests for hash map type with lookup, update, and delete operations:
 * 1. Define hash map in manifest with key_size=8, value_size=16, max_entries=100
 * 2. Load program and verify map is created
 * 3. Call maps.myhash.lookup(keyBuffer, outBuffer) - verify returns false initially
 * 4. Call maps.myhash.update(keyBuffer, valueBuffer) - verify success
 * 5. Call maps.myhash.lookup(keyBuffer, outBuffer) - verify returns true with data
 * 6. Call maps.myhash.delete(keyBuffer) - verify returns true
 * 7. Call maps.myhash.lookup(keyBuffer, outBuffer) - verify returns false after delete
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

/* Helper to build a manifest with hash map definition */
static size_t build_manifest_with_hash_map(uint8_t *buf, size_t cap, int hook_type,
                                            const char *map_name, uint32_t key_size,
                                            uint32_t value_size, uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"hash_map_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":2,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and hash map */
static size_t build_mbpf_package_with_hash_map(uint8_t *buf, size_t cap,
                                                const uint8_t *bytecode, size_t bc_len,
                                                int hook_type,
                                                const char *map_name, uint32_t key_size,
                                                uint32_t value_size, uint32_t max_entries) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash_map(manifest, sizeof(manifest),
                                                        hook_type, map_name,
                                                        key_size, value_size, max_entries);
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
    const char *js_file = "/tmp/test_hash_map.js";
    const char *bc_file = "/tmp/test_hash_map.qjbc";

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
 * Test Cases - map-hash-basic
 * ============================================================================ */

/*
 * Test 1: Map is created and accessible with correct methods
 *
 * Verification: Program can access maps object and named hash map with lookup/update/delete
 */
TEST(map_created) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof maps === 'undefined') return -1;\n"
        "    if (typeof maps.myhash === 'undefined') return -2;\n"
        "    if (typeof maps.myhash.lookup !== 'function') return -3;\n"
        "    if (typeof maps.myhash.update !== 'function') return -4;\n"
        "    if (typeof maps.myhash.delete !== 'function') return -5;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* All checks passed */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Lookup returns false initially
 *
 * Verification: lookup on non-existent key returns false
 */
TEST(lookup_returns_false_initially) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array(8);\n"
        "    keyBuf[0] = 0x12; keyBuf[1] = 0x34;\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    var found = maps.myhash.lookup(keyBuf, outBuf);\n"
        "    return found ? 1 : 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* lookup returned false */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Update succeeds
 *
 * Verification: update returns true
 */
TEST(update_succeeds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var valueBuf = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,\n"
        "                                   0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);\n"
        "    var success = maps.myhash.update(keyBuf, valueBuf);\n"
        "    return success ? 1 : 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);  /* update returned true */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Lookup returns true after update with correct data
 *
 * Verification: lookup returns true and data matches what was written
 */
TEST(lookup_returns_correct_data) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var valueBuf = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,\n"
        "                                   0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);\n"
        "    maps.myhash.update(keyBuf, valueBuf);\n"
        "    \n"
        "    var outBuf = new Uint8Array(16);\n"
        "    var found = maps.myhash.lookup(keyBuf, outBuf);\n"
        "    if (!found) return -1;\n"
        "    \n"
        "    /* Verify data matches */\n"
        "    if (outBuf[0] !== 0x11) return -2;\n"
        "    if (outBuf[1] !== 0x22) return -3;\n"
        "    if (outBuf[7] !== 0x88) return -4;\n"
        "    if (outBuf[15] !== 0x00) return -5;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* All checks passed */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Delete returns true for existing key
 *
 * Verification: delete returns true when key exists
 */
TEST(delete_returns_true) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var valueBuf = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,\n"
        "                                   0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);\n"
        "    maps.myhash.update(keyBuf, valueBuf);\n"
        "    \n"
        "    var deleted = maps.myhash.delete(keyBuf);\n"
        "    return deleted ? 1 : 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);  /* delete returned true */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Lookup returns false after delete
 *
 * Verification: lookup returns false after key is deleted
 */
TEST(lookup_returns_false_after_delete) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var valueBuf = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,\n"
        "                                   0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00]);\n"
        "    maps.myhash.update(keyBuf, valueBuf);\n"
        "    maps.myhash.delete(keyBuf);\n"
        "    \n"
        "    var outBuf = new Uint8Array(16);\n"
        "    var found = maps.myhash.lookup(keyBuf, outBuf);\n"
        "    return found ? 1 : 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* lookup returned false */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Delete returns false for non-existent key
 *
 * Verification: delete returns false when key doesn't exist
 */
TEST(delete_nonexistent_returns_false) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var deleted = maps.myhash.delete(keyBuf);\n"
        "    return deleted ? 1 : 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* delete returned false */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Multiple entries work independently
 *
 * Verification: Different keys store different values
 */
TEST(multiple_entries) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert three different key-value pairs */\n"
        "    var key1 = new Uint8Array([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);\n"
        "    var val1 = new Uint8Array([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,\n"
        "                               0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);\n"
        "    maps.myhash.update(key1, val1);\n"
        "    \n"
        "    var key2 = new Uint8Array([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);\n"
        "    var val2 = new Uint8Array([0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,\n"
        "                               0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB]);\n"
        "    maps.myhash.update(key2, val2);\n"
        "    \n"
        "    var key3 = new Uint8Array([0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);\n"
        "    var val3 = new Uint8Array([0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,\n"
        "                               0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC]);\n"
        "    maps.myhash.update(key3, val3);\n"
        "    \n"
        "    /* Verify each key has correct value */\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    \n"
        "    if (!maps.myhash.lookup(key1, outBuf)) return -1;\n"
        "    if (outBuf[0] !== 0xAA) return -2;\n"
        "    \n"
        "    if (!maps.myhash.lookup(key2, outBuf)) return -3;\n"
        "    if (outBuf[0] !== 0xBB) return -4;\n"
        "    \n"
        "    if (!maps.myhash.lookup(key3, outBuf)) return -5;\n"
        "    if (outBuf[0] !== 0xCC) return -6;\n"
        "    \n"
        "    /* Key4 should not exist */\n"
        "    var key4 = new Uint8Array([0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);\n"
        "    if (maps.myhash.lookup(key4, outBuf)) return -7;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Update overwrites existing value
 *
 * Verification: updating an existing key changes the value
 */
TEST(update_overwrites_value) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var val1 = new Uint8Array([0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,\n"
        "                               0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]);\n"
        "    maps.myhash.update(keyBuf, val1);\n"
        "    \n"
        "    var val2 = new Uint8Array([0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,\n"
        "                               0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22]);\n"
        "    maps.myhash.update(keyBuf, val2);\n"
        "    \n"
        "    var outBuf = new Uint8Array(16);\n"
        "    if (!maps.myhash.lookup(keyBuf, outBuf)) return -1;\n"
        "    if (outBuf[0] !== 0x22) return -2;\n"
        "    if (outBuf[15] !== 0x22) return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Type checking - non-Uint8Array key
 *
 * Verification: non-Uint8Array key throws TypeError
 */
TEST(type_check_key) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    try {\n"
        "        maps.myhash.lookup('hello', outBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof TypeError)) return -2;\n"
        "    }\n"
        "    try {\n"
        "        maps.myhash.update([1, 2, 3, 4, 5, 6, 7, 8], outBuf);\n"
        "        return -3;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof TypeError)) return -4;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Key size validation
 *
 * Verification: key too small throws RangeError
 */
TEST(key_size_check) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var smallKey = new Uint8Array(4);  /* key_size is 8 */\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    try {\n"
        "        maps.myhash.lookup(smallKey, outBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -2;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Value buffer size validation
 *
 * Verification: value buffer too small throws RangeError
 */
TEST(value_size_check) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array(8);\n"
        "    var smallBuf = new Uint8Array(8);  /* value_size is 16 */\n"
        "    try {\n"
        "        maps.myhash.lookup(keyBuf, smallBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -2;\n"
        "    }\n"
        "    try {\n"
        "        maps.myhash.update(keyBuf, smallBuf);\n"
        "        return -3;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -4;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: Data persists across invocations
 *
 * Verification: Data written in one run is readable in the next
 */
TEST(data_persists_across_runs) {
    const char *js_code =
        "var invocation = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);\n"
        "    invocation++;\n"
        "    if (invocation === 1) {\n"
        "        var val = new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x00,\n"
        "                                  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);\n"
        "        maps.myhash.update(keyBuf, val);\n"
        "        return 1;  /* First run: wrote data */\n"
        "    } else {\n"
        "        var outBuf = new Uint8Array(16);\n"
        "        if (!maps.myhash.lookup(keyBuf, outBuf)) return -1;\n"
        "        if (outBuf[0] !== 0xCA) return -2;\n"
        "        if (outBuf[1] !== 0xFE) return -3;\n"
        "        if (outBuf[15] !== 0x88) return -4;\n"
        "        return 2;  /* Second run: data verified */\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;

    /* First run: write data */
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);  /* Wrote data */

    /* Second run: verify data */
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);  /* Data verified */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 14: Hash collision handling - multiple keys hashing to same bucket
 *
 * Verification: Keys that collide are handled correctly with linear probing.
 * We create keys that have distinct values but force them into similar
 * hash ranges by having a small max_entries (8). This increases collision probability.
 */
TEST(collision_handling) {
    /* Use a small map to increase collision probability */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 6 entries into a map with 8 slots - high collision chance */\n"
        "    var entries = [\n"
        "        { key: new Uint8Array([0x00, 0x00, 0x00, 0x00]), val: 0x11 },\n"
        "        { key: new Uint8Array([0x01, 0x00, 0x00, 0x00]), val: 0x22 },\n"
        "        { key: new Uint8Array([0x02, 0x00, 0x00, 0x00]), val: 0x33 },\n"
        "        { key: new Uint8Array([0x03, 0x00, 0x00, 0x00]), val: 0x44 },\n"
        "        { key: new Uint8Array([0x08, 0x00, 0x00, 0x00]), val: 0x55 },\n"  /* likely collides */
        "        { key: new Uint8Array([0x10, 0x00, 0x00, 0x00]), val: 0x66 }\n"  /* likely collides */
        "    ];\n"
        "    \n"
        "    /* Insert all entries */\n"
        "    for (var i = 0; i < entries.length; i++) {\n"
        "        var valBuf = new Uint8Array(8);\n"
        "        valBuf[0] = entries[i].val;\n"
        "        if (!maps.myhash.update(entries[i].key, valBuf)) {\n"
        "            return -(i + 1);  /* Insert failed */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify all entries are retrievable with correct values */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    for (var i = 0; i < entries.length; i++) {\n"
        "        if (!maps.myhash.lookup(entries[i].key, outBuf)) {\n"
        "            return -(10 + i);  /* Lookup failed */\n"
        "        }\n"
        "        if (outBuf[0] !== entries[i].val) {\n"
        "            return -(20 + i);  /* Value mismatch */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return 0;  /* All entries inserted and retrieved correctly */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    /* Use small max_entries (8) to force collisions */
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 4, 8, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 15: Delete collided entries and verify correct ones removed
 *
 * Verification: When keys collide, deleting one doesn't affect others.
 */
TEST(collision_delete_correct_entry) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 4 entries into 8-slot map */\n"
        "    var key1 = new Uint8Array([0x00, 0x00, 0x00, 0x00]);\n"
        "    var key2 = new Uint8Array([0x08, 0x00, 0x00, 0x00]);  /* likely collides with key1 */\n"
        "    var key3 = new Uint8Array([0x10, 0x00, 0x00, 0x00]);  /* likely collides with key1 */\n"
        "    var key4 = new Uint8Array([0x18, 0x00, 0x00, 0x00]);  /* likely collides with key1 */\n"
        "    \n"
        "    var val1 = new Uint8Array([0x11, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    var val2 = new Uint8Array([0x22, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    var val3 = new Uint8Array([0x33, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    var val4 = new Uint8Array([0x44, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    \n"
        "    /* Insert all */\n"
        "    maps.myhash.update(key1, val1);\n"
        "    maps.myhash.update(key2, val2);\n"
        "    maps.myhash.update(key3, val3);\n"
        "    maps.myhash.update(key4, val4);\n"
        "    \n"
        "    /* Delete the middle entry (key2) */\n"
        "    if (!maps.myhash.delete(key2)) return -1;\n"
        "    \n"
        "    /* Verify key2 is gone */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    if (maps.myhash.lookup(key2, outBuf)) return -2;  /* Should not be found */\n"
        "    \n"
        "    /* Verify other keys still accessible with correct values */\n"
        "    if (!maps.myhash.lookup(key1, outBuf)) return -3;\n"
        "    if (outBuf[0] !== 0x11) return -4;\n"
        "    \n"
        "    if (!maps.myhash.lookup(key3, outBuf)) return -5;\n"
        "    if (outBuf[0] !== 0x33) return -6;\n"
        "    \n"
        "    if (!maps.myhash.lookup(key4, outBuf)) return -7;\n"
        "    if (outBuf[0] !== 0x44) return -8;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 4, 8, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 16: Lookup finds correct entry when probe chain has tombstones
 *
 * Verification: After delete, lookup still finds entries past tombstones.
 */
TEST(collision_lookup_past_tombstone) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Create keys that likely collide */\n"
        "    var keys = [];\n"
        "    var vals = [];\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        keys[i] = new Uint8Array([i * 8, 0, 0, 0]);\n"
        "        vals[i] = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    }\n"
        "    \n"
        "    /* Insert all */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        maps.myhash.update(keys[i], vals[i]);\n"
        "    }\n"
        "    \n"
        "    /* Delete keys[1] and keys[2] (middle of chain) */\n"
        "    maps.myhash.delete(keys[1]);\n"
        "    maps.myhash.delete(keys[2]);\n"
        "    \n"
        "    /* Verify keys[3] and keys[4] are still findable past tombstones */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    if (!maps.myhash.lookup(keys[3], outBuf)) return -1;\n"
        "    if (outBuf[0] !== 0x13) return -2;\n"
        "    \n"
        "    if (!maps.myhash.lookup(keys[4], outBuf)) return -3;\n"
        "    if (outBuf[0] !== 0x14) return -4;\n"
        "    \n"
        "    /* Also verify keys[0] is still there */\n"
        "    if (!maps.myhash.lookup(keys[0], outBuf)) return -5;\n"
        "    if (outBuf[0] !== 0x10) return -6;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 4, 8, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 17: High load - fill map to near capacity and verify integrity
 *
 * Verification: Map works correctly when nearly full.
 */
TEST(high_load_no_corruption) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Fill map with 90 entries (max_entries=100) */\n"
        "    var insertCount = 90;\n"
        "    var deleteCount = 30;\n"
        "    \n"
        "    /* Insert entries */\n"
        "    for (var i = 0; i < insertCount; i++) {\n"
        "        var key = new Uint8Array([\n"
        "            i & 0xFF, (i >> 8) & 0xFF, 0, 0, 0, 0, 0, 0\n"
        "        ]);\n"
        "        var val = new Uint8Array([\n"
        "            (i * 3) & 0xFF, ((i * 3) >> 8) & 0xFF, 0, 0, 0, 0, 0, 0,\n"
        "            0, 0, 0, 0, 0, 0, 0, 0\n"
        "        ]);\n"
        "        if (!maps.myhash.update(key, val)) {\n"
        "            return -(1000 + i);  /* Insert failed */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify all entries */\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    for (var i = 0; i < insertCount; i++) {\n"
        "        var key = new Uint8Array([\n"
        "            i & 0xFF, (i >> 8) & 0xFF, 0, 0, 0, 0, 0, 0\n"
        "        ]);\n"
        "        if (!maps.myhash.lookup(key, outBuf)) {\n"
        "            return -(2000 + i);  /* Lookup failed */\n"
        "        }\n"
        "        var expected = (i * 3) & 0xFF;\n"
        "        if (outBuf[0] !== expected) {\n"
        "            return -(3000 + i);  /* Value mismatch */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Delete some entries (indices 10-39) */\n"
        "    for (var i = 10; i < 10 + deleteCount; i++) {\n"
        "        var key = new Uint8Array([\n"
        "            i & 0xFF, (i >> 8) & 0xFF, 0, 0, 0, 0, 0, 0\n"
        "        ]);\n"
        "        if (!maps.myhash.delete(key)) {\n"
        "            return -(4000 + i);  /* Delete failed */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify deleted entries are gone */\n"
        "    for (var i = 10; i < 10 + deleteCount; i++) {\n"
        "        var key = new Uint8Array([\n"
        "            i & 0xFF, (i >> 8) & 0xFF, 0, 0, 0, 0, 0, 0\n"
        "        ]);\n"
        "        if (maps.myhash.lookup(key, outBuf)) {\n"
        "            return -(5000 + i);  /* Should be deleted */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify non-deleted entries are still correct */\n"
        "    for (var i = 0; i < 10; i++) {\n"
        "        var key = new Uint8Array([\n"
        "            i & 0xFF, (i >> 8) & 0xFF, 0, 0, 0, 0, 0, 0\n"
        "        ]);\n"
        "        if (!maps.myhash.lookup(key, outBuf)) {\n"
        "            return -(6000 + i);\n"
        "        }\n"
        "        var expected = (i * 3) & 0xFF;\n"
        "        if (outBuf[0] !== expected) {\n"
        "            return -(7000 + i);\n"
        "        }\n"
        "    }\n"
        "    for (var i = 40; i < insertCount; i++) {\n"
        "        var key = new Uint8Array([\n"
        "            i & 0xFF, (i >> 8) & 0xFF, 0, 0, 0, 0, 0, 0\n"
        "        ]);\n"
        "        if (!maps.myhash.lookup(key, outBuf)) {\n"
        "            return -(8000 + i);\n"
        "        }\n"
        "        var expected = (i * 3) & 0xFF;\n"
        "        if (outBuf[0] !== expected) {\n"
        "            return -(9000 + i);\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 18: Insert after delete reuses tombstone slot
 *
 * Verification: Inserting a new key after deletions can use tombstone slots.
 */
TEST(insert_reuses_tombstone) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Fill map with 6 entries */\n"
        "    for (var i = 0; i < 6; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.myhash.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Delete entries 2, 3, 4 */\n"
        "    for (var i = 2; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        maps.myhash.delete(key);\n"
        "    }\n"
        "    \n"
        "    /* Insert new entries 10, 11, 12 - should reuse tombstones */\n"
        "    for (var i = 10; i < 13; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0xA0 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        if (!maps.myhash.update(key, val)) {\n"
        "            return -(i + 100);  /* Insert failed */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify new entries */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    for (var i = 10; i < 13; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.myhash.lookup(key, outBuf)) {\n"
        "            return -(i + 200);\n"
        "        }\n"
        "        if (outBuf[0] !== 0xA0 + i) {\n"
        "            return -(i + 300);\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify original remaining entries (0, 1, 5) */\n"
        "    var remaining = [0, 1, 5];\n"
        "    for (var j = 0; j < remaining.length; j++) {\n"
        "        var i = remaining[j];\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.myhash.lookup(key, outBuf)) {\n"
        "            return -(i + 400);\n"
        "        }\n"
        "        if (outBuf[0] !== 0x10 + i) {\n"
        "            return -(i + 500);\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 4, 8, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 19: Re-insert after delete (tombstone handling)
 *
 * Verification: Can re-insert a key after it has been deleted
 */
TEST(reinsert_after_delete) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var val1 = new Uint8Array([0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,\n"
        "                               0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]);\n"
        "    var val2 = new Uint8Array([0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,\n"
        "                               0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22]);\n"
        "    \n"
        "    /* Insert, delete, re-insert */\n"
        "    maps.myhash.update(keyBuf, val1);\n"
        "    maps.myhash.delete(keyBuf);\n"
        "    maps.myhash.update(keyBuf, val2);\n"
        "    \n"
        "    /* Verify the new value */\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    if (!maps.myhash.lookup(keyBuf, outBuf)) return -1;\n"
        "    if (outBuf[0] !== 0x22) return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "myhash", 8, 16, 100);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

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

    printf("microBPF Hash Map Tests\n");
    printf("=======================\n");

    printf("\nMap creation tests:\n");
    RUN_TEST(map_created);

    printf("\nLookup tests:\n");
    RUN_TEST(lookup_returns_false_initially);
    RUN_TEST(lookup_returns_correct_data);

    printf("\nUpdate tests:\n");
    RUN_TEST(update_succeeds);
    RUN_TEST(update_overwrites_value);

    printf("\nDelete tests:\n");
    RUN_TEST(delete_returns_true);
    RUN_TEST(lookup_returns_false_after_delete);
    RUN_TEST(delete_nonexistent_returns_false);
    RUN_TEST(reinsert_after_delete);

    printf("\nCollision handling tests:\n");
    RUN_TEST(collision_handling);
    RUN_TEST(collision_delete_correct_entry);
    RUN_TEST(collision_lookup_past_tombstone);
    RUN_TEST(insert_reuses_tombstone);

    printf("\nHigh load tests:\n");
    RUN_TEST(high_load_no_corruption);

    printf("\nMultiple entries test:\n");
    RUN_TEST(multiple_entries);

    printf("\nType checking tests:\n");
    RUN_TEST(type_check_key);
    RUN_TEST(key_size_check);
    RUN_TEST(value_size_check);

    printf("\nPersistence tests:\n");
    RUN_TEST(data_persists_across_runs);

    printf("\n=======================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
