/*
 * microBPF LRU Hash Map Tests
 *
 * Tests for LRU hash map type with eviction behavior:
 * 1. Define LRU hash map in manifest
 * 2. Fill map to capacity
 * 3. Insert new entry - verify oldest/least-used is evicted
 * 4. Access entries to update LRU order
 * 5. Verify most recently accessed entries are retained
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
        printf("FAIL (code %d)\n", result); \
        failed++; \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("ASSERT FAILED: " #cond " at line %d\n", __LINE__); return -1; } } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Helper to build a manifest with LRU hash map definition */
static size_t build_manifest_with_lru_map(uint8_t *buf, size_t cap, int hook_type,
                                           const char *map_name, uint32_t key_size,
                                           uint32_t value_size, uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"lru_map_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":3,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and LRU hash map */
static size_t build_mbpf_package_with_lru_map(uint8_t *buf, size_t cap,
                                               const uint8_t *bytecode, size_t bc_len,
                                               int hook_type,
                                               const char *map_name, uint32_t key_size,
                                               uint32_t value_size, uint32_t max_entries) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_lru_map(manifest, sizeof(manifest),
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
    const char *js_file = "/tmp/test_lru_map.js";
    const char *bc_file = "/tmp/test_lru_map.qjbc";

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
 * Test Cases - map-lru-hash
 * ============================================================================ */

/*
 * Test 1: Define LRU hash map in manifest and load
 *
 * Verification: Map is created and can be accessed
 */
TEST(lru_map_created) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Verify map exists */\n"
        "    if (!maps.lrumap) return -1;\n"
        "    if (typeof maps.lrumap.lookup !== 'function') return -2;\n"
        "    if (typeof maps.lrumap.update !== 'function') return -3;\n"
        "    if (typeof maps.lrumap.delete !== 'function') return -4;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Fill map to capacity
 *
 * Verification: Insert max_entries items, all succeed
 */
TEST(fill_to_capacity) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries to fill the map */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        if (!maps.lrumap.update(key, val)) {\n"
        "            return -(i + 1);  /* Insert failed */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify all entries exist */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.lrumap.lookup(key, outBuf)) {\n"
        "            return -(i + 10);  /* Lookup failed */\n"
        "        }\n"
        "        if (outBuf[0] !== 0x10 + i) {\n"
        "            return -(i + 20);  /* Wrong value */\n"
        "        }\n"
        "    }\n"
        "    return 5;  /* All 5 entries work */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 5);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Insert when full evicts oldest entry (LRU)
 *
 * Verification: After filling, new insert evicts the first entry added
 */
TEST(insert_evicts_oldest) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries (indices 0-4) */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        if (!maps.lrumap.update(key, val)) {\n"
        "            return -(i + 1);\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Insert 6th entry (key=10) - should evict key=0 (oldest) */\n"
        "    var key6 = new Uint8Array([10, 0, 0, 0]);\n"
        "    var val6 = new Uint8Array([0xAA, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (!maps.lrumap.update(key6, val6)) {\n"
        "        return -100;  /* Insert should succeed with eviction */\n"
        "    }\n"
        "    \n"
        "    /* Verify key=0 is gone (was evicted) */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    var key0 = new Uint8Array([0, 0, 0, 0]);\n"
        "    if (maps.lrumap.lookup(key0, outBuf)) {\n"
        "        return -101;  /* Key 0 should have been evicted */\n"
        "    }\n"
        "    \n"
        "    /* Verify key=10 exists with correct value */\n"
        "    if (!maps.lrumap.lookup(key6, outBuf)) {\n"
        "        return -102;  /* Key 10 should exist */\n"
        "    }\n"
        "    if (outBuf[0] !== 0xAA) {\n"
        "        return -103;  /* Key 10 has wrong value */\n"
        "    }\n"
        "    \n"
        "    /* Verify keys 1-4 still exist */\n"
        "    for (var i = 1; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.lrumap.lookup(key, outBuf)) {\n"
        "            return -(i + 200);  /* Key i should still exist */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Lookup updates LRU order
 *
 * Verification: Accessed entries are moved to MRU position and not evicted
 */
TEST(lookup_updates_lru_order) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries (0-4), so LRU order is: 0(oldest), 1, 2, 3, 4(newest) */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.lrumap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Access key=0 to move it to MRU (most recently used) */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    var key0 = new Uint8Array([0, 0, 0, 0]);\n"
        "    if (!maps.lrumap.lookup(key0, outBuf)) {\n"
        "        return -1;  /* Key 0 lookup failed */\n"
        "    }\n"
        "    \n"
        "    /* Now LRU order should be: 1(oldest), 2, 3, 4, 0(newest) */\n"
        "    /* Insert new entry - should evict key=1 (now the oldest) */\n"
        "    var key10 = new Uint8Array([10, 0, 0, 0]);\n"
        "    var val10 = new Uint8Array([0xBB, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (!maps.lrumap.update(key10, val10)) {\n"
        "        return -2;  /* Insert should succeed */\n"
        "    }\n"
        "    \n"
        "    /* Verify key=0 still exists (because it was accessed) */\n"
        "    if (!maps.lrumap.lookup(key0, outBuf)) {\n"
        "        return -3;  /* Key 0 should still exist */\n"
        "    }\n"
        "    if (outBuf[0] !== 0x10) {\n"
        "        return -4;  /* Key 0 has wrong value */\n"
        "    }\n"
        "    \n"
        "    /* Verify key=1 was evicted (was oldest after key=0 accessed) */\n"
        "    var key1 = new Uint8Array([1, 0, 0, 0]);\n"
        "    if (maps.lrumap.lookup(key1, outBuf)) {\n"
        "        return -5;  /* Key 1 should have been evicted */\n"
        "    }\n"
        "    \n"
        "    /* Verify key=10 exists */\n"
        "    if (!maps.lrumap.lookup(key10, outBuf)) {\n"
        "        return -6;  /* Key 10 should exist */\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Most recently accessed entries are retained
 *
 * Verification: Access multiple entries in specific order, verify correct eviction
 */
TEST(recently_accessed_retained) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries (0-4) */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.lrumap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Access keys in order: 4, 3, 2, 1, 0 */\n"
        "    /* After this, LRU order is: 4(oldest), 3, 2, 1, 0(newest) */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    for (var i = 4; i >= 0; i--) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        maps.lrumap.lookup(key, outBuf);\n"
        "    }\n"
        "    \n"
        "    /* Insert 3 new entries (10, 11, 12) - should evict 4, 3, 2 */\n"
        "    for (var i = 10; i < 13; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.lrumap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Verify 4, 3, 2 are evicted */\n"
        "    for (var i = 4; i >= 2; i--) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (maps.lrumap.lookup(key, outBuf)) {\n"
        "            return -(i + 100);  /* Should have been evicted */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify 0, 1 still exist (most recently accessed) */\n"
        "    for (var i = 0; i < 2; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.lrumap.lookup(key, outBuf)) {\n"
        "            return -(i + 200);  /* Should still exist */\n"
        "        }\n"
        "        if (outBuf[0] !== i) {\n"
        "            return -(i + 300);\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify 10, 11, 12 exist */\n"
        "    for (var i = 10; i < 13; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.lrumap.lookup(key, outBuf)) {\n"
        "            return -(i + 400);\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Update existing key moves to MRU
 *
 * Verification: Updating an existing entry refreshes its LRU position
 */
TEST(update_moves_to_mru) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries (0-4) */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.lrumap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Update key=0 (the oldest) with new value */\n"
        "    var key0 = new Uint8Array([0, 0, 0, 0]);\n"
        "    var newVal = new Uint8Array([0xFF, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (!maps.lrumap.update(key0, newVal)) {\n"
        "        return -1;\n"
        "    }\n"
        "    \n"
        "    /* Now LRU order: 1(oldest), 2, 3, 4, 0(newest) */\n"
        "    /* Insert new entry - should evict key=1 */\n"
        "    var key10 = new Uint8Array([10, 0, 0, 0]);\n"
        "    var val10 = new Uint8Array([0xCC, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    maps.lrumap.update(key10, val10);\n"
        "    \n"
        "    /* Verify key=0 still exists with updated value */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    if (!maps.lrumap.lookup(key0, outBuf)) {\n"
        "        return -2;\n"
        "    }\n"
        "    if (outBuf[0] !== 0xFF) {\n"
        "        return -3;  /* Value should be updated */\n"
        "    }\n"
        "    \n"
        "    /* Verify key=1 was evicted */\n"
        "    var key1 = new Uint8Array([1, 0, 0, 0]);\n"
        "    if (maps.lrumap.lookup(key1, outBuf)) {\n"
        "        return -4;  /* Key 1 should be evicted */\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Delete removes from LRU list
 *
 * Verification: Deleted entries don't affect eviction order
 */
TEST(delete_removes_from_lru) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries (0-4) */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.lrumap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Delete key=0 (oldest) */\n"
        "    var key0 = new Uint8Array([0, 0, 0, 0]);\n"
        "    if (!maps.lrumap.delete(key0)) {\n"
        "        return -1;\n"
        "    }\n"
        "    \n"
        "    /* Now we have 4 entries: 1(oldest), 2, 3, 4(newest) */\n"
        "    /* Insert new entry - should NOT trigger eviction (we have room) */\n"
        "    var key10 = new Uint8Array([10, 0, 0, 0]);\n"
        "    var val10 = new Uint8Array([0xDD, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (!maps.lrumap.update(key10, val10)) {\n"
        "        return -2;\n"
        "    }\n"
        "    \n"
        "    /* All of 1-4 and 10 should exist */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    for (var i = 1; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.lrumap.lookup(key, outBuf)) {\n"
        "            return -(i + 100);\n"
        "        }\n"
        "    }\n"
        "    if (!maps.lrumap.lookup(key10, outBuf)) {\n"
        "        return -200;\n"
        "    }\n"
        "    \n"
        "    /* Key=0 should not exist (deleted) */\n"
        "    if (maps.lrumap.lookup(key0, outBuf)) {\n"
        "        return -300;\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Multiple evictions in sequence
 *
 * Verification: Evictions happen correctly one after another
 */
TEST(multiple_evictions) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries (0-4) */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.lrumap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Insert 5 more entries (10-14), evicting 0-4 one by one */\n"
        "    for (var i = 10; i < 15; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        if (!maps.lrumap.update(key, val)) {\n"
        "            return -(i);\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify all 0-4 are gone */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (maps.lrumap.lookup(key, outBuf)) {\n"
        "            return -(i + 100);  /* Should be evicted */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify all 10-14 exist */\n"
        "    for (var i = 10; i < 15; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.lrumap.lookup(key, outBuf)) {\n"
        "            return -(i + 200);  /* Should exist */\n"
        "        }\n"
        "        if (outBuf[0] !== i) {\n"
        "            return -(i + 300);  /* Wrong value */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: max_entries=1 edge case
 *
 * Verification: Single entry map with LRU eviction
 */
TEST(max_entries_one) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert entry 0 */\n"
        "    var key0 = new Uint8Array([0, 0, 0, 0]);\n"
        "    var val0 = new Uint8Array([0xAA, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (!maps.lrumap.update(key0, val0)) {\n"
        "        return -1;\n"
        "    }\n"
        "    \n"
        "    /* Verify entry 0 exists */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    if (!maps.lrumap.lookup(key0, outBuf) || outBuf[0] !== 0xAA) {\n"
        "        return -2;\n"
        "    }\n"
        "    \n"
        "    /* Insert entry 1 - should evict entry 0 */\n"
        "    var key1 = new Uint8Array([1, 0, 0, 0]);\n"
        "    var val1 = new Uint8Array([0xBB, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (!maps.lrumap.update(key1, val1)) {\n"
        "        return -3;\n"
        "    }\n"
        "    \n"
        "    /* Verify entry 0 is gone */\n"
        "    if (maps.lrumap.lookup(key0, outBuf)) {\n"
        "        return -4;\n"
        "    }\n"
        "    \n"
        "    /* Verify entry 1 exists */\n"
        "    if (!maps.lrumap.lookup(key1, outBuf) || outBuf[0] !== 0xBB) {\n"
        "        return -5;\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 1);  /* max_entries=1 */
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
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Type validation same as hash map
 *
 * Verification: LRU map validates key/value types correctly
 */
TEST(type_validation) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    var key = new Uint8Array([0, 0, 0, 0]);\n"
        "    var val = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);\n"
        "    \n"
        "    /* Test wrong key type */\n"
        "    try {\n"
        "        maps.lrumap.lookup('badkey', outBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e1) {\n"
        "        if (!(e1 instanceof TypeError)) return -2;\n"
        "    }\n"
        "    \n"
        "    /* Test wrong value type */\n"
        "    try {\n"
        "        maps.lrumap.update(key, 'badvalue');\n"
        "        return -3;  /* Should have thrown */\n"
        "    } catch (e2) {\n"
        "        if (!(e2 instanceof TypeError)) return -4;\n"
        "    }\n"
        "    \n"
        "    /* Test key too small */\n"
        "    try {\n"
        "        var smallKey = new Uint8Array([0, 0]);\n"
        "        maps.lrumap.lookup(smallKey, outBuf);\n"
        "        return -5;  /* Should have thrown */\n"
        "    } catch (e3) {\n"
        "        if (!(e3 instanceof RangeError)) return -6;\n"
        "    }\n"
        "    \n"
        "    /* Test value too small */\n"
        "    try {\n"
        "        var smallVal = new Uint8Array([1, 2]);\n"
        "        maps.lrumap.update(key, smallVal);\n"
        "        return -7;  /* Should have thrown */\n"
        "    } catch (e4) {\n"
        "        if (!(e4 instanceof RangeError)) return -8;\n"
        "    }\n"
        "    \n"
        "    /* Valid operations should work */\n"
        "    if (!maps.lrumap.update(key, val)) return -9;\n"
        "    if (!maps.lrumap.lookup(key, outBuf)) return -10;\n"
        "    if (outBuf[0] !== 1) return -11;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_lru_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      "lrumap", 4, 8, 5);
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

    printf("microBPF LRU Hash Map Tests\n");
    printf("===========================\n");

    printf("\nMap creation tests:\n");
    RUN_TEST(lru_map_created);

    printf("\nBasic LRU behavior tests:\n");
    RUN_TEST(fill_to_capacity);
    RUN_TEST(insert_evicts_oldest);

    printf("\nLRU order update tests:\n");
    RUN_TEST(lookup_updates_lru_order);
    RUN_TEST(recently_accessed_retained);
    RUN_TEST(update_moves_to_mru);

    printf("\nDelete and eviction tests:\n");
    RUN_TEST(delete_removes_from_lru);
    RUN_TEST(multiple_evictions);

    printf("\nEdge cases:\n");
    RUN_TEST(max_entries_one);
    RUN_TEST(type_validation);

    printf("\n===========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
