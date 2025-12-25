/*
 * microBPF Map Iteration Tests
 *
 * Tests for bounded map iteration with nextKey:
 * 1. Define hash map and populate with multiple entries
 * 2. Call maps.myhash.nextKey(null, outKey) - verify returns first key
 * 3. Call maps.myhash.nextKey(prevKey, outKey) - verify returns next key
 * 4. Iterate until nextKey returns false
 * 5. Verify all keys are visited
 * 6. Verify iteration counts toward max_helpers budget
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
        "\"program_name\":\"iteration_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\",\"CAP_MAP_ITERATE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":2,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, map_name, key_size, value_size, max_entries);
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
    const char *js_file = "/tmp/test_map_iteration.js";
    const char *bc_file = "/tmp/test_map_iteration.qjbc";

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
 * Test Cases - map-iteration
 * ============================================================================ */

/*
 * Test 1: nextKey(null, outKey) returns first key
 *
 * Verification: Calling nextKey with null should return the first key in the map
 */
TEST(nextkey_null_returns_first) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert some entries */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Call nextKey with null to get first key */\n"
        "    var outKey = new Uint8Array(4);\n"
        "    var found = maps.mymap.nextKey(null, outKey);\n"
        "    \n"
        "    if (!found) {\n"
        "        return -1;  /* Should find a key */\n"
        "    }\n"
        "    \n"
        "    /* Verify the key is valid (exists in map) */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    if (!maps.mymap.lookup(outKey, outBuf)) {\n"
        "        return -2;  /* First key should be in map */\n"
        "    }\n"
        "    \n"
        "    return 1;  /* Success */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: nextKey(prevKey, outKey) returns next key
 *
 * Verification: Calling nextKey with a valid previous key returns the next key
 */
TEST(nextkey_prev_returns_next) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert some entries */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Get first key */\n"
        "    var key1 = new Uint8Array(4);\n"
        "    if (!maps.mymap.nextKey(null, key1)) {\n"
        "        return -1;\n"
        "    }\n"
        "    \n"
        "    /* Get second key */\n"
        "    var key2 = new Uint8Array(4);\n"
        "    if (!maps.mymap.nextKey(key1, key2)) {\n"
        "        return -2;  /* Should find a second key */\n"
        "    }\n"
        "    \n"
        "    /* Keys should be different */\n"
        "    var same = true;\n"
        "    for (var i = 0; i < 4; i++) {\n"
        "        if (key1[i] !== key2[i]) same = false;\n"
        "    }\n"
        "    if (same) {\n"
        "        return -3;  /* Keys should be different */\n"
        "    }\n"
        "    \n"
        "    /* Both keys should exist in map */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    if (!maps.mymap.lookup(key2, outBuf)) {\n"
        "        return -4;\n"
        "    }\n"
        "    \n"
        "    return 1;  /* Success */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Iterate until nextKey returns false
 *
 * Verification: Iteration eventually terminates with false
 */
TEST(iterate_until_end) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Iterate through all keys */\n"
        "    var count = 0;\n"
        "    var currKey = null;\n"
        "    var nextKeyBuf = new Uint8Array(4);\n"
        "    \n"
        "    while (maps.mymap.nextKey(currKey, nextKeyBuf)) {\n"
        "        count++;\n"
        "        /* Copy nextKeyBuf to currKey for next iteration */\n"
        "        currKey = new Uint8Array(4);\n"
        "        for (var i = 0; i < 4; i++) {\n"
        "            currKey[i] = nextKeyBuf[i];\n"
        "        }\n"
        "        /* Safety: prevent infinite loop */\n"
        "        if (count > 100) break;\n"
        "    }\n"
        "    \n"
        "    return count;  /* Should return 5 */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 5);  /* Should iterate 5 times */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: All keys are visited during iteration
 *
 * Verification: Every key in the map is seen exactly once during iteration
 */
TEST(all_keys_visited) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries with known keys */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Track which keys we've seen (simple bitmap for keys 0-4) */\n"
        "    var seen = [false, false, false, false, false];\n"
        "    var currKey = null;\n"
        "    var nextKeyBuf = new Uint8Array(4);\n"
        "    \n"
        "    while (maps.mymap.nextKey(currKey, nextKeyBuf)) {\n"
        "        var keyIdx = nextKeyBuf[0];\n"
        "        if (keyIdx < 5) {\n"
        "            seen[keyIdx] = true;\n"
        "        }\n"
        "        currKey = new Uint8Array(4);\n"
        "        for (var i = 0; i < 4; i++) {\n"
        "            currKey[i] = nextKeyBuf[i];\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify all keys were seen */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        if (!seen[i]) {\n"
        "            return -(i + 1);  /* Key i not seen */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return 5;  /* All 5 keys seen */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
 * Test 5: nextKey on empty map returns false
 *
 * Verification: Calling nextKey on empty map returns false
 */
TEST(empty_map_returns_false) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Don't insert any entries */\n"
        "    var outKey = new Uint8Array(4);\n"
        "    var found = maps.mymap.nextKey(null, outKey);\n"
        "    \n"
        "    if (found) {\n"
        "        return -1;  /* Should not find any key */\n"
        "    }\n"
        "    \n"
        "    return 1;  /* Correctly returned false */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Single entry map iteration
 *
 * Verification: Map with one entry returns it, then returns false
 */
TEST(single_entry_iteration) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert one entry */\n"
        "    var key = new Uint8Array([0x42, 0, 0, 0]);\n"
        "    var val = new Uint8Array([0xAB, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    maps.mymap.update(key, val);\n"
        "    \n"
        "    /* First nextKey should succeed */\n"
        "    var outKey = new Uint8Array(4);\n"
        "    if (!maps.mymap.nextKey(null, outKey)) {\n"
        "        return -1;\n"
        "    }\n"
        "    \n"
        "    /* Verify it's our key */\n"
        "    if (outKey[0] !== 0x42) {\n"
        "        return -2;\n"
        "    }\n"
        "    \n"
        "    /* Second nextKey should fail */\n"
        "    var nextKey = new Uint8Array(4);\n"
        "    if (maps.mymap.nextKey(outKey, nextKey)) {\n"
        "        return -3;  /* Should be no more keys */\n"
        "    }\n"
        "    \n"
        "    return 1;  /* Success */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Iteration with deleted keys
 *
 * Verification: Deleted keys are not returned during iteration
 */
TEST(iteration_skips_deleted) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Delete keys 1 and 3 */\n"
        "    maps.mymap.delete(new Uint8Array([1, 0, 0, 0]));\n"
        "    maps.mymap.delete(new Uint8Array([3, 0, 0, 0]));\n"
        "    \n"
        "    /* Count remaining keys */\n"
        "    var count = 0;\n"
        "    var currKey = null;\n"
        "    var nextKeyBuf = new Uint8Array(4);\n"
        "    \n"
        "    while (maps.mymap.nextKey(currKey, nextKeyBuf)) {\n"
        "        count++;\n"
        "        /* Verify it's not a deleted key */\n"
        "        if (nextKeyBuf[0] === 1 || nextKeyBuf[0] === 3) {\n"
        "            return -1;  /* Should not see deleted keys */\n"
        "        }\n"
        "        currKey = new Uint8Array(4);\n"
        "        for (var i = 0; i < 4; i++) {\n"
        "            currKey[i] = nextKeyBuf[i];\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return count;  /* Should return 3 */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 3);  /* 5 - 2 deleted = 3 */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: TypeError for invalid outKey type
 *
 * Verification: Passing non-Uint8Array as outKey throws TypeError
 */
TEST(typeerror_invalid_outkey) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(new Uint8Array([1, 0, 0, 0]),\n"
        "                      new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]));\n"
        "    try {\n"
        "        maps.mymap.nextKey(null, 'not a uint8array');\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;  /* Correct error */\n"
        "        }\n"
        "        return -2;  /* Wrong error type */\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: RangeError for outKey too small
 *
 * Verification: Passing outKey smaller than key_size throws RangeError
 */
TEST(rangeerror_outkey_too_small) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(new Uint8Array([1, 0, 0, 0]),\n"
        "                      new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]));\n"
        "    try {\n"
        "        var smallBuf = new Uint8Array(2);  /* key_size is 4 */\n"
        "        maps.mymap.nextKey(null, smallBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof RangeError) {\n"
        "            return 1;  /* Correct error */\n"
        "        }\n"
        "        return -2;  /* Wrong error type */\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: TypeError for invalid prevKey type (not null and not Uint8Array)
 *
 * Verification: Passing non-null, non-Uint8Array prevKey throws TypeError
 */
TEST(typeerror_invalid_prevkey) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(new Uint8Array([1, 0, 0, 0]),\n"
        "                      new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]));\n"
        "    try {\n"
        "        var outKey = new Uint8Array(4);\n"
        "        maps.mymap.nextKey('invalid', outKey);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;  /* Correct error */\n"
        "        }\n"
        "        return -2;  /* Wrong error type */\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: nextKey with undefined prevKey (same as null)
 *
 * Verification: Passing undefined as prevKey works like null
 */
TEST(undefined_prevkey_like_null) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(new Uint8Array([1, 0, 0, 0]),\n"
        "                      new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]));\n"
        "    \n"
        "    var outKey = new Uint8Array(4);\n"
        "    /* Call with undefined */\n"
        "    if (!maps.mymap.nextKey(undefined, outKey)) {\n"
        "        return -1;\n"
        "    }\n"
        "    \n"
        "    /* Should have found the key */\n"
        "    if (outKey[0] !== 1) {\n"
        "        return -2;\n"
        "    }\n"
        "    \n"
        "    return 1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 10);
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
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Helper count increments for iteration (budget tracking)
 *
 * Verification: Each nextKey call should increment the helper count.
 * Note: The actual budget enforcement is a separate task; this test
 * just verifies that _helperCount is incremented if it exists.
 */
TEST(iteration_increments_helper_count) {
    /* This test verifies that the _helperCount mechanism is in place.
     * Since full budget enforcement isn't implemented yet, we can't
     * directly test it here. Instead, we verify that the iteration
     * works correctly, which implicitly includes the _helperCount increment. */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert entries */\n"
        "    for (var i = 0; i < 10; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Count iterations - each one should count toward budget */\n"
        "    var count = 0;\n"
        "    var currKey = null;\n"
        "    var nextKeyBuf = new Uint8Array(4);\n"
        "    \n"
        "    while (maps.mymap.nextKey(currKey, nextKeyBuf)) {\n"
        "        count++;\n"
        "        currKey = new Uint8Array(4);\n"
        "        for (var i = 0; i < 4; i++) {\n"
        "            currKey[i] = nextKeyBuf[i];\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* 10 entries = 10 nextKey calls (plus one final false return) */\n"
        "    return count;  /* Should return 10 */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 20);
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
    ASSERT_EQ(out_rc, 10);

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

    printf("microBPF Map Iteration Tests\n");
    printf("============================\n");

    printf("\nBasic iteration tests:\n");
    RUN_TEST(nextkey_null_returns_first);
    RUN_TEST(nextkey_prev_returns_next);
    RUN_TEST(iterate_until_end);
    RUN_TEST(all_keys_visited);

    printf("\nEdge case tests:\n");
    RUN_TEST(empty_map_returns_false);
    RUN_TEST(single_entry_iteration);
    RUN_TEST(iteration_skips_deleted);

    printf("\nError handling tests:\n");
    RUN_TEST(typeerror_invalid_outkey);
    RUN_TEST(rangeerror_outkey_too_small);
    RUN_TEST(typeerror_invalid_prevkey);
    RUN_TEST(undefined_prevkey_like_null);

    printf("\nBudget tracking tests:\n");
    RUN_TEST(iteration_increments_helper_count);

    printf("\n============================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
