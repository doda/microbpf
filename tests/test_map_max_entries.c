/*
 * microBPF Map Max Entries Tests
 *
 * Tests for verifying map enforces max_entries limit:
 * 1. Create hash map with max_entries=5
 * 2. Insert 5 entries - verify all succeed
 * 3. Attempt to insert 6th entry - verify appropriate behavior (reject)
 * 4. Verify existing entries remain intact
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
        "\"program_name\":\"max_entries_test\","
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
    const char *js_file = "/tmp/test_max_entries.js";
    const char *bc_file = "/tmp/test_max_entries.qjbc";

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
 * Test Cases - map-max-entries
 * ============================================================================ */

/*
 * Test 1: Insert 5 entries into max_entries=5 map - all should succeed
 *
 * Verification: All 5 inserts return true
 */
TEST(insert_5_entries_succeeds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Create 5 unique keys and insert them */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        if (!maps.mymap.update(key, val)) {\n"
        "            return -(i + 1);  /* Insert i failed */\n"
        "        }\n"
        "    }\n"
        "    return 5;  /* All 5 inserts succeeded */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 5);  /* All 5 inserts succeeded */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: 6th insert fails when map is at capacity
 *
 * Verification: After inserting 5 entries, 6th insert returns false
 */
TEST(sixth_insert_fails) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries to fill the map */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        if (!maps.mymap.update(key, val)) {\n"
        "            return -(i + 1);  /* Insert failed unexpectedly */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Attempt to insert 6th entry - should fail */\n"
        "    var key6 = new Uint8Array([5, 0, 0, 0]);\n"
        "    var val6 = new Uint8Array([0x66, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    var result = maps.mymap.update(key6, val6);\n"
        "    \n"
        "    if (result) {\n"
        "        return -100;  /* 6th insert should have failed */\n"
        "    }\n"
        "    return 1;  /* Correctly rejected 6th entry */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 5);
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
    ASSERT_EQ(out_rc, 1);  /* 6th entry correctly rejected */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Existing entries remain intact after failed insert
 *
 * Verification: After 6th insert fails, original 5 entries are still accessible
 */
TEST(existing_entries_intact_after_rejection) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Attempt to insert 6th entry (should fail) */\n"
        "    var key6 = new Uint8Array([5, 0, 0, 0]);\n"
        "    var val6 = new Uint8Array([0x66, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    maps.mymap.update(key6, val6);  /* Expected to fail */\n"
        "    \n"
        "    /* Verify all original entries are still intact */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.mymap.lookup(key, outBuf)) {\n"
        "            return -(i + 10);  /* Entry i not found */\n"
        "        }\n"
        "        if (outBuf[0] !== 0x10 + i) {\n"
        "            return -(i + 20);  /* Entry i has wrong value */\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    /* Verify 6th entry was not inserted */\n"
        "    if (maps.mymap.lookup(key6, outBuf)) {\n"
        "        return -100;  /* 6th entry should not exist */\n"
        "    }\n"
        "    \n"
        "    return 0;  /* All entries intact */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 5);
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
 * Test 4: Update existing key still works at capacity
 *
 * Verification: When map is full, updating an existing key should succeed
 */
TEST(update_existing_at_capacity) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Fill the map with 5 entries */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Update an existing key (key 2) - should succeed */\n"
        "    var key2 = new Uint8Array([2, 0, 0, 0]);\n"
        "    var newVal = new Uint8Array([0xAA, 0xBB, 0, 0, 0, 0, 0, 0]);\n"
        "    if (!maps.mymap.update(key2, newVal)) {\n"
        "        return -1;  /* Update should have succeeded */\n"
        "    }\n"
        "    \n"
        "    /* Verify the updated value */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    if (!maps.mymap.lookup(key2, outBuf)) {\n"
        "        return -2;  /* Key 2 not found */\n"
        "    }\n"
        "    if (outBuf[0] !== 0xAA || outBuf[1] !== 0xBB) {\n"
        "        return -3;  /* Value not updated correctly */\n"
        "    }\n"
        "    \n"
        "    /* Verify other entries are still intact */\n"
        "    var key0 = new Uint8Array([0, 0, 0, 0]);\n"
        "    if (!maps.mymap.lookup(key0, outBuf) || outBuf[0] !== 0x10) {\n"
        "        return -4;\n"
        "    }\n"
        "    \n"
        "    var key4 = new Uint8Array([4, 0, 0, 0]);\n"
        "    if (!maps.mymap.lookup(key4, outBuf) || outBuf[0] !== 0x14) {\n"
        "        return -5;\n"
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
                                                       "mymap", 4, 8, 5);
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
 * Test 5: Delete allows new insert
 *
 * Verification: After deleting an entry, a new entry can be inserted
 */
TEST(delete_allows_new_insert) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Fill the map with 5 entries */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Verify 6th insert fails */\n"
        "    var key6 = new Uint8Array([6, 0, 0, 0]);\n"
        "    var val6 = new Uint8Array([0x66, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (maps.mymap.update(key6, val6)) {\n"
        "        return -1;  /* Should have failed */\n"
        "    }\n"
        "    \n"
        "    /* Delete entry 2 */\n"
        "    var key2 = new Uint8Array([2, 0, 0, 0]);\n"
        "    if (!maps.mymap.delete(key2)) {\n"
        "        return -2;  /* Delete should succeed */\n"
        "    }\n"
        "    \n"
        "    /* Now 6th insert should succeed (using tombstone slot) */\n"
        "    if (!maps.mymap.update(key6, val6)) {\n"
        "        return -3;  /* Insert should now succeed */\n"
        "    }\n"
        "    \n"
        "    /* Verify key6 was inserted */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    if (!maps.mymap.lookup(key6, outBuf)) {\n"
        "        return -4;  /* Key 6 not found */\n"
        "    }\n"
        "    if (outBuf[0] !== 0x66) {\n"
        "        return -5;  /* Key 6 has wrong value */\n"
        "    }\n"
        "    \n"
        "    /* Verify key2 is no longer present */\n"
        "    if (maps.mymap.lookup(key2, outBuf)) {\n"
        "        return -6;  /* Key 2 should be deleted */\n"
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
                                                       "mymap", 4, 8, 5);
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
 * Test 6: Multiple rejections at capacity
 *
 * Verification: Multiple attempts to insert beyond capacity all fail
 */
TEST(multiple_rejections) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Fill the map with 5 entries */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0x10 + i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        maps.mymap.update(key, val);\n"
        "    }\n"
        "    \n"
        "    /* Try to insert 10 more entries - all should fail */\n"
        "    var failCount = 0;\n"
        "    for (var i = 10; i < 20; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([0xAA, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        if (!maps.mymap.update(key, val)) {\n"
        "            failCount++;\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    if (failCount !== 10) {\n"
        "        return -failCount;  /* Not all inserts failed */\n"
        "    }\n"
        "    \n"
        "    return 10;  /* All 10 inserts correctly rejected */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 5);
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

/*
 * Test 7: max_entries=1 edge case
 *
 * Verification: Map with single entry works correctly
 */
TEST(max_entries_one) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert one entry */\n"
        "    var key1 = new Uint8Array([1, 0, 0, 0]);\n"
        "    var val1 = new Uint8Array([0x11, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (!maps.mymap.update(key1, val1)) {\n"
        "        return -1;  /* First insert should succeed */\n"
        "    }\n"
        "    \n"
        "    /* Try to insert second entry - should fail */\n"
        "    var key2 = new Uint8Array([2, 0, 0, 0]);\n"
        "    var val2 = new Uint8Array([0x22, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (maps.mymap.update(key2, val2)) {\n"
        "        return -2;  /* Second insert should fail */\n"
        "    }\n"
        "    \n"
        "    /* Verify first entry is still there */\n"
        "    var outBuf = new Uint8Array(8);\n"
        "    if (!maps.mymap.lookup(key1, outBuf) || outBuf[0] !== 0x11) {\n"
        "        return -3;\n"
        "    }\n"
        "    \n"
        "    /* Update first entry - should succeed */\n"
        "    var newVal = new Uint8Array([0xFF, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (!maps.mymap.update(key1, newVal)) {\n"
        "        return -4;  /* Update should succeed */\n"
        "    }\n"
        "    \n"
        "    if (!maps.mymap.lookup(key1, outBuf) || outBuf[0] !== 0xFF) {\n"
        "        return -5;\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    /* max_entries = 1 */
    size_t pkg_len = build_mbpf_package_with_hash_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 4, 8, 1);
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
 * Test 8: Verify count tracking across operations
 *
 * Verification: Insert, delete, re-insert all work correctly
 */
TEST(count_tracking) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Insert 5 entries (max) */\n"
        "    for (var i = 0; i < 5; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        if (!maps.mymap.update(key, val)) return -1;\n"
        "    }\n"
        "    \n"
        "    /* Delete 3 entries */\n"
        "    for (var i = 0; i < 3; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        if (!maps.mymap.delete(key)) return -2;\n"
        "    }\n"
        "    \n"
        "    /* Now we should be able to insert 3 new entries */\n"
        "    for (var i = 10; i < 13; i++) {\n"
        "        var key = new Uint8Array([i, 0, 0, 0]);\n"
        "        var val = new Uint8Array([i, 0, 0, 0, 0, 0, 0, 0]);\n"
        "        if (!maps.mymap.update(key, val)) return -(i + 100);\n"
        "    }\n"
        "    \n"
        "    /* 6th insert should fail (we have 5 entries again) */\n"
        "    var key6 = new Uint8Array([20, 0, 0, 0]);\n"
        "    var val6 = new Uint8Array([20, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    if (maps.mymap.update(key6, val6)) {\n"
        "        return -200;  /* Should fail */\n"
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
                                                       "mymap", 4, 8, 5);
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

    printf("microBPF Map Max Entries Tests\n");
    printf("==============================\n");

    printf("\nBasic capacity tests:\n");
    RUN_TEST(insert_5_entries_succeeds);
    RUN_TEST(sixth_insert_fails);
    RUN_TEST(existing_entries_intact_after_rejection);

    printf("\nUpdate and delete at capacity:\n");
    RUN_TEST(update_existing_at_capacity);
    RUN_TEST(delete_allows_new_insert);

    printf("\nEdge cases:\n");
    RUN_TEST(multiple_rejections);
    RUN_TEST(max_entries_one);
    RUN_TEST(count_tracking);

    printf("\n==============================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
