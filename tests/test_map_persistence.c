/*
 * microBPF Map Persistence Tests
 *
 * Tests for map persistence across program updates (hot swap):
 * 1. Load program and populate map with data
 * 2. Update program to new version
 * 3. Verify map data is preserved after update
 * 4. Verify maps are destroyed when policy requires
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

/* Helper to build a manifest with array map definition */
static size_t build_manifest_with_map(uint8_t *buf, size_t cap, int hook_type,
                                       const char *map_name, uint32_t max_entries,
                                       uint32_t value_size, const char *prog_version) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"persistence_test\","
        "\"program_version\":\"%s\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":1,\"key_size\":4,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        prog_version, hook_type, map_name, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with hash map definition */
static size_t build_manifest_with_hash_map(uint8_t *buf, size_t cap, int hook_type,
                                            const char *map_name, uint32_t max_entries,
                                            uint32_t key_size, uint32_t value_size,
                                            const char *prog_version) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"persistence_test\","
        "\"program_version\":\"%s\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":2,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        prog_version, hook_type, map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and array map */
static size_t build_mbpf_package_with_map(uint8_t *buf, size_t cap,
                                           const uint8_t *bytecode, size_t bc_len,
                                           int hook_type,
                                           const char *map_name, uint32_t max_entries,
                                           uint32_t value_size,
                                           const char *prog_version) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_map(manifest, sizeof(manifest),
                                                   hook_type, map_name,
                                                   max_entries, value_size,
                                                   prog_version);
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

/* Build a complete .mbpf package with bytecode and hash map */
static size_t build_mbpf_package_with_hash_map(uint8_t *buf, size_t cap,
                                                const uint8_t *bytecode, size_t bc_len,
                                                int hook_type,
                                                const char *map_name, uint32_t max_entries,
                                                uint32_t key_size, uint32_t value_size,
                                                const char *prog_version) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash_map(manifest, sizeof(manifest),
                                                        hook_type, map_name,
                                                        max_entries, key_size, value_size,
                                                        prog_version);
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
    const char *js_file = "/tmp/test_persistence.js";
    const char *bc_file = "/tmp/test_persistence.qjbc";

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
 * Test Cases - map-persistence
 * ============================================================================ */

/*
 * Test 1: Basic map persistence across update
 *
 * Steps:
 * 1. Load v1 program, write data to map
 * 2. Detach and update to v2 program
 * 3. Attach and verify data is still present
 */
TEST(basic_persistence) {
    /* v1 program: writes data to map */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]));\n"
        "    return 1;\n"
        "}\n";

    /* v2 program: reads data from map */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (!maps.mymap.lookup(0, buf)) return -1;\n"
        "    if (buf[0] !== 0xDE) return -2;\n"
        "    if (buf[1] !== 0xAD) return -3;\n"
        "    if (buf[2] !== 0xBE) return -4;\n"
        "    if (buf[3] !== 0xEF) return -5;\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    ASSERT_NOT_NULL(bc1);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc2);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package_with_map(pkg1, sizeof(pkg1),
                                                   bc1, bc1_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "1.0.0");
    size_t pkg2_len = build_mbpf_package_with_map(pkg2, sizeof(pkg2),
                                                   bc2, bc2_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "2.0.0");
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Load v1 and write data */
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);  /* v1 wrote data */

    /* Detach before update */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Update to v2 (maps should persist by default) */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_OK);

    /* Reattach and verify data persisted */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);  /* v2 found the data */

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/*
 * Test 2: Hash map persistence
 *
 * Verify hash maps also persist data across updates
 */
TEST(hash_map_persistence) {
    /* v1 program: writes key/value to hash map */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([0x01, 0x02, 0x03, 0x04]);\n"
        "    var val = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    maps.myhash.update(key, val);\n"
        "    return 1;\n"
        "}\n";

    /* v2 program: reads key/value from hash map */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([0x01, 0x02, 0x03, 0x04]);\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (!maps.myhash.lookup(key, buf)) return -1;\n"
        "    if (buf[0] !== 0xAA) return -2;\n"
        "    if (buf[1] !== 0xBB) return -3;\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    ASSERT_NOT_NULL(bc1);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc2);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package_with_hash_map(pkg1, sizeof(pkg1),
                                                        bc1, bc1_len,
                                                        MBPF_HOOK_TRACEPOINT,
                                                        "myhash", 100, 4, 4, "1.0.0");
    size_t pkg2_len = build_mbpf_package_with_hash_map(pkg2, sizeof(pkg2),
                                                        bc2, bc2_len,
                                                        MBPF_HOOK_TRACEPOINT,
                                                        "myhash", 100, 4, 4, "2.0.0");
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);  /* Data persisted */

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/*
 * Test 3: Map destruction with MBPF_MAP_POLICY_DESTROY
 *
 * Verify maps are destroyed when policy requires
 */
TEST(map_destruction_policy) {
    /* v1 program: writes data to map */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0x11, 0x22, 0x33, 0x44]));\n"
        "    return 1;\n"
        "}\n";

    /* v2 program: checks if data is present (should not be after destroy) */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (maps.mymap.lookup(0, buf)) {\n"
        "        return -1;  /* Data should NOT be present */\n"
        "    }\n"
        "    return 2;  /* Correct: data was destroyed */\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    ASSERT_NOT_NULL(bc1);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc2);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package_with_map(pkg1, sizeof(pkg1),
                                                   bc1, bc1_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "1.0.0");
    size_t pkg2_len = build_mbpf_package_with_map(pkg2, sizeof(pkg2),
                                                   bc2, bc2_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "2.0.0");
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Update with DESTROY policy */
    mbpf_update_opts_t opts = {
        .map_policy = MBPF_MAP_POLICY_DESTROY
    };
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, &opts);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);  /* Data was destroyed as expected */

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/*
 * Test 4: Update must be detached first
 *
 * Verify update fails if program is still attached
 */
TEST(update_requires_detach) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package_with_map(pkg1, sizeof(pkg1),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "1.0.0");
    size_t pkg2_len = build_mbpf_package_with_map(pkg2, sizeof(pkg2),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "2.0.0");
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Try to update while attached - should fail */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_ERR_STILL_ATTACHED);

    /* Detach and update should work */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Multiple map entries persist
 *
 * Verify multiple entries in a map all persist
 */
TEST(multiple_entries_persist) {
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0x00, 0x00, 0x00, 0x00]));\n"
        "    maps.mymap.update(1, new Uint8Array([0x11, 0x11, 0x11, 0x11]));\n"
        "    maps.mymap.update(2, new Uint8Array([0x22, 0x22, 0x22, 0x22]));\n"
        "    maps.mymap.update(5, new Uint8Array([0x55, 0x55, 0x55, 0x55]));\n"
        "    return 1;\n"
        "}\n";

    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (!maps.mymap.lookup(0, buf) || buf[0] !== 0x00) return -1;\n"
        "    if (!maps.mymap.lookup(1, buf) || buf[0] !== 0x11) return -2;\n"
        "    if (!maps.mymap.lookup(2, buf) || buf[0] !== 0x22) return -3;\n"
        "    if (!maps.mymap.lookup(5, buf) || buf[0] !== 0x55) return -4;\n"
        "    /* Entry 3 was never set, should not exist */\n"
        "    if (maps.mymap.lookup(3, buf)) return -5;\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    ASSERT_NOT_NULL(bc1);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc2);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package_with_map(pkg1, sizeof(pkg1),
                                                   bc1, bc1_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "1.0.0");
    size_t pkg2_len = build_mbpf_package_with_map(pkg2, sizeof(pkg2),
                                                   bc2, bc2_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "2.0.0");
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/*
 * Test 6: Update with invalid arguments
 *
 * Verify proper error handling
 */
TEST(update_invalid_args) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "mymap", 10, 4, "1.0.0");
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* NULL runtime */
    err = mbpf_program_update(NULL, prog, pkg, pkg_len, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL program */
    err = mbpf_program_update(rt, NULL, pkg, pkg_len, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL package */
    err = mbpf_program_update(rt, prog, NULL, pkg_len, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* Package too small */
    err = mbpf_program_update(rt, prog, pkg, 10, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Cannot update unloaded program
 *
 * Verify update fails for unloaded program
 */
TEST(update_unloaded_fails) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package_with_map(pkg1, sizeof(pkg1),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "1.0.0");
    size_t pkg2_len = build_mbpf_package_with_map(pkg2, sizeof(pkg2),
                                                   bytecode, bc_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "2.0.0");
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Unload the program */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Try to update - should fail */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_ERR_ALREADY_UNLOADED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Multiple updates preserve data
 *
 * Verify data persists across multiple consecutive updates
 */
TEST(multiple_updates_preserve) {
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0x01, 0x02, 0x03, 0x04]));\n"
        "    return 1;\n"
        "}\n";

    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (!maps.mymap.lookup(0, buf)) return -1;\n"
        "    if (buf[0] !== 0x01) return -2;\n"
        "    /* Add more data */\n"
        "    maps.mymap.update(1, new Uint8Array([0x05, 0x06, 0x07, 0x08]));\n"
        "    return 2;\n"
        "}\n";

    const char *v3_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    /* Verify both entries */\n"
        "    if (!maps.mymap.lookup(0, buf) || buf[0] !== 0x01) return -1;\n"
        "    if (!maps.mymap.lookup(1, buf) || buf[0] !== 0x05) return -2;\n"
        "    return 3;\n"
        "}\n";

    size_t bc1_len, bc2_len, bc3_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    ASSERT_NOT_NULL(bc1);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc2);
    uint8_t *bc3 = compile_js_to_bytecode(v3_code, &bc3_len);
    ASSERT_NOT_NULL(bc3);

    uint8_t pkg1[16384], pkg2[16384], pkg3[16384];
    size_t pkg1_len = build_mbpf_package_with_map(pkg1, sizeof(pkg1), bc1, bc1_len,
                                                   MBPF_HOOK_TRACEPOINT, "mymap", 10, 4, "1.0.0");
    size_t pkg2_len = build_mbpf_package_with_map(pkg2, sizeof(pkg2), bc2, bc2_len,
                                                   MBPF_HOOK_TRACEPOINT, "mymap", 10, 4, "2.0.0");
    size_t pkg3_len = build_mbpf_package_with_map(pkg3, sizeof(pkg3), bc3, bc3_len,
                                                   MBPF_HOOK_TRACEPOINT, "mymap", 10, 4, "3.0.0");
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);
    ASSERT(pkg3_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;

    /* v1: write first entry */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Update to v2 */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_OK);

    /* v2: verify first entry and write second */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Update to v3 */
    err = mbpf_program_update(rt, prog, pkg3, pkg3_len, NULL);
    ASSERT_EQ(err, MBPF_OK);

    /* v3: verify both entries */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 3);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    free(bc3);
    return 0;
}

/* Helper to build a manifest with LRU map definition */
static size_t build_manifest_with_lru_map(uint8_t *buf, size_t cap, int hook_type,
                                           const char *map_name, uint32_t max_entries,
                                           uint32_t key_size, uint32_t value_size,
                                           const char *prog_version) {
    char json[2048];
    /* type 3 = LRU hash map */
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"persistence_test\","
        "\"program_version\":\"%s\","
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
        prog_version, hook_type, map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and LRU map */
static size_t build_mbpf_package_with_lru_map(uint8_t *buf, size_t cap,
                                               const uint8_t *bytecode, size_t bc_len,
                                               int hook_type,
                                               const char *map_name, uint32_t max_entries,
                                               uint32_t key_size, uint32_t value_size,
                                               const char *prog_version) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_lru_map(manifest, sizeof(manifest),
                                                       hook_type, map_name,
                                                       max_entries, key_size, value_size,
                                                       prog_version);
    if (manifest_len == 0) return 0;

    /* Calculate offsets */
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
 * Test 9: LRU map persistence
 *
 * Verify LRU map data persists across program updates
 */
TEST(lru_map_persistence) {
    /* v1: Insert a key-value pair into LRU map */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([0x01, 0x02, 0x03, 0x04]);\n"
        "    var val = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    maps.mymap.update(key, val);\n"
        "    return 1;\n"
        "}\n";

    /* v2: Verify the entry exists after update */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([0x01, 0x02, 0x03, 0x04]);\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (!maps.mymap.lookup(key, buf)) return -1;\n"
        "    if (buf[0] !== 0xAA || buf[1] !== 0xBB) return -2;\n"
        "    if (buf[2] !== 0xCC || buf[3] !== 0xDD) return -3;\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package_with_lru_map(pkg1, sizeof(pkg1),
                                                       bc1, bc1_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 10, 4, 4, "1.0.0");
    size_t pkg2_len = build_mbpf_package_with_lru_map(pkg2, sizeof(pkg2),
                                                       bc2, bc2_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "mymap", 10, 4, 4, "2.0.0");
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Run v1 to populate the map */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    uint32_t ctx[4] = {0};
    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Update to v2 - should preserve LRU map data */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_OK);

    /* Run v2 to verify the data persisted */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);  /* Should return 2 if data was preserved */

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/*
 * Test 10: Map resize on update - shrinking
 *
 * Verify that when max_entries decreases, data is truncated properly
 * and the new size is respected (can't access old indices).
 */
TEST(map_resize_shrink) {
    /* v1: Create map with max_entries=10 and write to index 3 and 7 */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    maps.mymap.update(3, buf);\n"
        "    maps.mymap.update(7, buf);\n"
        "    return 1;\n"
        "}\n";

    /* v2: max_entries shrunk to 5 - index 3 should exist, but 7 should be gone */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    // Index 3 should still exist\n"
        "    if (!maps.mymap.lookup(3, buf)) return -1;\n"
        "    if (buf[0] !== 0xAA) return -2;\n"
        "    // Index 7 should be out of range (RangeError)\n"
        "    try {\n"
        "        maps.mymap.lookup(7, buf);\n"
        "        return -3;  // Should have thrown\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -4;\n"
        "    }\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);

    /* v1 package has max_entries=10 */
    uint8_t pkg1[16384];
    size_t pkg1_len = build_mbpf_package_with_map(pkg1, sizeof(pkg1),
                                                   bc1, bc1_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "1.0.0");
    ASSERT(pkg1_len > 0);

    /* v2 package has max_entries=5 (shrunk) */
    uint8_t pkg2[16384];
    size_t pkg2_len = build_mbpf_package_with_map(pkg2, sizeof(pkg2),
                                                   bc2, bc2_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 5, 4, "2.0.0");
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Run v1 to populate the map */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    uint32_t ctx[4] = {0};
    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Update to v2 with smaller max_entries */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_OK);

    /* Run v2 to verify resize behavior */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);  /* Should return 2 if resize worked correctly */

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/*
 * Test 11: Map resize on update - expanding
 *
 * Verify that when max_entries increases, old data is preserved
 * and new indices become accessible.
 */
TEST(map_resize_expand) {
    /* v1: Create map with max_entries=5 and write to index 3 */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    maps.mymap.update(3, buf);\n"
        "    return 1;\n"
        "}\n";

    /* v2: max_entries expanded to 10 - can now access index 7 */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    // Index 3 should still have old data\n"
        "    if (!maps.mymap.lookup(3, buf)) return -1;\n"
        "    if (buf[0] !== 0xAA || buf[1] !== 0xBB) return -2;\n"
        "    // Index 7 should now be accessible (but empty)\n"
        "    if (maps.mymap.lookup(7, buf)) return -3;  // Should be empty\n"
        "    // Can write to index 7 now\n"
        "    var newval = new Uint8Array([0x11, 0x22, 0x33, 0x44]);\n"
        "    if (!maps.mymap.update(7, newval)) return -4;\n"
        "    if (!maps.mymap.lookup(7, buf)) return -5;\n"
        "    if (buf[0] !== 0x11) return -6;\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);

    /* v1 package has max_entries=5 */
    uint8_t pkg1[16384];
    size_t pkg1_len = build_mbpf_package_with_map(pkg1, sizeof(pkg1),
                                                   bc1, bc1_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 5, 4, "1.0.0");
    ASSERT(pkg1_len > 0);

    /* v2 package has max_entries=10 (expanded) */
    uint8_t pkg2[16384];
    size_t pkg2_len = build_mbpf_package_with_map(pkg2, sizeof(pkg2),
                                                   bc2, bc2_len,
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "mymap", 10, 4, "2.0.0");
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Run v1 to populate the map */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    uint32_t ctx[4] = {0};
    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Update to v2 with larger max_entries */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_OK);

    /* Run v2 to verify resize behavior */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);  /* Should return 2 if resize worked correctly */

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Map Persistence Tests\n");
    printf("==============================\n");

    printf("\nBasic persistence tests:\n");
    RUN_TEST(basic_persistence);
    RUN_TEST(hash_map_persistence);
    RUN_TEST(multiple_entries_persist);
    RUN_TEST(multiple_updates_preserve);

    printf("\nAdvanced map type persistence tests:\n");
    RUN_TEST(lru_map_persistence);

    printf("\nMap resize tests:\n");
    RUN_TEST(map_resize_shrink);
    RUN_TEST(map_resize_expand);

    printf("\nPolicy tests:\n");
    RUN_TEST(map_destruction_policy);

    printf("\nError handling tests:\n");
    RUN_TEST(update_requires_detach);
    RUN_TEST(update_invalid_args);
    RUN_TEST(update_unloaded_fails);

    printf("\n==============================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
