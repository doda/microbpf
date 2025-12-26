/*
 * microBPF Integration Tests - Map Persistence
 *
 * Integration tests for map persistence across the full program lifecycle:
 * 1. Load program, populate maps, update program
 * 2. Verify map data persists
 * 3. Unload and verify cleanup
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include "test_utils.h"
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
#define ASSERT_OK(err) ASSERT((err) == MBPF_OK)

/* Helper to build a manifest with array map definition */
static size_t build_manifest_with_array_map(uint8_t *buf, size_t cap, int hook_type,
                                             const char *prog_name,
                                             const char *map_name, uint32_t max_entries,
                                             uint32_t value_size, const char *prog_version) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"%s\","
        "\"program_version\":\"%s\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":1,\"key_size\":4,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        prog_name, prog_version, hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with hash map definition */
static size_t build_manifest_with_hash_map(uint8_t *buf, size_t cap, int hook_type,
                                            const char *prog_name,
                                            const char *map_name, uint32_t max_entries,
                                            uint32_t key_size, uint32_t value_size,
                                            const char *prog_version) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"%s\","
        "\"program_version\":\"%s\","
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
        prog_name, prog_version, hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with multiple maps */
static size_t build_manifest_with_two_maps(uint8_t *buf, size_t cap, int hook_type,
                                            const char *prog_name,
                                            const char *prog_version) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"%s\","
        "\"program_version\":\"%s\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":["
        "{\"name\":\"array_map\",\"type\":1,\"key_size\":4,\"value_size\":8,\"max_entries\":10,\"flags\":0},"
        "{\"name\":\"hash_map\",\"type\":2,\"key_size\":4,\"value_size\":8,\"max_entries\":50,\"flags\":0}"
        "]"
        "}",
        prog_name, prog_version, hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness());
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *manifest, size_t manifest_len,
                                  const uint8_t *bytecode, size_t bc_len) {
    if (cap < 256) return 0;

    uint32_t header_size = 20 + 2 * 16;
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
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 1: BYTECODE (type=2) */
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
    const char *js_file = "/tmp/test_integration_maps.js";
    const char *bc_file = "/tmp/test_integration_maps.qjbc";

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
 * Step 1: Load program, populate maps, update program
 * ============================================================================ */

/*
 * Integration test: Full lifecycle with array map
 *
 * 1. Load v1 program
 * 2. Attach and populate array map
 * 3. Detach and update to v2
 * 4. Attach and verify data persists
 * 5. Unload and verify cleanup
 */
TEST(full_lifecycle_array_map) {
    /* v1: Write known data pattern to array map */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0x11, 0x22, 0x33, 0x44]));\n"
        "    maps.mymap.update(1, new Uint8Array([0x55, 0x66, 0x77, 0x88]));\n"
        "    maps.mymap.update(5, new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]));\n"
        "    return 1;\n"
        "}\n";

    /* v2: Read and verify data from map */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (!maps.mymap.lookup(0, buf)) return -1;\n"
        "    if (buf[0] !== 0x11 || buf[1] !== 0x22) return -2;\n"
        "    if (!maps.mymap.lookup(1, buf)) return -3;\n"
        "    if (buf[0] !== 0x55 || buf[1] !== 0x66) return -4;\n"
        "    if (!maps.mymap.lookup(5, buf)) return -5;\n"
        "    if (buf[0] !== 0xAA || buf[1] !== 0xBB) return -6;\n"
        "    /* Entry 2 was never set */\n"
        "    if (maps.mymap.lookup(2, buf)) return -7;\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    ASSERT_NOT_NULL(bc1);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc2);

    uint8_t manifest1[2048], manifest2[2048];
    size_t m1_len = build_manifest_with_array_map(manifest1, sizeof(manifest1),
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "map_test", "mymap", 10, 4, "1.0.0");
    size_t m2_len = build_manifest_with_array_map(manifest2, sizeof(manifest2),
                                                   MBPF_HOOK_TRACEPOINT,
                                                   "map_test", "mymap", 10, 4, "2.0.0");
    ASSERT(m1_len > 0);
    ASSERT(m2_len > 0);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package(pkg1, sizeof(pkg1), manifest1, m1_len, bc1, bc1_len);
    size_t pkg2_len = build_mbpf_package(pkg2, sizeof(pkg2), manifest2, m2_len, bc2, bc2_len);
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    /* Initialize runtime */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Step 1: Load v1 program */
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_OK(err);
    ASSERT_NOT_NULL(prog);

    /* Step 2: Attach and populate map */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 1);  /* v1 wrote data successfully */

    /* Verify stats */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_OK(err);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);

    /* Step 3: Detach and update to v2 */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_OK(err);

    /* Step 4: Attach and verify data persists */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 2);  /* v2 found data */

    /* Step 5: Detach and unload */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_program_unload(rt, prog);
    ASSERT_OK(err);

    /* Cleanup */
    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/*
 * Integration test: Full lifecycle with hash map
 */
TEST(full_lifecycle_hash_map) {
    /* v1: Write entries to hash map */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    var key1 = new Uint8Array([0x01, 0x02, 0x03, 0x04]);\n"
        "    var val1 = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    maps.myhash.update(key1, val1);\n"
        "    var key2 = new Uint8Array([0x05, 0x06, 0x07, 0x08]);\n"
        "    var val2 = new Uint8Array([0x11, 0x22, 0x33, 0x44]);\n"
        "    maps.myhash.update(key2, val2);\n"
        "    return 1;\n"
        "}\n";

    /* v2: Verify entries exist */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var key1 = new Uint8Array([0x01, 0x02, 0x03, 0x04]);\n"
        "    var key2 = new Uint8Array([0x05, 0x06, 0x07, 0x08]);\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (!maps.myhash.lookup(key1, buf)) return -1;\n"
        "    if (buf[0] !== 0xAA) return -2;\n"
        "    if (!maps.myhash.lookup(key2, buf)) return -3;\n"
        "    if (buf[0] !== 0x11) return -4;\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    ASSERT_NOT_NULL(bc1);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc2);

    uint8_t manifest1[2048], manifest2[2048];
    size_t m1_len = build_manifest_with_hash_map(manifest1, sizeof(manifest1),
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "hash_test", "myhash", 100, 4, 4, "1.0.0");
    size_t m2_len = build_manifest_with_hash_map(manifest2, sizeof(manifest2),
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "hash_test", "myhash", 100, 4, 4, "2.0.0");
    ASSERT(m1_len > 0);
    ASSERT(m2_len > 0);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package(pkg1, sizeof(pkg1), manifest1, m1_len, bc1, bc1_len);
    size_t pkg2_len = build_mbpf_package(pkg2, sizeof(pkg2), manifest2, m2_len, bc2, bc2_len);
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 1);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 2);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);
    err = mbpf_program_unload(rt, prog);
    ASSERT_OK(err);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/* ============================================================================
 * Step 2: Verify map data persists
 * ============================================================================ */

/*
 * Verify data persists across multiple updates
 */
TEST(data_persists_multiple_updates) {
    /* v1: Write initial data */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]));\n"
        "    return 1;\n"
        "}\n";

    /* v2: Add more data, verify v1 data */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (!maps.mymap.lookup(0, buf)) return -1;\n"
        "    if (buf[0] !== 0xAA) return -2;\n"
        "    maps.mymap.update(1, new Uint8Array([0x11, 0x22, 0x33, 0x44]));\n"
        "    return 2;\n"
        "}\n";

    /* v3: Verify both entries */
    const char *v3_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (!maps.mymap.lookup(0, buf) || buf[0] !== 0xAA) return -1;\n"
        "    if (!maps.mymap.lookup(1, buf) || buf[0] !== 0x11) return -2;\n"
        "    return 3;\n"
        "}\n";

    size_t bc1_len, bc2_len, bc3_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    uint8_t *bc3 = compile_js_to_bytecode(v3_code, &bc3_len);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);
    ASSERT_NOT_NULL(bc3);

    uint8_t m1[2048], m2[2048], m3[2048];
    size_t m1_len = build_manifest_with_array_map(m1, sizeof(m1), MBPF_HOOK_TRACEPOINT,
                                                   "persist_test", "mymap", 10, 4, "1.0.0");
    size_t m2_len = build_manifest_with_array_map(m2, sizeof(m2), MBPF_HOOK_TRACEPOINT,
                                                   "persist_test", "mymap", 10, 4, "2.0.0");
    size_t m3_len = build_manifest_with_array_map(m3, sizeof(m3), MBPF_HOOK_TRACEPOINT,
                                                   "persist_test", "mymap", 10, 4, "3.0.0");

    uint8_t pkg1[16384], pkg2[16384], pkg3[16384];
    size_t pkg1_len = build_mbpf_package(pkg1, sizeof(pkg1), m1, m1_len, bc1, bc1_len);
    size_t pkg2_len = build_mbpf_package(pkg2, sizeof(pkg2), m2, m2_len, bc2, bc2_len);
    size_t pkg3_len = build_mbpf_package(pkg3, sizeof(pkg3), m3, m3_len, bc3, bc3_len);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc;
    int err;

    /* Load and run v1 */
    err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_OK(err);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 1);
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Update to v2 */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_OK(err);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 2);
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Update to v3 */
    err = mbpf_program_update(rt, prog, pkg3, pkg3_len, NULL);
    ASSERT_OK(err);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 3);

    /* Cleanup */
    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    free(bc3);
    return 0;
}

/*
 * Verify multiple maps persist together
 */
TEST(multiple_maps_persist) {
    /* v1: Write to both maps */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.array_map.update(0, new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));\n"
        "    var key = new Uint8Array([0x01, 0x02, 0x03, 0x04]);\n"
        "    maps.hash_map.update(key, new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]));\n"
        "    return 1;\n"
        "}\n";

    /* v2: Verify both maps */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(8);\n"
        "    if (!maps.array_map.lookup(0, buf)) return -1;\n"
        "    if (buf[0] !== 0x11 || buf[4] !== 0x55) return -2;\n"
        "    var key = new Uint8Array([0x01, 0x02, 0x03, 0x04]);\n"
        "    if (!maps.hash_map.lookup(key, buf)) return -3;\n"
        "    if (buf[0] !== 0xAA || buf[4] !== 0xEE) return -4;\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);

    uint8_t m1[2048], m2[2048];
    size_t m1_len = build_manifest_with_two_maps(m1, sizeof(m1), MBPF_HOOK_TRACEPOINT,
                                                  "multi_map_test", "1.0.0");
    size_t m2_len = build_manifest_with_two_maps(m2, sizeof(m2), MBPF_HOOK_TRACEPOINT,
                                                  "multi_map_test", "2.0.0");

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package(pkg1, sizeof(pkg1), m1, m1_len, bc1, bc1_len);
    size_t pkg2_len = build_mbpf_package(pkg2, sizeof(pkg2), m2, m2_len, bc2, bc2_len);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 1);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 2);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/*
 * Verify DESTROY policy clears map data
 */
TEST(destroy_policy_clears_data) {
    /* v1: Write data */
    const char *v1_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]));\n"
        "    return 1;\n"
        "}\n";

    /* v2: Verify data is gone */
    const char *v2_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    if (maps.mymap.lookup(0, buf)) return -1;  /* Should NOT find data */\n"
        "    return 2;\n"
        "}\n";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(v1_code, &bc1_len);
    uint8_t *bc2 = compile_js_to_bytecode(v2_code, &bc2_len);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);

    uint8_t m1[2048], m2[2048];
    size_t m1_len = build_manifest_with_array_map(m1, sizeof(m1), MBPF_HOOK_TRACEPOINT,
                                                   "destroy_test", "mymap", 10, 4, "1.0.0");
    size_t m2_len = build_manifest_with_array_map(m2, sizeof(m2), MBPF_HOOK_TRACEPOINT,
                                                   "destroy_test", "mymap", 10, 4, "2.0.0");

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package(pkg1, sizeof(pkg1), m1, m1_len, bc1, bc1_len);
    size_t pkg2_len = build_mbpf_package(pkg2, sizeof(pkg2), m2, m2_len, bc2, bc2_len);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 1);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Update with DESTROY policy */
    mbpf_update_opts_t opts = {
        .map_policy = MBPF_MAP_POLICY_DESTROY
    };
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, &opts);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 2);  /* Data was cleared */

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/* ============================================================================
 * Step 3: Unload and verify cleanup
 * ============================================================================ */

/*
 * Verify unload properly cleans up program and maps
 */
TEST(unload_cleans_up_program) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0x11, 0x22, 0x33, 0x44]));\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[2048];
    size_t m_len = build_manifest_with_array_map(manifest, sizeof(manifest),
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "cleanup_test", "mymap", 10, 4, "1.0.0");
    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), manifest, m_len, bytecode, bc_len);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_program_unload(rt, prog);
    ASSERT_OK(err);

    /* Verify double unload fails */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_ERR_ALREADY_UNLOADED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Verify runtime shutdown cleans up all programs
 */
TEST(runtime_shutdown_cleanup) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]));\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[2048];
    size_t m_len = build_manifest_with_array_map(manifest, sizeof(manifest),
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "shutdown_test", "mymap", 10, 4, "1.0.0");
    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), manifest, m_len, bytecode, bc_len);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Load multiple programs */
    mbpf_program_t *prog1 = NULL, *prog2 = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog1);
    ASSERT_OK(err);
    err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog2);
    ASSERT_OK(err);

    /* Attach both */
    err = mbpf_program_attach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);
    err = mbpf_program_attach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Run both */
    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);

    /* Shutdown without explicit detach/unload - should cleanup automatically */
    mbpf_runtime_shutdown(rt);

    free(bytecode);
    return 0;
}

/*
 * Verify attached program cannot be updated
 */
TEST(update_requires_detach) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t m1[2048], m2[2048];
    size_t m1_len = build_manifest_with_array_map(m1, sizeof(m1), MBPF_HOOK_TRACEPOINT,
                                                   "detach_test", "mymap", 10, 4, "1.0.0");
    size_t m2_len = build_manifest_with_array_map(m2, sizeof(m2), MBPF_HOOK_TRACEPOINT,
                                                   "detach_test", "mymap", 10, 4, "2.0.0");

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package(pkg1, sizeof(pkg1), m1, m1_len, bytecode, bc_len);
    size_t pkg2_len = build_mbpf_package(pkg2, sizeof(pkg2), m2, m2_len, bytecode, bc_len);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Try to update while attached - should fail */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_ERR_STILL_ATTACHED);

    /* Detach and update should work */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_OK(err);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Verify unloaded program cannot be updated
 */
TEST(update_unloaded_fails) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t m1[2048], m2[2048];
    size_t m1_len = build_manifest_with_array_map(m1, sizeof(m1), MBPF_HOOK_TRACEPOINT,
                                                   "unloaded_test", "mymap", 10, 4, "1.0.0");
    size_t m2_len = build_manifest_with_array_map(m2, sizeof(m2), MBPF_HOOK_TRACEPOINT,
                                                   "unloaded_test", "mymap", 10, 4, "2.0.0");

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg1_len = build_mbpf_package(pkg1, sizeof(pkg1), m1, m1_len, bytecode, bc_len);
    size_t pkg2_len = build_mbpf_package(pkg2, sizeof(pkg2), m2, m2_len, bytecode, bc_len);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_unload(rt, prog);
    ASSERT_OK(err);

    /* Try to update unloaded program */
    err = mbpf_program_update(rt, prog, pkg2, pkg2_len, NULL);
    ASSERT_EQ(err, MBPF_ERR_ALREADY_UNLOADED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Verify stats after complete lifecycle
 */
TEST(stats_after_lifecycle) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    maps.mymap.update(0, new Uint8Array([0x11, 0x22, 0x33, 0x44]));\n"
        "    return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[2048];
    size_t m_len = build_manifest_with_array_map(manifest, sizeof(manifest),
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "stats_test", "mymap", 10, 4, "1.0.0");
    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), manifest, m_len, bytecode, bc_len);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    /* Initial stats should be zero */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_OK(err);
    ASSERT_EQ(stats.invocations, 0);
    ASSERT_EQ(stats.successes, 0);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Run 3 times */
    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc;
    for (int i = 0; i < 3; i++) {
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_OK(err);
        ASSERT_EQ(out_rc, 42);
    }

    /* Verify stats */
    err = mbpf_program_stats(prog, &stats);
    ASSERT_OK(err);
    ASSERT_EQ(stats.invocations, 3);
    ASSERT_EQ(stats.successes, 3);
    ASSERT_EQ(stats.exceptions, 0);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);
    err = mbpf_program_unload(rt, prog);
    ASSERT_OK(err);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Integration Tests - Map Persistence\n");
    printf("=============================================\n\n");

    printf("Step 1: Load program, populate maps, update program\n");
    RUN_TEST(full_lifecycle_array_map);
    RUN_TEST(full_lifecycle_hash_map);

    printf("\nStep 2: Verify map data persists\n");
    RUN_TEST(data_persists_multiple_updates);
    RUN_TEST(multiple_maps_persist);
    RUN_TEST(destroy_policy_clears_data);

    printf("\nStep 3: Unload and verify cleanup\n");
    RUN_TEST(unload_cleans_up_program);
    RUN_TEST(runtime_shutdown_cleanup);
    RUN_TEST(update_requires_detach);
    RUN_TEST(update_unloaded_fails);
    RUN_TEST(stats_after_lifecycle);

    printf("\n=============================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
