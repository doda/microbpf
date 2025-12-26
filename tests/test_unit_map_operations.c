/*
 * microBPF Map Operations Unit Tests
 *
 * Comprehensive unit tests for map implementations covering:
 * - Array map: lookup, update, bounds checking
 * - Hash map: lookup, update, delete, collision handling
 * - Edge cases and error conditions
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

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
#define ASSERT_MEM_EQ(a, b, len) ASSERT(memcmp((a), (b), (len)) == 0)

/* Return value constants for lock-free map operations
 * For lookups: 1 = found, 0 = not found, -1 = error
 * For updates: 0 = success, -1 = error
 * For delete: 0 = success, 1 = not found, -1 = error */
#define MAP_FOUND 1
#define MAP_NOT_FOUND 0
#define MAP_ERROR -1
#define MAP_DELETE_NOT_FOUND 1

/* Helper to build manifest with array map */
static size_t build_manifest_with_array_map(uint8_t *buf, size_t cap,
                                             const char *map_name,
                                             uint32_t max_entries,
                                             uint32_t value_size) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"map_unit_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":1,\"key_size\":4,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build manifest with hash map */
static size_t build_manifest_with_hash_map(uint8_t *buf, size_t cap,
                                            const char *map_name,
                                            uint32_t key_size,
                                            uint32_t value_size,
                                            uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"map_unit_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":2,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build manifest with multiple maps */
static size_t build_manifest_with_multiple_maps(uint8_t *buf, size_t cap) {
    char json[4096];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"multi_map_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":["
        "{\"name\":\"array1\",\"type\":1,\"key_size\":4,\"value_size\":8,\"max_entries\":10,\"flags\":0},"
        "{\"name\":\"hash1\",\"type\":2,\"key_size\":4,\"value_size\":16,\"max_entries\":20,\"flags\":0},"
        "{\"name\":\"array2\",\"type\":1,\"key_size\":4,\"value_size\":4,\"max_entries\":5,\"flags\":0}"
        "]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
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

    return total_size;
}

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_unit_map.js";
    const char *bc_file = "/tmp/test_unit_map.qjbc";

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

/* Helper to create a program with an array map */
static mbpf_program_t *create_program_with_array_map(mbpf_runtime_t *rt,
                                                      const char *map_name,
                                                      uint32_t max_entries,
                                                      uint32_t value_size) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    if (!bytecode) return NULL;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_array_map(manifest, sizeof(manifest),
                                                         map_name, max_entries, value_size);
    if (manifest_len == 0) { free(bytecode); return NULL; }

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), manifest, manifest_len,
                                         bytecode, bc_len);
    free(bytecode);
    if (pkg_len == 0) return NULL;

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    if (err != MBPF_OK) return NULL;

    return prog;
}

/* Helper to create a program with a hash map */
static mbpf_program_t *create_program_with_hash_map(mbpf_runtime_t *rt,
                                                     const char *map_name,
                                                     uint32_t key_size,
                                                     uint32_t value_size,
                                                     uint32_t max_entries) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    if (!bytecode) return NULL;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash_map(manifest, sizeof(manifest),
                                                        map_name, key_size, value_size, max_entries);
    if (manifest_len == 0) { free(bytecode); return NULL; }

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), manifest, manifest_len,
                                         bytecode, bc_len);
    free(bytecode);
    if (pkg_len == 0) return NULL;

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    if (err != MBPF_OK) return NULL;

    return prog;
}

/* Helper to create a program with multiple maps */
static mbpf_program_t *create_program_with_multiple_maps(mbpf_runtime_t *rt) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    if (!bytecode) return NULL;

    uint8_t manifest[4096];
    size_t manifest_len = build_manifest_with_multiple_maps(manifest, sizeof(manifest));
    if (manifest_len == 0) { free(bytecode); return NULL; }

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), manifest, manifest_len,
                                         bytecode, bc_len);
    free(bytecode);
    if (pkg_len == 0) return NULL;

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    if (err != MBPF_OK) return NULL;

    return prog;
}

/* ============================================================================
 * ARRAY MAP UNIT TESTS
 * ============================================================================ */

/* Test: Find array map by name */
TEST(array_map_find_by_name) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    int type = mbpf_map_get_type(prog, map_idx);
    ASSERT_EQ(type, MBPF_MAP_TYPE_ARRAY);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Array map lookup returns not found for uninitialized entry */
TEST(array_map_lookup_uninitialized) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 8);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    uint8_t value[8];
    int ret = mbpf_array_map_lookup_lockfree(prog, map_idx, 0, value, sizeof(value));
    ASSERT_EQ(ret, MAP_NOT_FOUND);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Array map update and lookup */
TEST(array_map_update_lookup) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 8);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    /* Update entry 5 */
    uint8_t write_value[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    int ret = mbpf_array_map_update_locked(prog, map_idx, 5, write_value, sizeof(write_value));
    ASSERT_EQ(ret, MBPF_OK);

    /* Lookup entry 5 */
    uint8_t read_value[8] = {0};
    ret = mbpf_array_map_lookup_lockfree(prog, map_idx, 5, read_value, sizeof(read_value));
    ASSERT_EQ(ret, MAP_FOUND);
    ASSERT_MEM_EQ(write_value, read_value, 8);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Array map multiple entries */
TEST(array_map_multiple_entries) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    /* Write different values to different indices */
    uint8_t val0[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t val5[4] = {0x55, 0x55, 0x55, 0x55};
    uint8_t val9[4] = {0x99, 0x99, 0x99, 0x99};

    ASSERT_EQ(mbpf_array_map_update_locked(prog, map_idx, 0, val0, 4), MBPF_OK);
    ASSERT_EQ(mbpf_array_map_update_locked(prog, map_idx, 5, val5, 4), MBPF_OK);
    ASSERT_EQ(mbpf_array_map_update_locked(prog, map_idx, 9, val9, 4), MBPF_OK);

    /* Verify each */
    uint8_t buf[4];
    ASSERT_EQ(mbpf_array_map_lookup_lockfree(prog, map_idx, 0, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val0, 4);

    ASSERT_EQ(mbpf_array_map_lookup_lockfree(prog, map_idx, 5, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val5, 4);

    ASSERT_EQ(mbpf_array_map_lookup_lockfree(prog, map_idx, 9, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val9, 4);

    /* Entry 3 was never written */
    ASSERT_EQ(mbpf_array_map_lookup_lockfree(prog, map_idx, 3, buf, 4), MAP_NOT_FOUND);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Array map bounds checking - out of range index */
TEST(array_map_bounds_check) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    uint8_t value[4] = {0x11, 0x22, 0x33, 0x44};

    /* Index 10 is out of bounds (max_entries = 10, valid: 0-9) */
    int ret = mbpf_array_map_update_locked(prog, map_idx, 10, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_array_map_lookup_lockfree(prog, map_idx, 10, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    /* Very large index */
    ret = mbpf_array_map_update_locked(prog, map_idx, 1000000, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Array map last valid index */
TEST(array_map_last_valid_index) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    /* Index 9 is the last valid index (max_entries = 10) */
    uint8_t value[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    int ret = mbpf_array_map_update_locked(prog, map_idx, 9, value, 4);
    ASSERT_EQ(ret, MBPF_OK);

    uint8_t buf[4];
    ret = mbpf_array_map_lookup_lockfree(prog, map_idx, 9, buf, 4);
    ASSERT_EQ(ret, MAP_FOUND);
    ASSERT_MEM_EQ(buf, value, 4);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Array map invalid map index */
TEST(array_map_invalid_map_idx) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    uint8_t value[4] = {0x11, 0x22, 0x33, 0x44};

    /* Invalid map index */
    int ret = mbpf_array_map_update_locked(prog, -1, 0, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_array_map_update_locked(prog, 999, 0, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_array_map_lookup_lockfree(prog, -1, 0, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Array map buffer size validation */
TEST(array_map_buffer_size) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 8);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    /* Buffer too small for value_size - update should reject */
    uint8_t small_buf[4];
    int ret = mbpf_array_map_update_locked(prog, map_idx, 0, small_buf, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    /* Lookup with smaller buffer is allowed - just truncates copy */
    /* Entry not set yet, so returns not found */
    ret = mbpf_array_map_lookup_lockfree(prog, map_idx, 0, small_buf, 4);
    ASSERT_EQ(ret, MAP_NOT_FOUND);

    /* Correct size works */
    uint8_t correct_buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    ret = mbpf_array_map_update_locked(prog, map_idx, 0, correct_buf, 8);
    ASSERT_EQ(ret, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Array map value overwrite */
TEST(array_map_overwrite) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    /* Write initial value */
    uint8_t val1[4] = {0x11, 0x11, 0x11, 0x11};
    ASSERT_EQ(mbpf_array_map_update_locked(prog, map_idx, 3, val1, 4), MBPF_OK);

    /* Overwrite with new value */
    uint8_t val2[4] = {0x22, 0x22, 0x22, 0x22};
    ASSERT_EQ(mbpf_array_map_update_locked(prog, map_idx, 3, val2, 4), MBPF_OK);

    /* Verify new value */
    uint8_t buf[4];
    ASSERT_EQ(mbpf_array_map_lookup_lockfree(prog, map_idx, 3, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val2, 4);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * HASH MAP UNIT TESTS
 * ============================================================================ */

/* Test: Find hash map by name */
TEST(hash_map_find_by_name) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 8, 16, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    int type = mbpf_map_get_type(prog, map_idx);
    ASSERT_EQ(type, MBPF_MAP_TYPE_HASH);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map lookup returns not found for missing key */
TEST(hash_map_lookup_missing) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 8, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t value[8];
    int ret = mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, value, 8);
    ASSERT_EQ(ret, MAP_NOT_FOUND);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map update and lookup */
TEST(hash_map_update_lookup) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 8, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    /* Insert key-value pair */
    uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t value[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    int ret = mbpf_hash_map_update_locked(prog, map_idx, key, 4, value, 8);
    ASSERT_EQ(ret, MBPF_OK);

    /* Lookup the key */
    uint8_t read_value[8];
    ret = mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, read_value, 8);
    ASSERT_EQ(ret, MAP_FOUND);
    ASSERT_MEM_EQ(value, read_value, 8);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map delete */
TEST(hash_map_delete) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 8, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    /* Insert key-value pair */
    uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t value[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    ASSERT_EQ(mbpf_hash_map_update_locked(prog, map_idx, key, 4, value, 8), MBPF_OK);

    /* Verify it exists */
    uint8_t read_value[8];
    ASSERT_EQ(mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, read_value, 8), MAP_FOUND);

    /* Delete the key */
    int ret = mbpf_hash_map_delete_locked(prog, map_idx, key, 4);
    ASSERT_EQ(ret, MBPF_OK);

    /* Verify it's gone */
    ret = mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, read_value, 8);
    ASSERT_EQ(ret, MAP_NOT_FOUND);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map delete missing key */
TEST(hash_map_delete_missing) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 8, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    /* Try to delete a key that doesn't exist */
    uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    int ret = mbpf_hash_map_delete_locked(prog, map_idx, key, 4);
    ASSERT_EQ(ret, MAP_DELETE_NOT_FOUND);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map multiple keys */
TEST(hash_map_multiple_keys) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 4, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    /* Insert multiple key-value pairs */
    uint8_t key1[4] = {0x01, 0x00, 0x00, 0x00};
    uint8_t val1[4] = {0x11, 0x11, 0x11, 0x11};
    uint8_t key2[4] = {0x02, 0x00, 0x00, 0x00};
    uint8_t val2[4] = {0x22, 0x22, 0x22, 0x22};
    uint8_t key3[4] = {0x03, 0x00, 0x00, 0x00};
    uint8_t val3[4] = {0x33, 0x33, 0x33, 0x33};

    ASSERT_EQ(mbpf_hash_map_update_locked(prog, map_idx, key1, 4, val1, 4), MBPF_OK);
    ASSERT_EQ(mbpf_hash_map_update_locked(prog, map_idx, key2, 4, val2, 4), MBPF_OK);
    ASSERT_EQ(mbpf_hash_map_update_locked(prog, map_idx, key3, 4, val3, 4), MBPF_OK);

    /* Verify all keys */
    uint8_t buf[4];
    ASSERT_EQ(mbpf_hash_map_lookup_lockfree(prog, map_idx, key1, 4, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val1, 4);

    ASSERT_EQ(mbpf_hash_map_lookup_lockfree(prog, map_idx, key2, 4, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val2, 4);

    ASSERT_EQ(mbpf_hash_map_lookup_lockfree(prog, map_idx, key3, 4, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val3, 4);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map key overwrite */
TEST(hash_map_overwrite) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 4, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};

    /* Write initial value */
    uint8_t val1[4] = {0xAA, 0xAA, 0xAA, 0xAA};
    ASSERT_EQ(mbpf_hash_map_update_locked(prog, map_idx, key, 4, val1, 4), MBPF_OK);

    /* Overwrite with new value */
    uint8_t val2[4] = {0xBB, 0xBB, 0xBB, 0xBB};
    ASSERT_EQ(mbpf_hash_map_update_locked(prog, map_idx, key, 4, val2, 4), MBPF_OK);

    /* Verify new value */
    uint8_t buf[4];
    ASSERT_EQ(mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val2, 4);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map invalid map index */
TEST(hash_map_invalid_map_idx) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 8, 100);
    ASSERT_NOT_NULL(prog);

    uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t value[8] = {0};

    /* Invalid map index */
    int ret = mbpf_hash_map_update_locked(prog, -1, key, 4, value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_update_locked(prog, 999, key, 4, value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_lookup_lockfree(prog, -1, key, 4, value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_delete_locked(prog, -1, key, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map buffer size validation */
TEST(hash_map_buffer_size) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 8, 16, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    /* Key buffer too small - rejected for both update and lookup */
    uint8_t small_key[4];
    uint8_t value[16];
    int ret = mbpf_hash_map_update_locked(prog, map_idx, small_key, 4, value, 16);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_lookup_lockfree(prog, map_idx, small_key, 4, value, 16);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    /* Value buffer too small - rejected for update only */
    uint8_t key[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t small_value[8];
    ret = mbpf_hash_map_update_locked(prog, map_idx, key, 8, small_value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    /* Lookup with smaller value buffer is allowed (truncates), key doesn't exist yet */
    ret = mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 8, small_value, 8);
    ASSERT_EQ(ret, MAP_NOT_FOUND);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map with same hash (collision simulation with specific keys) */
TEST(hash_map_many_entries) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 4, 50);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    /* Insert many entries to test collision handling */
    for (uint32_t i = 0; i < 40; i++) {
        uint8_t key[4];
        uint8_t value[4];
        memcpy(key, &i, 4);
        uint32_t val = i * 0x11111111;
        memcpy(value, &val, 4);
        int ret = mbpf_hash_map_update_locked(prog, map_idx, key, 4, value, 4);
        ASSERT_EQ(ret, MBPF_OK);
    }

    /* Verify all entries */
    for (uint32_t i = 0; i < 40; i++) {
        uint8_t key[4];
        memcpy(key, &i, 4);
        uint8_t value[4];
        int ret = mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, value, 4);
        ASSERT_EQ(ret, MAP_FOUND);
        uint32_t expected = i * 0x11111111;
        uint32_t actual;
        memcpy(&actual, value, 4);
        ASSERT_EQ(actual, expected);
    }

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map delete and reinsert */
TEST(hash_map_delete_reinsert) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 4, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    uint8_t key[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t val1[4] = {0xAA, 0xAA, 0xAA, 0xAA};
    uint8_t val2[4] = {0xBB, 0xBB, 0xBB, 0xBB};
    uint8_t buf[4];

    /* Insert */
    ASSERT_EQ(mbpf_hash_map_update_locked(prog, map_idx, key, 4, val1, 4), MBPF_OK);
    ASSERT_EQ(mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val1, 4);

    /* Delete */
    ASSERT_EQ(mbpf_hash_map_delete_locked(prog, map_idx, key, 4), MBPF_OK);
    ASSERT_EQ(mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, buf, 4), MAP_NOT_FOUND);

    /* Reinsert with different value */
    ASSERT_EQ(mbpf_hash_map_update_locked(prog, map_idx, key, 4, val2, 4), MBPF_OK);
    ASSERT_EQ(mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, buf, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf, val2, 4);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * EDGE CASES AND ERROR CONDITIONS
 * ============================================================================ */

/* Test: Find map that doesn't exist */
TEST(find_map_not_found) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "nonexistent");
    ASSERT_EQ(map_idx, -1);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Get type of invalid map index */
TEST(get_type_invalid_map) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    int type = mbpf_map_get_type(prog, -1);
    ASSERT_EQ(type, -1);

    type = mbpf_map_get_type(prog, 999);
    ASSERT_EQ(type, -1);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Multiple maps in one program */
TEST(multiple_maps_find) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_multiple_maps(rt);
    ASSERT_NOT_NULL(prog);

    /* Find each map */
    int idx1 = mbpf_program_find_map(prog, "array1");
    int idx2 = mbpf_program_find_map(prog, "hash1");
    int idx3 = mbpf_program_find_map(prog, "array2");

    ASSERT(idx1 >= 0);
    ASSERT(idx2 >= 0);
    ASSERT(idx3 >= 0);

    /* All different indices */
    ASSERT_NE(idx1, idx2);
    ASSERT_NE(idx2, idx3);
    ASSERT_NE(idx1, idx3);

    /* Correct types */
    ASSERT_EQ(mbpf_map_get_type(prog, idx1), MBPF_MAP_TYPE_ARRAY);
    ASSERT_EQ(mbpf_map_get_type(prog, idx2), MBPF_MAP_TYPE_HASH);
    ASSERT_EQ(mbpf_map_get_type(prog, idx3), MBPF_MAP_TYPE_ARRAY);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Multiple maps operations are independent */
TEST(multiple_maps_independent) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_multiple_maps(rt);
    ASSERT_NOT_NULL(prog);

    int arr1_idx = mbpf_program_find_map(prog, "array1");
    int arr2_idx = mbpf_program_find_map(prog, "array2");
    ASSERT(arr1_idx >= 0);
    ASSERT(arr2_idx >= 0);

    /* Write to array1 index 0 */
    uint8_t val1[8] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    ASSERT_EQ(mbpf_array_map_update_locked(prog, arr1_idx, 0, val1, 8), MBPF_OK);

    /* Write to array2 index 0 (different map) */
    uint8_t val2[4] = {0x22, 0x22, 0x22, 0x22};
    ASSERT_EQ(mbpf_array_map_update_locked(prog, arr2_idx, 0, val2, 4), MBPF_OK);

    /* Verify array1 has its value */
    uint8_t buf1[8];
    ASSERT_EQ(mbpf_array_map_lookup_lockfree(prog, arr1_idx, 0, buf1, 8), MAP_FOUND);
    ASSERT_MEM_EQ(buf1, val1, 8);

    /* Verify array2 has its value */
    uint8_t buf2[4];
    ASSERT_EQ(mbpf_array_map_lookup_lockfree(prog, arr2_idx, 0, buf2, 4), MAP_FOUND);
    ASSERT_MEM_EQ(buf2, val2, 4);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: NULL program pointer */
TEST(null_program_pointer) {
    uint8_t key[4] = {0};
    uint8_t value[4] = {0};

    /* All functions should handle NULL program gracefully */
    int ret = mbpf_program_find_map(NULL, "test");
    ASSERT_EQ(ret, -1);

    ret = mbpf_map_get_type(NULL, 0);
    ASSERT_EQ(ret, -1);

    ret = mbpf_array_map_lookup_lockfree(NULL, 0, 0, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_array_map_update_locked(NULL, 0, 0, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_lookup_lockfree(NULL, 0, key, 4, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_update_locked(NULL, 0, key, 4, value, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_delete_locked(NULL, 0, key, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test: NULL buffer pointers */
TEST(null_buffer_pointers) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    /* NULL value buffer */
    int ret = mbpf_array_map_lookup_lockfree(prog, map_idx, 0, NULL, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_array_map_update_locked(prog, map_idx, 0, NULL, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: NULL key buffer for hash map */
TEST(null_key_buffer) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 8, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    uint8_t value[8] = {0};

    int ret = mbpf_hash_map_lookup_lockfree(prog, map_idx, NULL, 4, value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_update_locked(prog, map_idx, NULL, 4, value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_delete_locked(prog, map_idx, NULL, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Use array map API on hash map (type mismatch) */
TEST(type_mismatch_array_on_hash) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 4, 8, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);
    ASSERT_EQ(mbpf_map_get_type(prog, map_idx), MBPF_MAP_TYPE_HASH);

    uint8_t value[8] = {0};

    /* Try to use array API on hash map */
    int ret = mbpf_array_map_lookup_lockfree(prog, map_idx, 0, value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_array_map_update_locked(prog, map_idx, 0, value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Use hash map API on array map (type mismatch) */
TEST(type_mismatch_hash_on_array) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 8);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);
    ASSERT_EQ(mbpf_map_get_type(prog, map_idx), MBPF_MAP_TYPE_ARRAY);

    uint8_t key[4] = {0};
    uint8_t value[8] = {0};

    /* Try to use hash API on array map */
    int ret = mbpf_hash_map_lookup_lockfree(prog, map_idx, key, 4, value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_update_locked(prog, map_idx, key, 4, value, 8);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    ret = mbpf_hash_map_delete_locked(prog, map_idx, key, 4);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Array map with value size 1 (minimal) */
TEST(array_map_minimal_value_size) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 1);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    uint8_t value = 0x42;
    ASSERT_EQ(mbpf_array_map_update_locked(prog, map_idx, 0, &value, 1), MBPF_OK);

    uint8_t read_value = 0;
    ASSERT_EQ(mbpf_array_map_lookup_lockfree(prog, map_idx, 0, &read_value, 1), MAP_FOUND);
    ASSERT_EQ(read_value, 0x42);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Hash map with key size 1 (minimal) */
TEST(hash_map_minimal_key_size) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_hash_map(rt, "testhash", 1, 4, 100);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testhash");
    ASSERT(map_idx >= 0);

    uint8_t key = 0x11;
    uint8_t value[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    ASSERT_EQ(mbpf_hash_map_update_locked(prog, map_idx, &key, 1, value, 4), MBPF_OK);

    uint8_t read_value[4];
    ASSERT_EQ(mbpf_hash_map_lookup_lockfree(prog, map_idx, &key, 1, read_value, 4), MAP_FOUND);
    ASSERT_MEM_EQ(read_value, value, 4);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Zero-length buffer handling */
TEST(zero_length_buffer) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = create_program_with_array_map(rt, "testarray", 10, 4);
    ASSERT_NOT_NULL(prog);

    int map_idx = mbpf_program_find_map(prog, "testarray");
    ASSERT(map_idx >= 0);

    uint8_t value[4] = {0};

    /* Zero-length buffer for update - rejected because value_len < value_size */
    int ret = mbpf_array_map_update_locked(prog, map_idx, 0, value, 0);
    ASSERT_EQ(ret, MBPF_ERR_INVALID_ARG);

    /* Zero-length buffer for lookup is allowed - just copies 0 bytes */
    /* Entry not set yet, so returns not found */
    ret = mbpf_array_map_lookup_lockfree(prog, map_idx, 0, value, 0);
    ASSERT_EQ(ret, MAP_NOT_FOUND);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Map Operations Unit Tests\n");
    printf("===================================\n");

    printf("\nArray Map Tests:\n");
    RUN_TEST(array_map_find_by_name);
    RUN_TEST(array_map_lookup_uninitialized);
    RUN_TEST(array_map_update_lookup);
    RUN_TEST(array_map_multiple_entries);
    RUN_TEST(array_map_bounds_check);
    RUN_TEST(array_map_last_valid_index);
    RUN_TEST(array_map_invalid_map_idx);
    RUN_TEST(array_map_buffer_size);
    RUN_TEST(array_map_overwrite);

    printf("\nHash Map Tests:\n");
    RUN_TEST(hash_map_find_by_name);
    RUN_TEST(hash_map_lookup_missing);
    RUN_TEST(hash_map_update_lookup);
    RUN_TEST(hash_map_delete);
    RUN_TEST(hash_map_delete_missing);
    RUN_TEST(hash_map_multiple_keys);
    RUN_TEST(hash_map_overwrite);
    RUN_TEST(hash_map_invalid_map_idx);
    RUN_TEST(hash_map_buffer_size);
    RUN_TEST(hash_map_many_entries);
    RUN_TEST(hash_map_delete_reinsert);

    printf("\nEdge Cases and Error Conditions:\n");
    RUN_TEST(find_map_not_found);
    RUN_TEST(get_type_invalid_map);
    RUN_TEST(multiple_maps_find);
    RUN_TEST(multiple_maps_independent);
    RUN_TEST(null_program_pointer);
    RUN_TEST(null_buffer_pointers);
    RUN_TEST(null_key_buffer);
    RUN_TEST(type_mismatch_array_on_hash);
    RUN_TEST(type_mismatch_hash_on_array);
    RUN_TEST(array_map_minimal_value_size);
    RUN_TEST(hash_map_minimal_key_size);
    RUN_TEST(zero_length_buffer);

    printf("\n===================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
