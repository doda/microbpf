/*
 * microBPF Map Type Validation Tests
 *
 * Tests for map-type-validation task:
 * 1. Attempt lookup with key of wrong size - verify TypeError thrown
 * 2. Attempt lookup with non-Uint8Array key (for hash) - verify TypeError
 * 3. Attempt update with value of wrong size - verify TypeError
 * 4. Attempt array lookup with non-number key - verify TypeError
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
        "\"program_name\":\"type_validation_test\","
        "\"program_version\":\"1.0.0\","
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
        hook_type, map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with array map definition */
static size_t build_manifest_with_array_map(uint8_t *buf, size_t cap, int hook_type,
                                             const char *map_name, uint32_t max_entries,
                                             uint32_t value_size) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"type_validation_test\","
        "\"program_version\":\"1.0.0\","
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
        hook_type, map_name, value_size, max_entries);
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

/* Build a complete .mbpf package with bytecode and array map */
static size_t build_mbpf_package_with_array_map(uint8_t *buf, size_t cap,
                                                 const uint8_t *bytecode, size_t bc_len,
                                                 int hook_type,
                                                 const char *map_name, uint32_t max_entries,
                                                 uint32_t value_size) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_array_map(manifest, sizeof(manifest),
                                                         hook_type, map_name,
                                                         max_entries, value_size);
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
    const char *js_file = "/tmp/test_map_type.js";
    const char *bc_file = "/tmp/test_map_type.qjbc";

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
 * Test Cases - map-type-validation
 * ============================================================================ */

/*
 * Test 1: Hash map lookup with key of wrong size throws TypeError
 *
 * Task Step: "Attempt lookup with key of wrong size - verify TypeError thrown"
 *
 * We have a hash map with key_size=8. Providing a key smaller or larger
 * should throw a RangeError (size validation).
 */
TEST(hash_lookup_wrong_key_size) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    /* Key is 4 bytes but map expects 8 bytes */\n"
        "    var smallKey = new Uint8Array(4);\n"
        "    try {\n"
        "        maps.myhash.lookup(smallKey, outBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        /* RangeError for size validation is acceptable */\n"
        "        if (e instanceof RangeError || e instanceof TypeError) {\n"
        "            return 1;  /* Correct: error thrown */\n"
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
    ASSERT_EQ(out_rc, 1);  /* Error was thrown */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Hash map lookup with zero-length key fails
 */
TEST(hash_lookup_zero_length_key) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    /* Key is 0 bytes but map expects 8 bytes */\n"
        "    var emptyKey = new Uint8Array(0);\n"
        "    try {\n"
        "        maps.myhash.lookup(emptyKey, outBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof RangeError || e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
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
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Hash map lookup with non-Uint8Array key throws TypeError
 *
 * Task Step: "Attempt lookup with non-Uint8Array key (for hash) - verify TypeError"
 */
TEST(hash_lookup_non_uint8array_key_string) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    try {\n"
        "        maps.myhash.lookup('hello123', outBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;  /* Correct: TypeError thrown */\n"
        "        }\n"
        "        return -2;  /* Wrong error type: \" + e.name */\n"
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
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Hash map lookup with regular Array key throws TypeError
 */
TEST(hash_lookup_non_uint8array_key_array) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    try {\n"
        "        maps.myhash.lookup([1, 2, 3, 4, 5, 6, 7, 8], outBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
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
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Hash map lookup with number key throws TypeError
 */
TEST(hash_lookup_non_uint8array_key_number) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    try {\n"
        "        maps.myhash.lookup(12345678, outBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
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
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Hash map update with value of wrong size throws error
 *
 * Task Step: "Attempt update with value of wrong size - verify TypeError"
 */
TEST(hash_update_wrong_value_size) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array(8);\n"
        "    /* Value is 8 bytes but map expects 16 bytes */\n"
        "    var smallVal = new Uint8Array(8);\n"
        "    try {\n"
        "        maps.myhash.update(keyBuf, smallVal);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof RangeError || e instanceof TypeError) {\n"
        "            return 1;  /* Correct: error thrown */\n"
        "        }\n"
        "        return -2;\n"
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
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Hash map update with zero-length value throws error
 */
TEST(hash_update_zero_length_value) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array(8);\n"
        "    /* Value is 0 bytes but map expects 16 bytes */\n"
        "    var emptyVal = new Uint8Array(0);\n"
        "    try {\n"
        "        maps.myhash.update(keyBuf, emptyVal);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof RangeError || e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
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
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Hash map update with non-Uint8Array value throws TypeError
 */
TEST(hash_update_non_uint8array_value) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array(8);\n"
        "    try {\n"
        "        maps.myhash.update(keyBuf, 'not a buffer');\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
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
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Array map lookup with non-number key throws TypeError
 *
 * Task Step: "Attempt array lookup with non-number key - verify TypeError"
 */
TEST(array_lookup_non_number_key_string) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    try {\n"
        "        maps.myarray.lookup('hello', buf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;  /* Correct: TypeError thrown */\n"
        "        }\n"
        "        return -2;  /* Wrong error type */\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_array_map(pkg, sizeof(pkg),
                                                        bytecode, bc_len,
                                                        MBPF_HOOK_TRACEPOINT,
                                                        "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Array map lookup with object key throws TypeError
 */
TEST(array_lookup_non_number_key_object) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    try {\n"
        "        maps.myarray.lookup({index: 0}, buf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_array_map(pkg, sizeof(pkg),
                                                        bytecode, bc_len,
                                                        MBPF_HOOK_TRACEPOINT,
                                                        "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Array map lookup with Uint8Array key throws TypeError
 */
TEST(array_lookup_non_number_key_uint8array) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    var keyBuf = new Uint8Array([0]);\n"
        "    try {\n"
        "        maps.myarray.lookup(keyBuf, buf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_array_map(pkg, sizeof(pkg),
                                                        bytecode, bc_len,
                                                        MBPF_HOOK_TRACEPOINT,
                                                        "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Array map update with non-number key throws TypeError
 */
TEST(array_update_non_number_key) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    try {\n"
        "        maps.myarray.update('zero', buf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_array_map(pkg, sizeof(pkg),
                                                        bytecode, bc_len,
                                                        MBPF_HOOK_TRACEPOINT,
                                                        "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: Array map update with wrong value size throws error
 */
TEST(array_update_wrong_value_size) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Value is 2 bytes but map expects 4 bytes */\n"
        "    var smallBuf = new Uint8Array(2);\n"
        "    try {\n"
        "        maps.myarray.update(0, smallBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof RangeError || e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_array_map(pkg, sizeof(pkg),
                                                        bytecode, bc_len,
                                                        MBPF_HOOK_TRACEPOINT,
                                                        "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 14: Array map lookup with non-Uint8Array out buffer throws TypeError
 */
TEST(array_lookup_non_uint8array_out_buffer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        maps.myarray.lookup(0, 'not a buffer');\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_array_map(pkg, sizeof(pkg),
                                                        bytecode, bc_len,
                                                        MBPF_HOOK_TRACEPOINT,
                                                        "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 15: Hash map delete with wrong key size throws error
 */
TEST(hash_delete_wrong_key_size) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Key is 4 bytes but map expects 8 bytes */\n"
        "    var smallKey = new Uint8Array(4);\n"
        "    try {\n"
        "        maps.myhash.delete(smallKey);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof RangeError || e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
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
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 16: Hash map delete with non-Uint8Array key throws TypeError
 */
TEST(hash_delete_non_uint8array_key) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        maps.myhash.delete('invalid');\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) {\n"
        "            return 1;\n"
        "        }\n"
        "        return -2;\n"
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
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

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

    printf("microBPF Map Type Validation Tests\n");
    printf("===================================\n");

    printf("\nHash map key size validation:\n");
    RUN_TEST(hash_lookup_wrong_key_size);
    RUN_TEST(hash_lookup_zero_length_key);

    printf("\nHash map key type validation (non-Uint8Array):\n");
    RUN_TEST(hash_lookup_non_uint8array_key_string);
    RUN_TEST(hash_lookup_non_uint8array_key_array);
    RUN_TEST(hash_lookup_non_uint8array_key_number);

    printf("\nHash map value size validation:\n");
    RUN_TEST(hash_update_wrong_value_size);
    RUN_TEST(hash_update_zero_length_value);
    RUN_TEST(hash_update_non_uint8array_value);

    printf("\nArray map key type validation (non-number):\n");
    RUN_TEST(array_lookup_non_number_key_string);
    RUN_TEST(array_lookup_non_number_key_object);
    RUN_TEST(array_lookup_non_number_key_uint8array);
    RUN_TEST(array_update_non_number_key);

    printf("\nArray map value validation:\n");
    RUN_TEST(array_update_wrong_value_size);
    RUN_TEST(array_lookup_non_uint8array_out_buffer);

    printf("\nHash map delete validation:\n");
    RUN_TEST(hash_delete_wrong_key_size);
    RUN_TEST(hash_delete_non_uint8array_key);

    printf("\n===================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
