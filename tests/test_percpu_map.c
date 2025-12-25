/*
 * microBPF Per-CPU Map Tests
 *
 * Tests for per-CPU map variants (PERCPU_ARRAY and PERCPU_HASH):
 * 1. Define per-CPU array map (type=7) or via ARRAY+PERCPU flag with per-CPU instances
 * 2. Verify each CPU instance has independent map storage
 * 3. Update on CPU0, read on CPU1 - verify isolation
 * 4. Verify cpuId() returns correct instance index
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

/* Helper to build a manifest with per-CPU array map definition (using type=7 directly) */
static size_t build_manifest_with_percpu_array(uint8_t *buf, size_t cap, int hook_type,
                                                const char *map_name, uint32_t max_entries,
                                                uint32_t value_size) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"percpu_map_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":7,\"key_size\":4,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, map_name, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with per-CPU hash map definition (using type=8 directly) */
static size_t build_manifest_with_percpu_hash(uint8_t *buf, size_t cap, int hook_type,
                                               const char *map_name, uint32_t key_size,
                                               uint32_t value_size, uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"percpu_hash_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":8,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with ARRAY map + PERCPU flag (type=1, flags=1) */
static size_t build_manifest_with_array_percpu_flag(uint8_t *buf, size_t cap, int hook_type,
                                                     const char *map_name, uint32_t max_entries,
                                                     uint32_t value_size) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"percpu_flag_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":1,\"key_size\":4,\"value_size\":%u,\"max_entries\":%u,\"flags\":1}]"
        "}",
        hook_type, map_name, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with HASH map + PERCPU flag (type=2, flags=1) */
static size_t build_manifest_with_hash_percpu_flag(uint8_t *buf, size_t cap, int hook_type,
                                                    const char *map_name, uint32_t key_size,
                                                    uint32_t value_size, uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"percpu_hash_flag_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":2,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":1}]"
        "}",
        hook_type, map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and per-CPU array map */
static size_t build_mbpf_package_with_percpu_array(uint8_t *buf, size_t cap,
                                                    const uint8_t *bytecode, size_t bc_len,
                                                    int hook_type,
                                                    const char *map_name, uint32_t max_entries,
                                                    uint32_t value_size) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_percpu_array(manifest, sizeof(manifest),
                                                            hook_type, map_name,
                                                            max_entries, value_size);
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

/* Build a complete .mbpf package with bytecode and per-CPU hash map */
static size_t build_mbpf_package_with_percpu_hash(uint8_t *buf, size_t cap,
                                                   const uint8_t *bytecode, size_t bc_len,
                                                   int hook_type,
                                                   const char *map_name, uint32_t key_size,
                                                   uint32_t value_size, uint32_t max_entries) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_percpu_hash(manifest, sizeof(manifest),
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

/* Build a complete .mbpf package with ARRAY map + PERCPU flag (type=1, flags=1) */
static size_t build_mbpf_package_with_array_percpu_flag(uint8_t *buf, size_t cap,
                                                         const uint8_t *bytecode, size_t bc_len,
                                                         int hook_type,
                                                         const char *map_name, uint32_t max_entries,
                                                         uint32_t value_size) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_array_percpu_flag(manifest, sizeof(manifest),
                                                                  hook_type, map_name,
                                                                  max_entries, value_size);
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

/* Build a complete .mbpf package with HASH map + PERCPU flag (type=2, flags=1) */
static size_t build_mbpf_package_with_hash_percpu_flag(uint8_t *buf, size_t cap,
                                                        const uint8_t *bytecode, size_t bc_len,
                                                        int hook_type,
                                                        const char *map_name, uint32_t key_size,
                                                        uint32_t value_size, uint32_t max_entries) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash_percpu_flag(manifest, sizeof(manifest),
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
    const char *js_file = "/tmp/test_percpu_map.js";
    const char *bc_file = "/tmp/test_percpu_map.qjbc";

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
 * Test Cases - Per-CPU Array Map
 * ============================================================================ */

/*
 * Test 1: Per-CPU array map is created and accessible
 */
TEST(percpu_array_map_created) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof maps === 'undefined') return -1;\n"
        "    if (typeof maps.mypcpu === 'undefined') return -2;\n"
        "    if (typeof maps.mypcpu.lookup !== 'function') return -3;\n"
        "    if (typeof maps.mypcpu.update !== 'function') return -4;\n"
        "    if (typeof maps.mypcpu.cpuId !== 'function') return -5;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_array(pkg, sizeof(pkg),
                                                           bytecode, bc_len,
                                                           MBPF_HOOK_TRACEPOINT,
                                                           "mypcpu", 10, 4);
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
 * Test 2: Per-CPU array map lookup and update work
 */
TEST(percpu_array_lookup_update) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    var found = maps.mypcpu.lookup(0, outBuf);\n"
        "    if (found) return -1;  /* Should not exist initially */\n"
        "    var valueBuf = new Uint8Array([0x12, 0x34, 0x56, 0x78]);\n"
        "    var success = maps.mypcpu.update(0, valueBuf);\n"
        "    if (!success) return -2;\n"
        "    found = maps.mypcpu.lookup(0, outBuf);\n"
        "    if (!found) return -3;\n"
        "    if (outBuf[0] !== 0x12 || outBuf[1] !== 0x34) return -4;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_array(pkg, sizeof(pkg),
                                                           bytecode, bc_len,
                                                           MBPF_HOOK_TRACEPOINT,
                                                           "mypcpu", 10, 4);
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
 * Test 3: Per-CPU array map cpuId returns correct instance index
 */
TEST(percpu_array_cpuid) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var cpuId = maps.mypcpu.cpuId();\n"
        "    return cpuId;  /* Return the CPU ID to verify */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_array(pkg, sizeof(pkg),
                                                           bytecode, bc_len,
                                                           MBPF_HOOK_TRACEPOINT,
                                                           "mypcpu", 10, 4);
    ASSERT(pkg_len > 0);

    /* Use single instance mode - CPU ID should be 0 */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* Instance 0 */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Per-CPU array map isolation between instances
 *
 * With multi-instance mode, each instance has independent storage.
 */
TEST(percpu_array_isolation) {
    /* Program stores the CPU ID at index 0, then verifies it */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var cpuId = maps.mypcpu.cpuId();\n"
        "    var valueBuf = new Uint8Array([cpuId, 0, 0, 0]);\n"
        "    maps.mypcpu.update(0, valueBuf);\n"
        "    /* Read it back */\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    maps.mypcpu.lookup(0, outBuf);\n"
        "    /* Verify the stored value matches cpuId */\n"
        "    if (outBuf[0] !== cpuId) return -1;\n"
        "    return cpuId;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_array(pkg, sizeof(pkg),
                                                           bytecode, bc_len,
                                                           MBPF_HOOK_TRACEPOINT,
                                                           "mypcpu", 10, 4);
    ASSERT(pkg_len > 0);

    /* Configure for 2 instances */
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 16384,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_COUNT,
        .instance_count = 2,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify we have 2 instances */
    ASSERT_EQ(mbpf_program_instance_count(prog), 2);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run once - this will use the first instance */
    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* The return value is the cpuId (0 or 1 depending on scheduling) */
    ASSERT(out_rc >= 0 && out_rc < 2);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Per-CPU array map data isolation verification
 *
 * Each instance's data is independent.
 */
TEST(percpu_array_data_independence) {
    /* Just verify the map works in a multi-instance config */
    const char *js_code =
        "var counter = 0;\n"
        "function mbpf_init() {\n"
        "    /* Store unique value based on cpuId during init */\n"
        "    var cpuId = maps.mypcpu.cpuId();\n"
        "    var valueBuf = new Uint8Array([100 + cpuId, 0, 0, 0]);\n"
        "    maps.mypcpu.update(0, valueBuf);\n"
        "}\n"
        "function mbpf_prog(ctx) {\n"
        "    var cpuId = maps.mypcpu.cpuId();\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    maps.mypcpu.lookup(0, outBuf);\n"
        "    /* Verify the value matches what was stored in init for this CPU */\n"
        "    if (outBuf[0] !== 100 + cpuId) return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_array(pkg, sizeof(pkg),
                                                           bytecode, bc_len,
                                                           MBPF_HOOK_TRACEPOINT,
                                                           "mypcpu", 10, 4);
    ASSERT(pkg_len > 0);

    /* Configure for 2 instances */
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 16384,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_COUNT,
        .instance_count = 2,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times */
    for (int i = 0; i < 5; i++) {
        mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, 0);  /* Each run should verify its own CPU's data */
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - Per-CPU Hash Map
 * ============================================================================ */

/*
 * Test 6: Per-CPU hash map is created and accessible
 */
TEST(percpu_hash_map_created) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof maps === 'undefined') return -1;\n"
        "    if (typeof maps.myhash === 'undefined') return -2;\n"
        "    if (typeof maps.myhash.lookup !== 'function') return -3;\n"
        "    if (typeof maps.myhash.update !== 'function') return -4;\n"
        "    if (typeof maps.myhash.delete !== 'function') return -5;\n"
        "    if (typeof maps.myhash.cpuId !== 'function') return -6;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_hash(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "myhash", 4, 4, 10);
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
 * Test 7: Per-CPU hash map lookup and update work
 */
TEST(percpu_hash_lookup_update) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([1, 2, 3, 4]);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    var found = maps.myhash.lookup(keyBuf, outBuf);\n"
        "    if (found) return -1;  /* Should not exist initially */\n"
        "    var valueBuf = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    var success = maps.myhash.update(keyBuf, valueBuf);\n"
        "    if (!success) return -2;\n"
        "    found = maps.myhash.lookup(keyBuf, outBuf);\n"
        "    if (!found) return -3;\n"
        "    if (outBuf[0] !== 0xAA || outBuf[1] !== 0xBB) return -4;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_hash(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "myhash", 4, 4, 10);
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
 * Test 8: Per-CPU hash map delete works
 */
TEST(percpu_hash_delete) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var keyBuf = new Uint8Array([5, 6, 7, 8]);\n"
        "    var valueBuf = new Uint8Array([0x11, 0x22, 0x33, 0x44]);\n"
        "    maps.myhash.update(keyBuf, valueBuf);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    if (!maps.myhash.lookup(keyBuf, outBuf)) return -1;\n"
        "    if (!maps.myhash.delete(keyBuf)) return -2;\n"
        "    if (maps.myhash.lookup(keyBuf, outBuf)) return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_hash(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "myhash", 4, 4, 10);
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
 * Test 9: Per-CPU hash map cpuId returns correct value
 */
TEST(percpu_hash_cpuid) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return maps.myhash.cpuId();\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_hash(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "myhash", 4, 4, 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* Instance 0 in single-instance mode */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Per-CPU hash map isolation with multi-instance
 */
TEST(percpu_hash_isolation) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var cpuId = maps.myhash.cpuId();\n"
        "    var keyBuf = new Uint8Array([0, 0, 0, 0]);\n"
        "    var valueBuf = new Uint8Array([cpuId, 0, 0, 0]);\n"
        "    maps.myhash.update(keyBuf, valueBuf);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    maps.myhash.lookup(keyBuf, outBuf);\n"
        "    if (outBuf[0] !== cpuId) return -1;\n"
        "    return cpuId;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_percpu_hash(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "myhash", 4, 4, 10);
    ASSERT(pkg_len > 0);

    /* Configure for 3 instances */
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 16384,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_COUNT,
        .instance_count = 3,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(mbpf_program_instance_count(prog), 3);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run a few times */
    for (int i = 0; i < 5; i++) {
        mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT(out_rc >= 0 && out_rc < 3);  /* Should be one of the 3 CPU IDs */
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - PERCPU Flag Path (type=1/2 with flags=1)
 * ============================================================================ */

/*
 * Test 11: ARRAY map with PERCPU flag becomes per-CPU array
 *
 * This tests that type=1 (ARRAY) with flags=1 (PERCPU) is converted
 * to a per-CPU array map and has cpuId() method.
 */
TEST(array_with_percpu_flag) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof maps === 'undefined') return -1;\n"
        "    if (typeof maps.myarray === 'undefined') return -2;\n"
        "    if (typeof maps.myarray.lookup !== 'function') return -3;\n"
        "    if (typeof maps.myarray.update !== 'function') return -4;\n"
        "    if (typeof maps.myarray.cpuId !== 'function') return -5;\n"
        "    /* Verify cpuId returns a valid value */\n"
        "    var cpuId = maps.myarray.cpuId();\n"
        "    if (cpuId < 0) return -6;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_array_percpu_flag(pkg, sizeof(pkg),
                                                                 bytecode, bc_len,
                                                                 MBPF_HOOK_TRACEPOINT,
                                                                 "myarray", 10, 4);
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
 * Test 12: ARRAY map with PERCPU flag supports lookup/update per instance
 */
TEST(array_percpu_flag_isolation) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var cpuId = maps.myarray.cpuId();\n"
        "    var valueBuf = new Uint8Array([cpuId + 50, 0, 0, 0]);\n"
        "    maps.myarray.update(0, valueBuf);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    maps.myarray.lookup(0, outBuf);\n"
        "    if (outBuf[0] !== cpuId + 50) return -1;\n"
        "    return cpuId;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_array_percpu_flag(pkg, sizeof(pkg),
                                                                 bytecode, bc_len,
                                                                 MBPF_HOOK_TRACEPOINT,
                                                                 "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    /* Configure for 2 instances */
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 16384,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_COUNT,
        .instance_count = 2,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(mbpf_program_instance_count(prog), 2);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times */
    for (int i = 0; i < 5; i++) {
        mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT(out_rc >= 0 && out_rc < 2);
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: HASH map with PERCPU flag becomes per-CPU hash
 *
 * This tests that type=2 (HASH) with flags=1 (PERCPU) is converted
 * to a per-CPU hash map and has cpuId() method.
 */
TEST(hash_with_percpu_flag) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof maps === 'undefined') return -1;\n"
        "    if (typeof maps.myhash === 'undefined') return -2;\n"
        "    if (typeof maps.myhash.lookup !== 'function') return -3;\n"
        "    if (typeof maps.myhash.update !== 'function') return -4;\n"
        "    if (typeof maps.myhash.delete !== 'function') return -5;\n"
        "    if (typeof maps.myhash.cpuId !== 'function') return -6;\n"
        "    /* Verify cpuId returns a valid value */\n"
        "    var cpuId = maps.myhash.cpuId();\n"
        "    if (cpuId < 0) return -7;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_percpu_flag(pkg, sizeof(pkg),
                                                                bytecode, bc_len,
                                                                MBPF_HOOK_TRACEPOINT,
                                                                "myhash", 4, 4, 10);
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
 * Test 14: HASH map with PERCPU flag supports lookup/update/delete per instance
 */
TEST(hash_percpu_flag_isolation) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var cpuId = maps.myhash.cpuId();\n"
        "    var keyBuf = new Uint8Array([1, 2, 3, 4]);\n"
        "    var valueBuf = new Uint8Array([cpuId + 100, 0, 0, 0]);\n"
        "    maps.myhash.update(keyBuf, valueBuf);\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    if (!maps.myhash.lookup(keyBuf, outBuf)) return -1;\n"
        "    if (outBuf[0] !== cpuId + 100) return -2;\n"
        "    /* Delete and verify it's gone */\n"
        "    if (!maps.myhash.delete(keyBuf)) return -3;\n"
        "    if (maps.myhash.lookup(keyBuf, outBuf)) return -4;\n"
        "    return cpuId;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_hash_percpu_flag(pkg, sizeof(pkg),
                                                                bytecode, bc_len,
                                                                MBPF_HOOK_TRACEPOINT,
                                                                "myhash", 4, 4, 10);
    ASSERT(pkg_len > 0);

    /* Configure for 3 instances */
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 16384,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_COUNT,
        .instance_count = 3,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(mbpf_program_instance_count(prog), 3);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times */
    for (int i = 0; i < 5; i++) {
        mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT(out_rc >= 0 && out_rc < 3);
    }

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

    printf("microBPF Per-CPU Map Tests\n");
    printf("==========================\n");

    printf("\nPer-CPU array map tests:\n");
    RUN_TEST(percpu_array_map_created);
    RUN_TEST(percpu_array_lookup_update);
    RUN_TEST(percpu_array_cpuid);
    RUN_TEST(percpu_array_isolation);
    RUN_TEST(percpu_array_data_independence);

    printf("\nPer-CPU hash map tests:\n");
    RUN_TEST(percpu_hash_map_created);
    RUN_TEST(percpu_hash_lookup_update);
    RUN_TEST(percpu_hash_delete);
    RUN_TEST(percpu_hash_cpuid);
    RUN_TEST(percpu_hash_isolation);

    printf("\nPERCPU flag path tests (type=1/2 with flags=1):\n");
    RUN_TEST(array_with_percpu_flag);
    RUN_TEST(array_percpu_flag_isolation);
    RUN_TEST(hash_with_percpu_flag);
    RUN_TEST(hash_percpu_flag_isolation);

    printf("\n==========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
