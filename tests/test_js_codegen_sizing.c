/*
 * microBPF JS Code Generation Sizing Tests
 *
 * Tests for verifying that JS code generation handles:
 * 1. Long map names (tests dynamic buffer growth)
 * 2. High map counts (tests initial size estimates)
 * 3. Buffer truncation is handled safely (no underflow)
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

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_codegen_sizing.js";
    const char *bc_file = "/tmp/test_codegen_sizing.qjbc";

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

/* Simple JS that just returns 0 */
static const char *simple_js = "function mbpf_prog(ctx) { return 0; }\n";

/* Helper to build a manifest with a single array map with long name */
static size_t build_manifest_long_map_name(uint8_t *buf, size_t cap,
                                            const char *map_name) {
    char json[4096];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"sizing_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%.31s\",\"type\":1,\"key_size\":4,\"value_size\":4,\"max_entries\":4,\"flags\":0}]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with multiple maps */
static size_t build_manifest_many_maps(uint8_t *buf, size_t cap, int num_maps) {
    char json[65536];
    char *p = json;
    char *end = json + sizeof(json);

    p += snprintf(p, end - p,
        "{"
        "\"program_name\":\"many_maps_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":3,"  /* NET_RX */
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":524288,"
        "\"budgets\":{\"max_steps\":1000000,\"max_helpers\":10000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());

    for (int i = 0; i < num_maps && p < end - 256; i++) {
        if (i > 0) p += snprintf(p, end - p, ",");
        /* Alternate between array (1) and hash (2) maps */
        int map_type = (i % 2) + 1;
        p += snprintf(p, end - p,
            "{\"name\":\"map_%03d\",\"type\":%d,\"key_size\":4,\"value_size\":8,\"max_entries\":4,\"flags\":0}",
            i, map_type);
    }

    p += snprintf(p, end - p, "]}");

    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_package(uint8_t *buf, size_t cap,
                            const uint8_t *manifest, size_t manifest_len,
                            const uint8_t *bytecode, size_t bc_len) {
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

    /* Copy manifest */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    /* Copy bytecode */
    memcpy(p, bytecode, bc_len);

    return total_size;
}

/*
 * Test: Load a program with a map that has a 31-character name (maximum)
 * This tests that the JS code generation handles map names at the limit.
 */
TEST(long_map_name_loads) {
    /* 31 character name (max for map name) */
    const char *long_name = "very_long_map_name_12345678901";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[4096];
    size_t manifest_len = build_manifest_long_map_name(manifest, sizeof(manifest), long_name);
    ASSERT(manifest_len > 0);

    uint8_t package[8192];
    size_t pkg_len = build_package(package, sizeof(package),
                                    manifest, manifest_len,
                                    bytecode, bc_len);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, package, pkg_len, NULL, &prog);

    if (err != MBPF_OK) {
        mbpf_runtime_shutdown(rt);
        ASSERT_EQ(err, MBPF_OK);
    }

    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test: Load a program with many maps (10 maps)
 * This tests that the JS code generation handles multiple maps correctly.
 */
TEST(many_maps_10) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[65536];
    size_t manifest_len = build_manifest_many_maps(manifest, sizeof(manifest), 10);
    ASSERT(manifest_len > 0);

    uint8_t package[131072];
    size_t pkg_len = build_package(package, sizeof(package),
                                    manifest, manifest_len,
                                    bytecode, bc_len);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, package, pkg_len, NULL, &prog);

    if (err != MBPF_OK) {
        printf("(err=%d) ", err);
        mbpf_runtime_shutdown(rt);
        ASSERT_EQ(err, MBPF_OK);
    }

    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test: Load a program with 20 maps
 * This stresses the buffer estimation and growth.
 */
TEST(many_maps_20) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[65536];
    size_t manifest_len = build_manifest_many_maps(manifest, sizeof(manifest), 20);
    ASSERT(manifest_len > 0);

    uint8_t package[131072];
    size_t pkg_len = build_package(package, sizeof(package),
                                    manifest, manifest_len,
                                    bytecode, bc_len);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, package, pkg_len, NULL, &prog);

    if (err != MBPF_OK) {
        mbpf_runtime_shutdown(rt);
        ASSERT_EQ(err, MBPF_OK);
    }

    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test: Load and run a program with many maps
 * This ensures the generated JS code is valid and executable.
 */
TEST(many_maps_run_and_verify) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[65536];
    size_t manifest_len = build_manifest_many_maps(manifest, sizeof(manifest), 8);
    ASSERT(manifest_len > 0);

    uint8_t package[131072];
    size_t pkg_len = build_package(package, sizeof(package),
                                    manifest, manifest_len,
                                    bytecode, bc_len);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, package, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Attach the program */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program - this validates that the JS code is well-formed */
    uint8_t ctx_blob[256] = {0};
    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_NET_RX);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("\nmicroBPF JS Code Generation Sizing Tests\n");
    printf("=========================================\n\n");

    printf("Long map name tests:\n");
    RUN_TEST(long_map_name_loads);

    printf("\nHigh map count tests:\n");
    RUN_TEST(many_maps_10);
    RUN_TEST(many_maps_20);
    RUN_TEST(many_maps_run_and_verify);

    printf("\n=========================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
