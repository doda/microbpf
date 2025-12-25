/*
 * microBPF Program Load Basic Tests
 *
 * Tests for mbpf_program_load API:
 * - Create valid .mbpf package with simple program
 * - Call mbpf_program_load with package bytes
 * - Verify program is loaded successfully (return code 0)
 * - Verify out_prog pointer is set to valid mbpf_program_t
 * - Verify program can be retrieved/identified after loading
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

/* Helper to build a minimal valid JSON manifest */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    char json[512];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"simple_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
    if ((size_t)len >= cap) return 0;
    memcpy(buf, json, len);
    return (size_t)len;
}

/* Build a complete .mbpf package with bytecode */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
    if (manifest_len == 0) return 0;

    /* Calculate offsets */
    uint32_t header_size = 20 + 2 * 16;  /* header + 2 section descriptors */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    /* magic "MBPF" in little-endian: 0x4D425046 */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    /* format_version = 1 */
    *p++ = 0x01; *p++ = 0x00;
    /* header_size */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    /* flags = 0 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* section_count = 2 */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* file_crc32 = 0 (disabled) */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 0: MANIFEST (type=1) */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
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
    const char *js_file = "/tmp/test_program_load.js";
    const char *bc_file = "/tmp/test_program_load.qjbc";

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
 * Test Cases - program-load-basic
 * ============================================================================ */

/* Test 1: Create valid .mbpf package with simple program */
TEST(create_valid_package) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);
    ASSERT(bc_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Verify package is valid by parsing header */
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(pkg, pkg_len, &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.magic, MBPF_MAGIC);
    ASSERT_EQ(header.format_version, 1);
    ASSERT_EQ(header.section_count, 2);

    free(bytecode);
    return 0;
}

/* Test 2: Call mbpf_program_load with package bytes, verify return code 0 */
TEST(load_returns_success) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Verify return code 0 (MBPF_OK) */
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 3: Verify out_prog pointer is set to valid mbpf_program_t */
TEST(out_prog_is_valid) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify out_prog is set and not NULL */
    ASSERT_NOT_NULL(prog);

    /* Verify we can get stats from the program (proves it's valid) */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);

    /* Initial stats should all be zero */
    ASSERT_EQ(stats.invocations, 0);
    ASSERT_EQ(stats.successes, 0);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 4: Verify program can be retrieved/identified after loading */
TEST(program_identifiable_after_load) {
    const char *js_code1 =
        "function mbpf_prog(ctx) { return 1; }\n";
    const char *js_code2 =
        "function mbpf_prog(ctx) { return 2; }\n";

    size_t bc_len1, bc_len2;
    uint8_t *bytecode1 = compile_js_to_bytecode(js_code1, &bc_len1);
    uint8_t *bytecode2 = compile_js_to_bytecode(js_code2, &bc_len2);
    ASSERT_NOT_NULL(bytecode1);
    ASSERT_NOT_NULL(bytecode2);

    uint8_t pkg1[8192], pkg2[8192];
    size_t pkg_len1 = build_mbpf_package(pkg1, sizeof(pkg1), bytecode1, bc_len1);
    size_t pkg_len2 = build_mbpf_package(pkg2, sizeof(pkg2), bytecode2, bc_len2);
    ASSERT(pkg_len1 > 0);
    ASSERT(pkg_len2 > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog1 = NULL, *prog2 = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg_len1, NULL, &prog1);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog1);

    err = mbpf_program_load(rt, pkg2, pkg_len2, NULL, &prog2);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog2);

    /* Programs should be different pointers (identifiable) */
    ASSERT_NE(prog1, prog2);

    /* Each program should have its own stats */
    mbpf_stats_t stats1, stats2;
    ASSERT_EQ(mbpf_program_stats(prog1, &stats1), MBPF_OK);
    ASSERT_EQ(mbpf_program_stats(prog2, &stats2), MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode1);
    free(bytecode2);
    return 0;
}

/* Test 5: Load program with load options */
TEST(load_with_options) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_load_opts_t opts = {
        .override_capabilities = MBPF_CAP_LOG,
        .override_heap_size = 32768,
        .allow_unsigned = 1
    };

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 6: Invalid arguments return error */
TEST(invalid_args_return_error) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    uint8_t dummy[32] = {0};

    /* NULL runtime */
    int err = mbpf_program_load(NULL, dummy, sizeof(dummy), NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL package */
    err = mbpf_program_load(rt, NULL, 100, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* Zero length */
    err = mbpf_program_load(rt, dummy, 0, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* Too short */
    err = mbpf_program_load(rt, dummy, 10, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL out_prog */
    err = mbpf_program_load(rt, dummy, sizeof(dummy), NULL, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 7: Invalid magic number returns error */
TEST(invalid_magic_returns_error) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Corrupt the magic number */
    pkg[0] = 0xFF;
    pkg[1] = 0xFF;

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 8: Program can be attached after loading */
TEST(program_can_be_attached) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Attach to a hook */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Detach */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 9: Program can be unloaded after loading */
TEST(program_can_be_unloaded) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Unload the program */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Runtime should still be valid for shutdown */
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 10: Complex program loads successfully */
TEST(complex_program_loads) {
    const char *js_code =
        "var counter = 0;\n"
        "\n"
        "function mbpf_prog(ctx) {\n"
        "    counter++;\n"
        "    var result = 0;\n"
        "    if (counter > 5) {\n"
        "        result = 1;\n"
        "    }\n"
        "    return result;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

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

    printf("microBPF Program Load Basic Tests\n");
    printf("==================================\n");

    printf("\nPackage creation:\n");
    RUN_TEST(create_valid_package);

    printf("\nLoad success verification:\n");
    RUN_TEST(load_returns_success);
    RUN_TEST(out_prog_is_valid);
    RUN_TEST(program_identifiable_after_load);
    RUN_TEST(load_with_options);

    printf("\nError handling:\n");
    RUN_TEST(invalid_args_return_error);
    RUN_TEST(invalid_magic_returns_error);

    printf("\nProgram lifecycle:\n");
    RUN_TEST(program_can_be_attached);
    RUN_TEST(program_can_be_unloaded);
    RUN_TEST(complex_program_loads);

    printf("\n==================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
