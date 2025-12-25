/*
 * microBPF API Version Enforcement Tests
 *
 * Tests for helper API version compatibility during program load (§11.5):
 * - Load program with mbpf_api_version matching runtime - verify succeeds
 * - Load program with major version mismatch - verify rejected
 * - Load program requiring higher minor version than runtime - verify rejected
 * - Load program with lower minor version - verify succeeds
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

/* Helper to build a JSON manifest with customizable mbpf_api_version */
static size_t build_manifest_with_api_version(uint8_t *buf, size_t cap, uint32_t api_version) {
    char json[512];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"test_prog\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":%u,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}", api_version);
    if ((size_t)len >= cap) return 0;
    memcpy(buf, json, len);
    return (size_t)len;
}

/* Build a complete .mbpf package with manifest and bytecode */
static size_t build_complete_package(uint8_t *buf, size_t cap,
                                      const uint8_t *manifest, size_t manifest_len,
                                      const uint8_t *bytecode, size_t bc_len) {
    if (cap < 256) return 0;

    uint32_t header_size = 20 + 2 * 16;  /* header + 2 section descriptors */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;  /* magic "MBPF" */
    *p++ = 0x01; *p++ = 0x00;  /* version = 1 */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* flags */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* section_count = 2 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* file_crc32 */

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

    /* Manifest data */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    /* Bytecode data */
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_api_version.js";
    const char *bc_file = "/tmp/test_api_version.qjbc";

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
 * Test Cases - API Version Enforcement
 * ============================================================================ */

/*
 * Test: Load program with mbpf_api_version matching runtime - verify succeeds
 *
 * Runtime API version is MBPF_API_VERSION = (major << 16) | minor
 * Currently: major=0, minor=1, so MBPF_API_VERSION = 0x00000001
 */
TEST(api_version_matching_succeeds) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Use exact runtime API version */
    uint32_t runtime_api_ver = MBPF_API_VERSION;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_api_version(manifest, sizeof(manifest), runtime_api_ver);
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                            manifest, manifest_len,
                                            bytecode, bc_len);
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

/*
 * Test: Load program with major version mismatch (higher major) - verify rejected
 *
 * If runtime is major=0, program requiring major=1 should fail.
 */
TEST(api_version_major_higher_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Program requires major version 1 higher than runtime */
    uint16_t runtime_major = (uint16_t)(MBPF_API_VERSION >> 16);
    uint16_t runtime_minor = (uint16_t)(MBPF_API_VERSION & 0xFFFF);
    uint32_t prog_api_ver = ((uint32_t)(runtime_major + 1) << 16) | runtime_minor;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_api_version(manifest, sizeof(manifest), prog_api_ver);
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                            manifest, manifest_len,
                                            bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_API_VERSION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Load program with major version mismatch (lower major) - verify rejected
 *
 * If runtime is major=1, program with major=0 should fail (major must match exactly).
 * Since current runtime is major=0, we test with a high major runtime wouldn't support lower.
 * For this test, we use major=1 for program if runtime major > 0, else we test major mismatch
 * in a different way.
 *
 * Actually, since runtime is major=0, let's test with a program that has major=1
 * (already covered above) and also test the other direction by checking that
 * major versions must match exactly. If runtime were major=1 and program major=0,
 * it should also be rejected. But since we can't change runtime version, we'll
 * just verify major mismatch in one direction works.
 */
TEST(api_version_major_lower_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* If runtime major is > 0, test with program major - 1 */
    uint16_t runtime_major = (uint16_t)(MBPF_API_VERSION >> 16);
    uint16_t runtime_minor = (uint16_t)(MBPF_API_VERSION & 0xFFFF);

    /* Skip this test if runtime major is 0 (can't go lower) */
    if (runtime_major == 0) {
        /* Test with a different major version (e.g., 5) to ensure mismatch is caught */
        uint32_t prog_api_ver = (5 << 16) | runtime_minor;

        uint8_t manifest[512];
        size_t manifest_len = build_manifest_with_api_version(manifest, sizeof(manifest), prog_api_ver);
        ASSERT(manifest_len > 0);

        uint8_t pkg[8192];
        size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                                manifest, manifest_len,
                                                bytecode, bc_len);
        ASSERT(pkg_len > 0);

        mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
        ASSERT_NOT_NULL(rt);

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

        ASSERT_EQ(err, MBPF_ERR_API_VERSION);
        ASSERT_NULL(prog);

        mbpf_runtime_shutdown(rt);
    } else {
        uint32_t prog_api_ver = ((uint32_t)(runtime_major - 1) << 16) | runtime_minor;

        uint8_t manifest[512];
        size_t manifest_len = build_manifest_with_api_version(manifest, sizeof(manifest), prog_api_ver);
        ASSERT(manifest_len > 0);

        uint8_t pkg[8192];
        size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                                manifest, manifest_len,
                                                bytecode, bc_len);
        ASSERT(pkg_len > 0);

        mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
        ASSERT_NOT_NULL(rt);

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

        ASSERT_EQ(err, MBPF_ERR_API_VERSION);
        ASSERT_NULL(prog);

        mbpf_runtime_shutdown(rt);
    }

    free(bytecode);
    return 0;
}

/*
 * Test: Load program requiring higher minor version than runtime - verify rejected
 *
 * If runtime is minor=1, program requiring minor=2 should fail.
 */
TEST(api_version_minor_higher_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Program requires minor version 1 higher than runtime */
    uint16_t runtime_major = (uint16_t)(MBPF_API_VERSION >> 16);
    uint16_t runtime_minor = (uint16_t)(MBPF_API_VERSION & 0xFFFF);
    uint32_t prog_api_ver = ((uint32_t)runtime_major << 16) | (runtime_minor + 1);

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_api_version(manifest, sizeof(manifest), prog_api_ver);
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                            manifest, manifest_len,
                                            bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_API_VERSION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Load program with lower minor version - verify succeeds
 *
 * If runtime is minor=1, program with minor=0 should succeed (backward compatible).
 */
TEST(api_version_minor_lower_succeeds) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint16_t runtime_major = (uint16_t)(MBPF_API_VERSION >> 16);
    uint16_t runtime_minor = (uint16_t)(MBPF_API_VERSION & 0xFFFF);

    /* If runtime minor is 0, we can't go lower - skip test in that case */
    if (runtime_minor == 0) {
        printf("(skipped - runtime minor already 0) ");
        free(bytecode);
        return 0;
    }

    /* Program requires minor version 1 lower than runtime */
    uint32_t prog_api_ver = ((uint32_t)runtime_major << 16) | (runtime_minor - 1);

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_api_version(manifest, sizeof(manifest), prog_api_ver);
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                            manifest, manifest_len,
                                            bytecode, bc_len);
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

/*
 * Test: Load program with minor=0 when runtime has higher minor - verify succeeds
 *
 * This is the canonical backward compatibility test: old programs (minor=0)
 * should work on newer runtimes (minor > 0).
 */
TEST(api_version_minor_zero_succeeds) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint16_t runtime_major = (uint16_t)(MBPF_API_VERSION >> 16);

    /* Program with minor=0, same major */
    uint32_t prog_api_ver = ((uint32_t)runtime_major << 16) | 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_api_version(manifest, sizeof(manifest), prog_api_ver);
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                            manifest, manifest_len,
                                            bytecode, bc_len);
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

/*
 * Test: Verify mbpf_api_version() helper returns correct value
 */
TEST(api_version_helper_returns_correct) {
    uint32_t api_ver = mbpf_api_version();
    uint16_t expected_major = MBPF_VERSION_MAJOR;
    uint16_t expected_minor = MBPF_VERSION_MINOR;
    uint32_t expected = ((uint32_t)expected_major << 16) | expected_minor;

    ASSERT_EQ(api_ver, expected);
    ASSERT_EQ(api_ver, MBPF_API_VERSION);
    return 0;
}

/*
 * Test: Load program with significantly higher minor version - verify rejected
 *
 * Program requiring minor=100 when runtime is minor=1 should definitely fail.
 */
TEST(api_version_minor_much_higher_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint16_t runtime_major = (uint16_t)(MBPF_API_VERSION >> 16);
    /* Program requires minor=100 */
    uint32_t prog_api_ver = ((uint32_t)runtime_major << 16) | 100;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_api_version(manifest, sizeof(manifest), prog_api_ver);
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                            manifest, manifest_len,
                                            bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_API_VERSION);
    ASSERT_NULL(prog);

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

    printf("microBPF API Version Enforcement Tests\n");
    printf("========================================\n");
    printf("Runtime API version: %u.%u (0x%08X)\n",
           (unsigned)(MBPF_API_VERSION >> 16),
           (unsigned)(MBPF_API_VERSION & 0xFFFF),
           MBPF_API_VERSION);

    printf("\nMatching version tests:\n");
    RUN_TEST(api_version_matching_succeeds);
    RUN_TEST(api_version_helper_returns_correct);

    printf("\nMajor version mismatch tests:\n");
    RUN_TEST(api_version_major_higher_rejected);
    RUN_TEST(api_version_major_lower_rejected);

    printf("\nMinor version tests:\n");
    RUN_TEST(api_version_minor_higher_rejected);
    RUN_TEST(api_version_minor_lower_succeeds);
    RUN_TEST(api_version_minor_zero_succeeds);
    RUN_TEST(api_version_minor_much_higher_rejected);

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
