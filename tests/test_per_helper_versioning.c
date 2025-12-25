/*
 * microBPF Per-Helper Versioning Tests
 *
 * Tests for optional per-helper version enforcement during program load:
 * - Load program with helper_versions map in manifest - verify each helper version checked
 * - Verify incompatible helper version causes load rejection
 * - Verify compatible helper versions allow loading
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

/* Helper version: major=0, minor=1 (current runtime version) */
#define HELPER_VERSION_0_1 ((0 << 16) | 1)

/* Helper to build a JSON manifest with helper_versions map */
static size_t build_manifest_with_helper_versions(uint8_t *buf, size_t cap,
                                                   const char *helper_versions_json) {
    char json[1024];
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
        "%s%s"
        "}", MBPF_API_VERSION,
        helper_versions_json ? ",\"helper_versions\":" : "",
        helper_versions_json ? helper_versions_json : "");
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
    const char *js_file = "/tmp/test_helper_version.js";
    const char *bc_file = "/tmp/test_helper_version.qjbc";

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
 * Test Cases - Per-Helper Version Enforcement
 * ============================================================================ */

/*
 * Test: Load program with no helper_versions - verify succeeds
 * This is the baseline: if no helper_versions are specified, load succeeds.
 */
TEST(no_helper_versions_succeeds) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), NULL);
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
 * Test: Load program with helper_versions matching runtime - verify succeeds
 * Program requires log helper version 0.1, runtime provides 0.1.
 */
TEST(helper_version_matching_succeeds) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Require version 0.1 (which is what runtime provides) */
    char helper_versions[128];
    snprintf(helper_versions, sizeof(helper_versions), "{\"log\":%u}", HELPER_VERSION_0_1);

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), helper_versions);
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
 * Test: Load program with lower minor helper version - verify succeeds
 * Program requires log version 0.0, runtime provides 0.1 (backward compatible).
 */
TEST(helper_version_lower_minor_succeeds) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Require version 0.0 (lower minor) */
    uint32_t lower_version = (0 << 16) | 0;
    char helper_versions[128];
    snprintf(helper_versions, sizeof(helper_versions), "{\"log\":%u}", lower_version);

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), helper_versions);
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
 * Test: Load program with higher minor helper version - verify rejected
 * Program requires log version 0.2, runtime provides 0.1.
 */
TEST(helper_version_higher_minor_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Require version 0.2 (higher minor than runtime's 0.1) */
    uint32_t higher_version = (0 << 16) | 2;
    char helper_versions[128];
    snprintf(helper_versions, sizeof(helper_versions), "{\"log\":%u}", higher_version);

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), helper_versions);
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

    ASSERT_EQ(err, MBPF_ERR_HELPER_VERSION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Load program with major version mismatch - verify rejected
 * Program requires log version 1.0, runtime provides 0.1.
 */
TEST(helper_version_major_mismatch_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Require version 1.0 (major mismatch) */
    uint32_t major_mismatch = (1 << 16) | 0;
    char helper_versions[128];
    snprintf(helper_versions, sizeof(helper_versions), "{\"log\":%u}", major_mismatch);

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), helper_versions);
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

    ASSERT_EQ(err, MBPF_ERR_HELPER_VERSION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Load program with unknown helper in helper_versions - verify rejected
 * Program requires unknownHelper version 0.1, which doesn't exist.
 */
TEST(helper_version_unknown_helper_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Require version for an unknown helper */
    char helper_versions[128];
    snprintf(helper_versions, sizeof(helper_versions), "{\"unknownHelper\":%u}", HELPER_VERSION_0_1);

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), helper_versions);
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

    ASSERT_EQ(err, MBPF_ERR_HELPER_VERSION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Load program with multiple helper versions - all compatible - verify succeeds
 */
TEST(multiple_helper_versions_compatible_succeeds) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Require compatible versions for multiple helpers */
    uint32_t ver = HELPER_VERSION_0_1;
    char helper_versions[256];
    snprintf(helper_versions, sizeof(helper_versions),
             "{\"log\":%u,\"u64LoadLE\":%u,\"emit\":%u}", ver, ver, ver);

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), helper_versions);
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
 * Test: Load program with multiple helper versions - one incompatible - verify rejected
 */
TEST(multiple_helper_versions_one_incompatible_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* log is compatible, but nowNs requires higher minor */
    uint32_t compatible = HELPER_VERSION_0_1;
    uint32_t incompatible = (0 << 16) | 99;  /* 0.99 - way too high */
    char helper_versions[256];
    snprintf(helper_versions, sizeof(helper_versions),
             "{\"log\":%u,\"nowNs\":%u}", compatible, incompatible);

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), helper_versions);
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

    ASSERT_EQ(err, MBPF_ERR_HELPER_VERSION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Verify all known helpers can be versioned
 */
TEST(all_known_helpers_can_be_versioned) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Require compatible versions for all known helpers */
    uint32_t ver = HELPER_VERSION_0_1;
    char helper_versions[512];
    snprintf(helper_versions, sizeof(helper_versions),
             "{\"log\":%u,\"u64LoadLE\":%u,\"u64StoreLE\":%u,"
             "\"nowNs\":%u,\"emit\":%u,\"stats\":%u,"
             "\"mapLookup\":%u,\"mapUpdate\":%u,\"mapDelete\":%u}",
             ver, ver, ver, ver, ver, ver, ver, ver, ver);

    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), helper_versions);
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
 * Test: Empty helper_versions map - verify succeeds
 */
TEST(empty_helper_versions_succeeds) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Empty helper_versions map */
    uint8_t manifest[1024];
    size_t manifest_len = build_manifest_with_helper_versions(manifest, sizeof(manifest), "{}");
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

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Per-Helper Versioning Tests\n");
    printf("=====================================\n");
    printf("Runtime API version: %u.%u\n",
           (unsigned)(MBPF_API_VERSION >> 16),
           (unsigned)(MBPF_API_VERSION & 0xFFFF));
    printf("Helper versions: all at 0.1\n");

    printf("\nBasic tests:\n");
    RUN_TEST(no_helper_versions_succeeds);
    RUN_TEST(empty_helper_versions_succeeds);

    printf("\nCompatible version tests:\n");
    RUN_TEST(helper_version_matching_succeeds);
    RUN_TEST(helper_version_lower_minor_succeeds);
    RUN_TEST(multiple_helper_versions_compatible_succeeds);
    RUN_TEST(all_known_helpers_can_be_versioned);

    printf("\nIncompatible version tests:\n");
    RUN_TEST(helper_version_higher_minor_rejected);
    RUN_TEST(helper_version_major_mismatch_rejected);
    RUN_TEST(helper_version_unknown_helper_rejected);
    RUN_TEST(multiple_helper_versions_one_incompatible_rejected);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
