/*
 * microBPF Program Load Validation Tests
 *
 * Tests for comprehensive validation during program load:
 * - Attempt to load .mbpf with invalid header - verify rejection
 * - Attempt to load .mbpf with unsupported format version - verify rejection
 * - Attempt to load .mbpf with missing MANIFEST section - verify rejection
 * - Attempt to load .mbpf with missing BYTECODE section - verify rejection
 * - Attempt to load .mbpf with heap_size below platform minimum - verify rejection
 * - Attempt to load .mbpf with incompatible bytecode version - verify rejection
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

/* Helper to build a JSON manifest with customizable heap_size */
static size_t build_manifest_with_heap(uint8_t *buf, size_t cap, uint32_t heap_size) {
    char json[512];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"test_prog\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":%u,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}", mbpf_runtime_word_size(), mbpf_runtime_endianness(), heap_size);
    if ((size_t)len >= cap) return 0;
    memcpy(buf, json, len);
    return (size_t)len;
}

/* Helper to build a minimal valid JSON manifest */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    return build_manifest_with_heap(buf, cap, 65536);
}

/* Build a package with only header (no sections) */
static size_t build_header_only_package(uint8_t *buf, size_t cap,
                                        uint32_t magic, uint16_t version) {
    if (cap < 20) return 0;

    uint8_t *p = buf;

    /* Magic (4 bytes) */
    *p++ = magic & 0xFF;
    *p++ = (magic >> 8) & 0xFF;
    *p++ = (magic >> 16) & 0xFF;
    *p++ = (magic >> 24) & 0xFF;

    /* Format version (2 bytes) */
    *p++ = version & 0xFF;
    *p++ = (version >> 8) & 0xFF;

    /* Header size = 20 (no sections) */
    *p++ = 20;
    *p++ = 0;

    /* Flags (4 bytes) */
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;

    /* Section count = 0 (4 bytes) */
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;

    /* File CRC32 = 0 (4 bytes) */
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;

    return (size_t)(p - buf);
}

/* Build a package with manifest section only (no bytecode) */
static size_t build_manifest_only_package(uint8_t *buf, size_t cap) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
    if (manifest_len == 0) return 0;

    uint32_t header_size = 20 + 16;  /* header + 1 section descriptor */
    uint32_t manifest_offset = header_size;
    uint32_t total_size = manifest_offset + (uint32_t)manifest_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;  /* magic "MBPF" */
    *p++ = 0x01; *p++ = 0x00;  /* version = 1 */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;  /* header_size */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* flags */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* section_count = 1 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* file_crc32 */

    /* Section 0: MANIFEST (type=1) */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Manifest data */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    return (size_t)(p - buf);
}

/* Build a package with bytecode section only (no manifest) */
static size_t build_bytecode_only_package(uint8_t *buf, size_t cap,
                                           const uint8_t *bytecode, size_t bc_len) {
    if (cap < 256) return 0;

    uint32_t header_size = 20 + 16;  /* header + 1 section descriptor */
    uint32_t bytecode_offset = header_size;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;  /* magic "MBPF" */
    *p++ = 0x01; *p++ = 0x00;  /* version = 1 */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;  /* header_size */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* flags */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* section_count = 1 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* file_crc32 */

    /* Section 0: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Bytecode data */
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
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
    const char *js_file = "/tmp/test_validation.js";
    const char *bc_file = "/tmp/test_validation.qjbc";

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
 * Test Cases - Invalid Header
 * ============================================================================ */

/* Test: Corrupted magic bytes should be rejected */
TEST(invalid_magic_bytes) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), 0xDEADBEEF, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Partially corrupted header should be rejected */
TEST(invalid_header_partial) {
    /* Create a valid package first then corrupt specific header bytes */
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), MBPF_MAGIC, 1);
    ASSERT(pkg_len > 0);

    /* Corrupt bytes 2-3 of magic (middle of magic) */
    pkg[2] = 0xFF;
    pkg[3] = 0xFF;

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Truncated header should be rejected */
TEST(invalid_header_truncated) {
    uint8_t pkg[10] = { 0x46, 0x50, 0x42, 0x4D, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00 };

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, sizeof(pkg), NULL, &prog);

    /* Should fail during header parsing */
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * Test Cases - Unsupported Format Version
 * ============================================================================ */

/* Test: Version 0 should be rejected */
TEST(unsupported_version_zero) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), MBPF_MAGIC, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Future version (e.g., 99) should be rejected */
TEST(unsupported_version_future) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), MBPF_MAGIC, 99);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Version 2 (one above current) should be rejected */
TEST(unsupported_version_next) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), MBPF_MAGIC, MBPF_FORMAT_VERSION + 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * Test Cases - Missing MANIFEST Section
 * ============================================================================ */

/* Test: Package with no sections should fail (missing MANIFEST) */
TEST(missing_manifest_no_sections) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), MBPF_MAGIC, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Package with only bytecode section should fail (missing MANIFEST) */
TEST(missing_manifest_bytecode_only) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_bytecode_only_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - Missing BYTECODE Section
 * ============================================================================ */

/* Test: Package with only manifest section should fail (missing BYTECODE) */
TEST(missing_bytecode_manifest_only) {
    uint8_t pkg[1024];
    size_t pkg_len = build_manifest_only_package(pkg, sizeof(pkg));
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * Test Cases - Heap Size Below Minimum
 * ============================================================================ */

/* Test: heap_size of 1024 (below 8KB minimum) should be rejected */
TEST(heap_size_too_small_1024) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_heap(manifest, sizeof(manifest), 1024);
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

    ASSERT_EQ(err, MBPF_ERR_HEAP_TOO_SMALL);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: heap_size of 4096 (still below 8KB minimum) should be rejected */
TEST(heap_size_too_small_4096) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_heap(manifest, sizeof(manifest), 4096);
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

    ASSERT_EQ(err, MBPF_ERR_HEAP_TOO_SMALL);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: heap_size exactly at minimum (8192) should succeed */
TEST(heap_size_at_minimum) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_heap(manifest, sizeof(manifest), MBPF_MIN_HEAP_SIZE);
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

/* Test: heap_size of 0 should be rejected */
TEST(heap_size_zero) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_heap(manifest, sizeof(manifest), 0);
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

    ASSERT_EQ(err, MBPF_ERR_HEAP_TOO_SMALL);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - Incompatible Bytecode Version
 * ============================================================================ */

/* Test: Bytecode with wrong version should be rejected */
TEST(bytecode_version_mismatch) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Corrupt the bytecode version field in the header.
     * JSBytecodeHeader layout: magic (2 bytes), version (2 bytes), base_addr, ...
     * The version is at offset 2-3 in JSBytecodeHeader.
     * We set it to a wrong value by flipping the word size bit. */
    if (bc_len >= 4) {
        uint16_t expected = mbpf_bytecode_version();
        uint16_t wrong_version = expected ^ 0x8000;  /* flip word size bit */
        bytecode[2] = wrong_version & 0xFF;
        bytecode[3] = (wrong_version >> 8) & 0xFF;
    }

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
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

    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Bytecode with base version (32-bit) on 64-bit should be rejected */
TEST(bytecode_version_32bit_on_64bit) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Set version to 32-bit base (0x0001) when we're on 64-bit (0x8001)
     * JSBytecodeHeader: magic (2 bytes), version (2 bytes at offset 2-3) */
    if (bc_len >= 4 && sizeof(void*) == 8) {
        bytecode[2] = 0x01;
        bytecode[3] = 0x00;  /* 0x0001 = 32-bit version */
    }

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
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

    /* On 64-bit, loading 32-bit bytecode should fail */
    if (sizeof(void*) == 8) {
        ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);
        ASSERT_NULL(prog);
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Invalid bytecode (random garbage) should be rejected */
TEST(bytecode_invalid_garbage) {
    uint8_t garbage[64] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        /* ... more garbage ... */
    };

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                            manifest, manifest_len,
                                            garbage, sizeof(garbage));
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_INVALID_BYTECODE);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Empty bytecode section should be rejected */
TEST(bytecode_empty) {
    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    /* Build package with zero-length bytecode */
    uint8_t empty_bc[1] = {0};
    uint8_t pkg[8192];
    size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                            manifest, manifest_len,
                                            empty_bc, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Empty bytecode should fail validation - either INVALID_ARG (too short)
     * or INVALID_BYTECODE (malformed content) are acceptable errors */
    ASSERT(err == MBPF_ERR_INVALID_ARG || err == MBPF_ERR_INVALID_BYTECODE);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * Additional Validation Tests
 * ============================================================================ */

/* Test: Valid package still loads successfully (sanity check) */
TEST(valid_package_loads) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
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

    printf("microBPF Program Load Validation Tests\n");
    printf("=======================================\n");

    printf("\nInvalid header tests:\n");
    RUN_TEST(invalid_magic_bytes);
    RUN_TEST(invalid_header_partial);
    RUN_TEST(invalid_header_truncated);

    printf("\nUnsupported format version tests:\n");
    RUN_TEST(unsupported_version_zero);
    RUN_TEST(unsupported_version_future);
    RUN_TEST(unsupported_version_next);

    printf("\nMissing MANIFEST section tests:\n");
    RUN_TEST(missing_manifest_no_sections);
    RUN_TEST(missing_manifest_bytecode_only);

    printf("\nMissing BYTECODE section tests:\n");
    RUN_TEST(missing_bytecode_manifest_only);

    printf("\nHeap size validation tests:\n");
    RUN_TEST(heap_size_too_small_1024);
    RUN_TEST(heap_size_too_small_4096);
    RUN_TEST(heap_size_at_minimum);
    RUN_TEST(heap_size_zero);

    printf("\nBytecode version validation tests:\n");
    RUN_TEST(bytecode_version_mismatch);
    RUN_TEST(bytecode_version_32bit_on_64bit);
    RUN_TEST(bytecode_invalid_garbage);
    RUN_TEST(bytecode_empty);

    printf("\nSanity checks:\n");
    RUN_TEST(valid_package_loads);

    printf("\n=======================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
