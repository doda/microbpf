/*
 * microBPF Invalid Package Error Tests
 *
 * Tests for appropriate error handling for invalid packages:
 * - Load corrupted package - verify error code returned
 * - Load truncated package - verify error code returned
 * - Load package with wrong magic - verify error code returned
 * - Verify error messages are informative
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
#define ASSERT_STR_CONTAINS(str, substr) ASSERT(strstr(str, substr) != NULL)

/* Helper to build a JSON manifest */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
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
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}", mbpf_runtime_word_size(), mbpf_runtime_endianness());
    if ((size_t)len >= cap) return 0;
    memcpy(buf, json, len);
    return (size_t)len;
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
    const char *js_file = "/tmp/test_error_pkg.js";
    const char *bc_file = "/tmp/test_error_pkg.qjbc";

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

/* Helper to build a valid complete package */
static uint8_t *build_valid_package(size_t *out_len) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    if (!bytecode) return NULL;

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
    if (manifest_len == 0) { free(bytecode); return NULL; }

    static uint8_t pkg[8192];
    size_t pkg_len = build_complete_package(pkg, sizeof(pkg),
                                            manifest, manifest_len,
                                            bytecode, bc_len);
    free(bytecode);
    if (pkg_len == 0) return NULL;

    *out_len = pkg_len;
    return pkg;
}

/* ============================================================================
 * Test Cases - Corrupted Package
 * ============================================================================ */

/* Test: Corrupted header bytes in middle of package */
TEST(corrupted_header_bytes) {
    size_t pkg_len;
    uint8_t *pkg = build_valid_package(&pkg_len);
    ASSERT_NOT_NULL(pkg);

    /* Make a copy and corrupt middle bytes of header (bytes 8-11: flags) */
    uint8_t corrupted[8192];
    memcpy(corrupted, pkg, pkg_len);
    corrupted[8] = 0xFF;
    corrupted[9] = 0xFF;
    corrupted[10] = 0xFF;
    corrupted[11] = 0xFF;

    /* This may or may not fail depending on flags validation */
    /* But corrupting magic should definitely fail */
    corrupted[0] = 0xDE;
    corrupted[1] = 0xAD;
    corrupted[2] = 0xBE;
    corrupted[3] = 0xEF;

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, corrupted, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Corrupted manifest section data */
TEST(corrupted_manifest_section) {
    size_t pkg_len;
    uint8_t *pkg = build_valid_package(&pkg_len);
    ASSERT_NOT_NULL(pkg);

    /* Make a copy and corrupt bytes in the manifest section area */
    uint8_t corrupted[8192];
    memcpy(corrupted, pkg, pkg_len);

    /* Header is 20 bytes, 2 section descriptors are 32 bytes = 52 bytes
     * Manifest data starts at byte 52 - corrupt it completely */
    for (size_t i = 52; i < 100 && i < pkg_len; i++) {
        corrupted[i] = 0xFF;
    }

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, corrupted, pkg_len, NULL, &prog);

    /* Should fail with some error - either invalid package or invalid bytecode
     * since manifest parsing will fail and produce invalid settings */
    ASSERT(err != MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Corrupted bytecode section - corrupt the bytecode magic bytes */
TEST(corrupted_bytecode_section) {
    size_t pkg_len;
    uint8_t *pkg = build_valid_package(&pkg_len);
    ASSERT_NOT_NULL(pkg);
    ASSERT(pkg_len > 100);

    /* Make a copy */
    uint8_t corrupted[8192];
    memcpy(corrupted, pkg, pkg_len);

    /* The bytecode section starts after the manifest. To corrupt it safely,
     * we'll corrupt bytes that represent the bytecode magic/header.
     * Find the bytecode section offset from the section table.
     * Header = 20 bytes, section 0 (MANIFEST) = 16 bytes, section 1 (BYTECODE) = 16 bytes
     * Bytecode section offset is stored at header + 16 + 4 = byte 40-43 (little-endian) */
    uint32_t bc_offset = corrupted[40] | (corrupted[41] << 8) |
                         (corrupted[42] << 16) | (corrupted[43] << 24);

    /* Corrupt the first 8 bytes of bytecode (the magic header) */
    if (bc_offset + 8 <= pkg_len) {
        for (size_t i = 0; i < 8; i++) {
            corrupted[bc_offset + i] = 0xDE;
        }
    }

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, corrupted, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_INVALID_BYTECODE);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Completely random garbage data */
TEST(random_garbage_data) {
    uint8_t garbage[256];
    for (size_t i = 0; i < sizeof(garbage); i++) {
        garbage[i] = (uint8_t)(i * 31 + 17);  /* Pseudo-random pattern */
    }

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, garbage, sizeof(garbage), NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * Test Cases - Truncated Package
 * ============================================================================ */

/* Test: Package truncated mid-header (less than 20 bytes) */
TEST(truncated_mid_header) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), MBPF_MAGIC, 1);
    ASSERT(pkg_len >= 20);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, 10, NULL, &prog);  /* Only 10 bytes */

    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Package truncated at section table */
TEST(truncated_at_section_table) {
    size_t pkg_len;
    uint8_t *pkg = build_valid_package(&pkg_len);
    ASSERT_NOT_NULL(pkg);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    /* Truncate to just header (20 bytes) - missing section descriptors */
    int err = mbpf_program_load(rt, pkg, 20, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Package truncated mid-manifest */
TEST(truncated_mid_manifest) {
    size_t pkg_len;
    uint8_t *pkg = build_valid_package(&pkg_len);
    ASSERT_NOT_NULL(pkg);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    /* Truncate to header + section table + partial manifest */
    size_t truncated_len = 52 + 20;  /* 20-byte header + 32-byte sections + 20 bytes of manifest */
    int err = mbpf_program_load(rt, pkg, truncated_len, NULL, &prog);

    /* Should fail with some package-related error */
    ASSERT(err == MBPF_ERR_SECTION_BOUNDS ||
           err == MBPF_ERR_INVALID_PACKAGE ||
           err == MBPF_ERR_MISSING_SECTION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Package truncated mid-bytecode */
TEST(truncated_mid_bytecode) {
    size_t pkg_len;
    uint8_t *pkg = build_valid_package(&pkg_len);
    ASSERT_NOT_NULL(pkg);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    /* Truncate halfway through the package (removes half of bytecode) */
    size_t truncated_len = pkg_len / 2;
    int err = mbpf_program_load(rt, pkg, truncated_len, NULL, &prog);

    /* Should fail with some package-related error */
    ASSERT(err == MBPF_ERR_SECTION_BOUNDS ||
           err == MBPF_ERR_INVALID_BYTECODE ||
           err == MBPF_ERR_MISSING_SECTION);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Package truncated to just 1 byte */
TEST(truncated_one_byte) {
    uint8_t pkg[1] = { 0x46 };  /* First byte of magic */

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, 1, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Empty package (0 bytes) */
TEST(empty_package) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, "", 0, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* ============================================================================
 * Test Cases - Wrong Magic
 * ============================================================================ */

/* Test: Wrong magic number - all zeros */
TEST(wrong_magic_zeros) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), 0x00000000, 1);
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

/* Test: Wrong magic number - all ones */
TEST(wrong_magic_all_ones) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), 0xFFFFFFFF, 1);
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

/* Test: Wrong magic number - ELF magic (common confusion) */
TEST(wrong_magic_elf) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), 0x464C457F, 1);  /* "\x7FELF" */
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

/* Test: Wrong magic number - PDF magic (random common format) */
TEST(wrong_magic_pdf) {
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), 0x46445025, 1);  /* "%PDF" */
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

/* Test: Swapped endian magic */
TEST(wrong_magic_swapped_endian) {
    /* MBPF_MAGIC is 0x4D425046 ("MBPF" in little-endian), swapped would be 0x4650424D */
    uint8_t pkg[32];
    size_t pkg_len = build_header_only_package(pkg, sizeof(pkg), 0x4650424D, 1);
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

/* ============================================================================
 * Test Cases - Error Message Informativeness
 * ============================================================================ */

/* Test: mbpf_error_string returns informative message for INVALID_MAGIC */
TEST(error_string_invalid_magic) {
    const char *msg = mbpf_error_string(MBPF_ERR_INVALID_MAGIC);
    ASSERT_NOT_NULL(msg);
    /* Message should mention "magic" */
    ASSERT_STR_CONTAINS(msg, "magic");
    /* Message should be reasonably long (not just "error") */
    ASSERT(strlen(msg) > 10);
    return 0;
}

/* Test: mbpf_error_string returns informative message for INVALID_PACKAGE */
TEST(error_string_invalid_package) {
    const char *msg = mbpf_error_string(MBPF_ERR_INVALID_PACKAGE);
    ASSERT_NOT_NULL(msg);
    /* Message should mention "package" or "format" */
    ASSERT(strstr(msg, "package") != NULL || strstr(msg, "format") != NULL);
    ASSERT(strlen(msg) > 10);
    return 0;
}

/* Test: mbpf_error_string returns informative message for INVALID_BYTECODE */
TEST(error_string_invalid_bytecode) {
    const char *msg = mbpf_error_string(MBPF_ERR_INVALID_BYTECODE);
    ASSERT_NOT_NULL(msg);
    /* Message should mention "bytecode" */
    ASSERT_STR_CONTAINS(msg, "bytecode");
    ASSERT(strlen(msg) > 10);
    return 0;
}

/* Test: mbpf_error_string returns informative message for SECTION_BOUNDS */
TEST(error_string_section_bounds) {
    const char *msg = mbpf_error_string(MBPF_ERR_SECTION_BOUNDS);
    ASSERT_NOT_NULL(msg);
    /* Message should mention "section" */
    ASSERT_STR_CONTAINS(msg, "section");
    ASSERT(strlen(msg) > 10);
    return 0;
}

/* Test: mbpf_error_string returns informative message for UNSUPPORTED_VER */
TEST(error_string_unsupported_version) {
    const char *msg = mbpf_error_string(MBPF_ERR_UNSUPPORTED_VER);
    ASSERT_NOT_NULL(msg);
    /* Message should mention "version" */
    ASSERT_STR_CONTAINS(msg, "version");
    ASSERT(strlen(msg) > 10);
    return 0;
}

/* Test: mbpf_error_string returns informative message for MISSING_SECTION */
TEST(error_string_missing_section) {
    const char *msg = mbpf_error_string(MBPF_ERR_MISSING_SECTION);
    ASSERT_NOT_NULL(msg);
    /* Message should mention "section" and "missing" */
    ASSERT_STR_CONTAINS(msg, "section");
    ASSERT_STR_CONTAINS(msg, "missing");
    return 0;
}

/* Test: mbpf_error_string returns informative message for CRC_MISMATCH */
TEST(error_string_crc_mismatch) {
    const char *msg = mbpf_error_string(MBPF_ERR_CRC_MISMATCH);
    ASSERT_NOT_NULL(msg);
    /* Message should mention "CRC" or "checksum" */
    ASSERT(strstr(msg, "CRC") != NULL || strstr(msg, "checksum") != NULL);
    return 0;
}

/* Test: mbpf_error_string returns reasonable message for MBPF_OK */
TEST(error_string_ok) {
    const char *msg = mbpf_error_string(MBPF_OK);
    ASSERT_NOT_NULL(msg);
    /* Should indicate success */
    ASSERT_STR_CONTAINS(msg, "success");
    return 0;
}

/* Test: mbpf_error_string returns message for unknown error */
TEST(error_string_unknown) {
    const char *msg = mbpf_error_string((mbpf_error_t)-999);
    ASSERT_NOT_NULL(msg);
    /* Should return something (not crash) */
    ASSERT(strlen(msg) > 0);
    return 0;
}

/* Test: All error codes have informative messages */
TEST(all_error_codes_have_messages) {
    mbpf_error_t errors[] = {
        MBPF_OK,
        MBPF_ERR_INVALID_ARG,
        MBPF_ERR_NO_MEM,
        MBPF_ERR_INVALID_PACKAGE,
        MBPF_ERR_INVALID_MAGIC,
        MBPF_ERR_UNSUPPORTED_VER,
        MBPF_ERR_MISSING_SECTION,
        MBPF_ERR_INVALID_BYTECODE,
        MBPF_ERR_HOOK_MISMATCH,
        MBPF_ERR_CAPABILITY_DENIED,
        MBPF_ERR_BUDGET_EXCEEDED,
        MBPF_ERR_ALREADY_ATTACHED,
        MBPF_ERR_NOT_ATTACHED,
        MBPF_ERR_NESTED_EXEC,
        MBPF_ERR_SIGNATURE,
        MBPF_ERR_SECTION_BOUNDS,
        MBPF_ERR_SECTION_OVERLAP,
        MBPF_ERR_CRC_MISMATCH,
        MBPF_ERR_HEAP_TOO_SMALL,
        MBPF_ERR_ALREADY_UNLOADED,
        MBPF_ERR_ABI_MISMATCH,
        MBPF_ERR_MISSING_ENTRY,
        MBPF_ERR_INIT_FAILED,
        MBPF_ERR_MAP_INCOMPATIBLE,
        MBPF_ERR_STILL_ATTACHED,
        MBPF_ERR_API_VERSION,
        MBPF_ERR_HELPER_VERSION,
        MBPF_ERR_TARGET_MISMATCH,
    };

    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
        const char *msg = mbpf_error_string(errors[i]);
        ASSERT_NOT_NULL(msg);
        ASSERT(strlen(msg) >= 5);  /* Each message should be at least 5 chars */
        /* None should say "unknown" except for truly unknown errors */
        if (errors[i] != MBPF_OK) {
            ASSERT(strstr(msg, "unknown") == NULL);
        }
    }
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Invalid Package Error Tests\n");
    printf("=====================================\n");

    printf("\nCorrupted package tests:\n");
    RUN_TEST(corrupted_header_bytes);
    RUN_TEST(corrupted_manifest_section);
    RUN_TEST(corrupted_bytecode_section);
    RUN_TEST(random_garbage_data);

    printf("\nTruncated package tests:\n");
    RUN_TEST(truncated_mid_header);
    RUN_TEST(truncated_at_section_table);
    RUN_TEST(truncated_mid_manifest);
    RUN_TEST(truncated_mid_bytecode);
    RUN_TEST(truncated_one_byte);
    RUN_TEST(empty_package);

    printf("\nWrong magic tests:\n");
    RUN_TEST(wrong_magic_zeros);
    RUN_TEST(wrong_magic_all_ones);
    RUN_TEST(wrong_magic_elf);
    RUN_TEST(wrong_magic_pdf);
    RUN_TEST(wrong_magic_swapped_endian);

    printf("\nError message informativeness tests:\n");
    RUN_TEST(error_string_invalid_magic);
    RUN_TEST(error_string_invalid_package);
    RUN_TEST(error_string_invalid_bytecode);
    RUN_TEST(error_string_section_bounds);
    RUN_TEST(error_string_unsupported_version);
    RUN_TEST(error_string_missing_section);
    RUN_TEST(error_string_crc_mismatch);
    RUN_TEST(error_string_ok);
    RUN_TEST(error_string_unknown);
    RUN_TEST(all_error_codes_have_messages);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
