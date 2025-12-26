/*
 * microBPF Package Parser Unit Tests
 *
 * Comprehensive unit tests for the .mbpf package parser covering:
 * - Valid package parsing
 * - Invalid input handling
 * - Edge cases (empty sections, max sizes)
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

/* Helper to write little-endian uint32_t to buffer */
static void write_le32(uint8_t *buf, uint32_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

/* Helper to write little-endian uint16_t to buffer */
static void write_le16(uint8_t *buf, uint16_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
}

/* Create a minimal valid .mbpf header with specified parameters */
static size_t create_mbpf_header(uint8_t *buf, size_t buflen,
                                  uint32_t magic, uint16_t format_version,
                                  uint32_t flags, uint32_t section_count,
                                  uint32_t file_crc32) {
    size_t header_size = sizeof(mbpf_file_header_t) +
                         section_count * sizeof(mbpf_section_desc_t);

    if (buflen < header_size) return 0;

    memset(buf, 0, buflen);

    write_le32(buf + 0, magic);
    write_le16(buf + 4, format_version);
    write_le16(buf + 6, (uint16_t)header_size);
    write_le32(buf + 8, flags);
    write_le32(buf + 12, section_count);
    write_le32(buf + 16, file_crc32);

    return header_size;
}

/* Add a section descriptor at the appropriate position */
static void add_section_desc(uint8_t *buf, uint32_t section_idx,
                              uint32_t type, uint32_t offset,
                              uint32_t length, uint32_t crc32) {
    uint8_t *sec = buf + sizeof(mbpf_file_header_t) +
                   section_idx * sizeof(mbpf_section_desc_t);
    write_le32(sec + 0, type);
    write_le32(sec + 4, offset);
    write_le32(sec + 8, length);
    write_le32(sec + 12, crc32);
}

/* Create a minimal JSON manifest */
static size_t create_json_manifest(uint8_t *buf, size_t buflen,
                                    const char *program_name,
                                    uint32_t hook_type,
                                    uint32_t heap_size) {
    char json[1024];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"%s\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":%u,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":%u,"
        "\"budgets\":{\"max_steps\":10000,\"max_helpers\":100},"
        "\"capabilities\":[]"
        "}",
        program_name,
        hook_type,
        mbpf_runtime_word_size(),
        mbpf_runtime_endianness(),
        heap_size);

    if (len < 0 || (size_t)len >= buflen) return 0;
    memcpy(buf, json, len);
    return (size_t)len;
}

/* ============================================================================
 * VALID PACKAGE PARSING TESTS
 * ============================================================================ */

/* Test: Parse a complete valid package with header and manifest */
TEST(valid_complete_package) {
    uint8_t buf[1024];
    memset(buf, 0, sizeof(buf));

    /* Create header with 1 section (MANIFEST only) */
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf),
                                          MBPF_MAGIC, 1, 0, 1, 0);
    ASSERT(hdr_size > 0);

    /* Create manifest data */
    uint8_t manifest[512];
    size_t manifest_len = create_json_manifest(manifest, sizeof(manifest),
                                                "test_prog", MBPF_HOOK_NET_RX, 16384);
    ASSERT(manifest_len > 0);

    /* Add section descriptor for manifest */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, (uint32_t)manifest_len, 0);

    /* Copy manifest data */
    memcpy(buf + hdr_size, manifest, manifest_len);

    /* Parse header */
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.magic, MBPF_MAGIC);
    ASSERT_EQ(header.section_count, 1);

    /* Parse section table */
    mbpf_section_desc_t sections[1];
    uint32_t count;
    err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 1);
    ASSERT_EQ(sections[0].type, MBPF_SEC_MANIFEST);

    /* Get manifest section */
    const void *sec_data;
    size_t sec_len;
    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_MANIFEST,
                                    &sec_data, &sec_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sec_len, manifest_len);

    /* Parse manifest */
    mbpf_manifest_t mf;
    memset(&mf, 0, sizeof(mf));
    err = mbpf_package_parse_manifest(sec_data, sec_len, &mf);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT(strcmp(mf.program_name, "test_prog") == 0);
    ASSERT_EQ(mf.hook_type, MBPF_HOOK_NET_RX);
    mbpf_manifest_free(&mf);

    return 0;
}

/* Test: Parse package with multiple sections */
TEST(valid_multiple_sections) {
    uint8_t buf[2048];
    memset(buf, 0xAB, sizeof(buf));

    /* Header with 3 sections */
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 3, 0);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;

    /* Section 0: MANIFEST */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 100, 0);
    memset(buf + offset, 0x11, 100);
    offset += 100;

    /* Section 1: BYTECODE */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 200, 0);
    memset(buf + offset, 0x22, 200);
    offset += 200;

    /* Section 2: MAPS */
    add_section_desc(buf, 2, MBPF_SEC_MAPS, offset, 50, 0);
    memset(buf + offset, 0x33, 50);

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 3);

    ASSERT_EQ(sections[0].type, MBPF_SEC_MANIFEST);
    ASSERT_EQ(sections[0].length, 100);
    ASSERT_EQ(sections[1].type, MBPF_SEC_BYTECODE);
    ASSERT_EQ(sections[1].length, 200);
    ASSERT_EQ(sections[2].type, MBPF_SEC_MAPS);
    ASSERT_EQ(sections[2].length, 50);

    return 0;
}

/* Test: Parse package with all section types */
TEST(valid_all_section_types) {
    uint8_t buf[2048];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1,
                                          MBPF_FLAG_SIGNED | MBPF_FLAG_DEBUG, 5, 0);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 80, 0);
    offset += 80;
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 150, 0);
    offset += 150;
    add_section_desc(buf, 2, MBPF_SEC_MAPS, offset, 60, 0);
    offset += 60;
    add_section_desc(buf, 3, MBPF_SEC_DEBUG, offset, 40, 0);
    offset += 40;
    add_section_desc(buf, 4, MBPF_SEC_SIG, offset, 64, 0);

    mbpf_section_desc_t sections[5];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 5, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 5);

    /* Verify we can retrieve each section type */
    const void *data;
    size_t len;
    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_MANIFEST, &data, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len, 80);

    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_BYTECODE, &data, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len, 150);

    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_MAPS, &data, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len, 60);

    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_DEBUG, &data, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len, 40);

    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_SIG, &data, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len, 64);

    return 0;
}

/* Test: Parse manifest with all optional fields */
TEST(valid_manifest_full_fields) {
    const char *json =
        "{"
        "\"program_name\":\"full_test\","
        "\"program_version\":\"2.5.3\","
        "\"hook_type\":3,"
        "\"hook_ctx_abi_version\":1,"
        "\"entry_symbol\":\"custom_entry\","
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":32768,"
        "\"budgets\":{\"max_steps\":50000,\"max_helpers\":500,\"max_wall_time_us\":100000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\",\"CAP_EMIT\"],"
        "\"maps\":["
        "  {\"name\":\"counters\",\"type\":1,\"key_size\":4,\"value_size\":8,\"max_entries\":256}"
        "]"
        "}";

    mbpf_manifest_t mf;
    memset(&mf, 0, sizeof(mf));
    int err = mbpf_package_parse_manifest(json, strlen(json), &mf);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT(strcmp(mf.program_name, "full_test") == 0);
    ASSERT(strcmp(mf.program_version, "2.5.3") == 0);
    ASSERT_EQ(mf.hook_type, 3);
    ASSERT(strcmp(mf.entry_symbol, "custom_entry") == 0);
    ASSERT_EQ(mf.heap_size, 32768);
    ASSERT_EQ(mf.budgets.max_steps, 50000);
    ASSERT_EQ(mf.budgets.max_helpers, 500);
    ASSERT_EQ(mf.budgets.max_wall_time_us, 100000);
    ASSERT_EQ(mf.map_count, 1);
    ASSERT(mf.maps != NULL);
    ASSERT(strcmp(mf.maps[0].name, "counters") == 0);

    mbpf_manifest_free(&mf);
    return 0;
}

/* Test: Parse manifest with maps array */
TEST(valid_manifest_with_maps) {
    const char *json =
        "{"
        "\"program_name\":\"map_test\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":16384,"
        "\"budgets\":{\"max_steps\":10000,\"max_helpers\":100},"
        "\"capabilities\":[\"CAP_MAP_READ\"],"
        "\"maps\":["
        "  {\"name\":\"array_map\",\"type\":1,\"key_size\":4,\"value_size\":16,\"max_entries\":100},"
        "  {\"name\":\"hash_map\",\"type\":2,\"key_size\":8,\"value_size\":32,\"max_entries\":1000}"
        "]"
        "}";

    mbpf_manifest_t mf;
    memset(&mf, 0, sizeof(mf));
    int err = mbpf_package_parse_manifest(json, strlen(json), &mf);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(mf.map_count, 2);
    ASSERT(mf.maps != NULL);

    ASSERT(strcmp(mf.maps[0].name, "array_map") == 0);
    ASSERT_EQ(mf.maps[0].type, 1);
    ASSERT_EQ(mf.maps[0].key_size, 4);
    ASSERT_EQ(mf.maps[0].value_size, 16);
    ASSERT_EQ(mf.maps[0].max_entries, 100);

    ASSERT(strcmp(mf.maps[1].name, "hash_map") == 0);
    ASSERT_EQ(mf.maps[1].type, 2);
    ASSERT_EQ(mf.maps[1].key_size, 8);
    ASSERT_EQ(mf.maps[1].value_size, 32);
    ASSERT_EQ(mf.maps[1].max_entries, 1000);

    mbpf_manifest_free(&mf);
    return 0;
}

/* Test: CRC32 computation and validation */
TEST(valid_crc32_computation) {
    const uint8_t test_data[] = "Hello, microBPF!";
    uint32_t crc = mbpf_crc32(test_data, sizeof(test_data) - 1);
    ASSERT_NE(crc, 0);

    /* CRC32 should be deterministic */
    uint32_t crc2 = mbpf_crc32(test_data, sizeof(test_data) - 1);
    ASSERT_EQ(crc, crc2);

    /* Different data should produce different CRC */
    const uint8_t other_data[] = "Different data";
    uint32_t crc3 = mbpf_crc32(other_data, sizeof(other_data) - 1);
    ASSERT_NE(crc, crc3);

    return 0;
}

/* ============================================================================
 * INVALID INPUT TESTS
 * ============================================================================ */

/* Test: Corrupted magic number */
TEST(invalid_corrupted_magic) {
    uint8_t buf[256];
    mbpf_file_header_t header;
    int err;

    /* Single bit flip in magic */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC ^ 0x01, 1, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);

    /* All bytes inverted */
    create_mbpf_header(buf, sizeof(buf), ~MBPF_MAGIC, 1, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);

    /* Truncated magic (only 3 bytes match) */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC & 0x00FFFFFF, 1, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);

    return 0;
}

/* Test: Truncated package data */
TEST(invalid_truncated_data) {
    uint8_t buf[256];
    mbpf_file_header_t header;

    /* Exactly 19 bytes (1 byte short of header) */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, 0);
    int err = mbpf_package_parse_header(buf, 19, &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* Zero length */
    err = mbpf_package_parse_header(buf, 0, &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test: Invalid format version */
TEST(invalid_format_version) {
    uint8_t buf[256];
    mbpf_file_header_t header;

    /* Version 0 (invalid) */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 0, 0, 0, 0);
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);

    /* Version 255 (too high) */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 255, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);

    /* Version max uint16 */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 0xFFFF, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);

    return 0;
}

/* Test: Section exceeds file size */
TEST(invalid_section_exceeds_file) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 1, 0);
    ASSERT(hdr_size > 0);

    /* Section claims to be at offset 100 with length 200 = end at 300 */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 200, 0);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_ERR_SECTION_BOUNDS);

    return 0;
}

/* Test: Overlapping sections */
TEST(invalid_overlapping_sections) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 2, 0);
    ASSERT(hdr_size > 0);

    /* Two sections that overlap */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 50, 0);  /* 100-150 */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 120, 50, 0);  /* 120-170 */

    mbpf_section_desc_t sections[2];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 2, &count);
    ASSERT_EQ(err, MBPF_ERR_SECTION_OVERLAP);

    return 0;
}

/* Test: Invalid JSON manifest */
TEST(invalid_json_manifest) {
    mbpf_manifest_t mf;

    /* Completely invalid JSON */
    const char *invalid1 = "not json at all";
    int err = mbpf_package_parse_manifest(invalid1, strlen(invalid1), &mf);
    ASSERT_NE(err, MBPF_OK);

    /* Truncated JSON */
    const char *invalid2 = "{\"program_name\":\"test";
    err = mbpf_package_parse_manifest(invalid2, strlen(invalid2), &mf);
    ASSERT_NE(err, MBPF_OK);

    /* Empty JSON object */
    const char *invalid3 = "{}";
    err = mbpf_package_parse_manifest(invalid3, strlen(invalid3), &mf);
    ASSERT_NE(err, MBPF_OK);

    return 0;
}

/* Test: Manifest missing required fields */
TEST(invalid_manifest_missing_fields) {
    mbpf_manifest_t mf;

    /* Missing hook_type */
    const char *json1 =
        "{"
        "\"program_name\":\"test\","
        "\"program_version\":\"1.0\","
        "\"mquickjs_bytecode_version\":1,"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":16384,"
        "\"budgets\":{\"max_steps\":1000,\"max_helpers\":100}"
        "}";
    int err = mbpf_package_parse_manifest(json1, strlen(json1), &mf);
    ASSERT_NE(err, MBPF_OK);

    /* Missing budgets */
    const char *json2 =
        "{"
        "\"program_name\":\"test\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":16384"
        "}";
    err = mbpf_package_parse_manifest(json2, strlen(json2), &mf);
    ASSERT_NE(err, MBPF_OK);

    return 0;
}

/* Test: NULL pointer arguments */
TEST(invalid_null_pointers) {
    uint8_t buf[256];
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, 0);

    mbpf_file_header_t header;
    mbpf_section_desc_t sections[1];
    uint32_t count;
    const void *data;
    size_t len;

    /* NULL data to parse_header */
    int err = mbpf_package_parse_header(NULL, 256, &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL output header */
    err = mbpf_package_parse_header(buf, 256, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL data to parse_section_table */
    err = mbpf_package_parse_section_table(NULL, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL count pointer */
    err = mbpf_package_parse_section_table(buf, 256, sections, 1, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL data to get_section */
    err = mbpf_package_get_section(NULL, 256, MBPF_SEC_MANIFEST, &data, &len);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL output data */
    err = mbpf_package_get_section(buf, 256, MBPF_SEC_MANIFEST, NULL, &len);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL output len */
    err = mbpf_package_get_section(buf, 256, MBPF_SEC_MANIFEST, &data, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test: Section not found */
TEST(invalid_section_not_found) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 1, 0);
    ASSERT(hdr_size > 0);

    /* Only MANIFEST section exists */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 50, 0);

    const void *data;
    size_t len;

    /* Try to get BYTECODE section (doesn't exist) */
    int err = mbpf_package_get_section(buf, 256, MBPF_SEC_BYTECODE, &data, &len);
    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);

    /* Try to get DEBUG section (doesn't exist) */
    err = mbpf_package_get_section(buf, 256, MBPF_SEC_DEBUG, &data, &len);
    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);

    return 0;
}

/* Test: Header size mismatch */
TEST(invalid_header_size_mismatch) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    /* Create header manually with incorrect header_size */
    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, 1);           /* format_version */
    write_le16(buf + 6, 10);          /* header_size = 10 (way too small) */
    write_le32(buf + 8, 0);           /* flags */
    write_le32(buf + 12, 1);          /* section_count = 1 */
    write_le32(buf + 16, 0);          /* file_crc32 */

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);

    return 0;
}

/* ============================================================================
 * EDGE CASE TESTS
 * ============================================================================ */

/* Test: Empty section (zero length) */
TEST(edge_empty_section) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 2, 0);
    ASSERT(hdr_size > 0);

    /* Empty MANIFEST section followed by non-empty BYTECODE */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 0, 0);
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, (uint32_t)hdr_size, 50, 0);

    mbpf_section_desc_t sections[2];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 2, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sections[0].length, 0);

    const void *data;
    size_t len;
    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_MANIFEST, &data, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len, 0);

    return 0;
}

/* Test: Multiple empty sections at same offset */
TEST(edge_multiple_empty_sections) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 3, 0);
    ASSERT(hdr_size > 0);

    /* All three sections are empty and at the same offset */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 0, 0);
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, (uint32_t)hdr_size, 0, 0);
    add_section_desc(buf, 2, MBPF_SEC_MAPS, (uint32_t)hdr_size, 0, 0);

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    /* Empty sections don't overlap */
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 3);

    return 0;
}

/* Test: Section at exact file boundary */
TEST(edge_section_at_boundary) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 1, 0);
    ASSERT(hdr_size > 0);

    /* Section that ends exactly at byte 256 */
    size_t section_offset = hdr_size;
    size_t section_len = 256 - section_offset;
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)section_offset, (uint32_t)section_len, 0);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);

    /* One byte over should fail */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)section_offset, (uint32_t)section_len + 1, 0);
    err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_ERR_SECTION_BOUNDS);

    return 0;
}

/* Test: Zero sections */
TEST(edge_zero_sections) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, 0);
    ASSERT(hdr_size > 0);
    ASSERT_EQ(hdr_size, sizeof(mbpf_file_header_t));

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 0);

    /* Requesting a section that doesn't exist */
    const void *data;
    size_t len;
    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_MANIFEST, &data, &len);
    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);

    return 0;
}

/* Test: Maximum section count */
TEST(edge_max_section_count) {
    /* Create buffer large enough for many sections */
    uint8_t *buf = malloc(32768);
    ASSERT(buf != NULL);
    memset(buf, 0, 32768);

    /* Create header with 8 sections (max allowed by MBPF_MAX_SECTIONS) */
    size_t hdr_size = create_mbpf_header(buf, 32768, MBPF_MAGIC, 1, 0, 8, 0);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;
    for (int i = 0; i < 8; i++) {
        add_section_desc(buf, i, MBPF_SEC_MANIFEST + (i % 5), offset, 100, 0);
        offset += 100;
    }

    mbpf_section_desc_t sections[8];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 32768, sections, 8, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 8);

    free(buf);
    return 0;
}

/* Test: Large section length (near uint32 max) */
TEST(edge_large_section_length) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 1, 0);
    ASSERT(hdr_size > 0);

    /* Section with very large length that would overflow */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 0xFFFFFF00, 0);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_ERR_SECTION_BOUNDS);

    return 0;
}

/* Test: Sections with gaps between them */
TEST(edge_sections_with_gaps) {
    uint8_t buf[1024];
    memset(buf, 0xCC, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 3, 0);
    ASSERT(hdr_size > 0);

    /* Sections with gaps between them */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 50, 0);  /* 100-150 */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 200, 50, 0);  /* 200-250 (gap: 150-200) */
    add_section_desc(buf, 2, MBPF_SEC_MAPS, 400, 50, 0);      /* 400-450 (gap: 250-400) */

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 3);

    return 0;
}

/* Test: Sections in non-sequential offset order */
TEST(edge_sections_unordered) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 3, 0);
    ASSERT(hdr_size > 0);

    /* Sections listed out of order by offset */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 300, 50, 0);  /* Third by offset */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 100, 50, 0);  /* First by offset */
    add_section_desc(buf, 2, MBPF_SEC_MAPS, 200, 50, 0);      /* Second by offset */

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    ASSERT_EQ(err, MBPF_OK);

    /* Sections should be returned in table order, not offset order */
    ASSERT_EQ(sections[0].offset, 300);
    ASSERT_EQ(sections[1].offset, 100);
    ASSERT_EQ(sections[2].offset, 200);

    return 0;
}

/* Test: Unknown section types are preserved */
TEST(edge_unknown_section_types) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 2, 0);
    ASSERT(hdr_size > 0);

    /* Known section followed by unknown section type */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 30, 0);
    add_section_desc(buf, 1, 999, 130, 40, 0);  /* Unknown type 999 */

    mbpf_section_desc_t sections[2];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 2, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 2);
    ASSERT_EQ(sections[1].type, 999);

    return 0;
}

/* Test: Integer overflow in offset + length */
TEST(edge_integer_overflow) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 1, 0);
    ASSERT(hdr_size > 0);

    /* offset=0xFFFFFFF0, length=0x20 would overflow to 0x10 */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 0xFFFFFFF0, 0x20, 0);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_ERR_SECTION_BOUNDS);

    return 0;
}

/* Test: Adjacent sections (not overlapping) */
TEST(edge_adjacent_sections) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 3, 0);
    ASSERT(hdr_size > 0);

    /* Sections that are exactly adjacent */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 50, 0);   /* 100-150 */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 150, 50, 0);   /* 150-200 */
    add_section_desc(buf, 2, MBPF_SEC_MAPS, 200, 50, 0);       /* 200-250 */

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 3);

    return 0;
}

/* Test: Manifest with empty maps array */
TEST(edge_manifest_empty_maps) {
    const char *json =
        "{"
        "\"program_name\":\"test\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":16384,"
        "\"budgets\":{\"max_steps\":10000,\"max_helpers\":100},"
        "\"capabilities\":[],"
        "\"maps\":[]"
        "}";

    mbpf_manifest_t mf;
    memset(&mf, 0, sizeof(mf));
    int err = mbpf_package_parse_manifest(json, strlen(json), &mf);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(mf.map_count, 0);
    ASSERT(mf.maps == NULL);

    mbpf_manifest_free(&mf);
    return 0;
}

/* Test: Manifest with long program name */
TEST(edge_manifest_long_name) {
    char json[2048];
    char long_name[70];  /* Longer than program_name[64] in manifest struct */
    memset(long_name, 'A', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';

    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"%s\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":16384,"
        "\"budgets\":{\"max_steps\":10000,\"max_helpers\":100},"
        "\"capabilities\":[]"
        "}",
        long_name);

    mbpf_manifest_t mf;
    memset(&mf, 0, sizeof(mf));
    int err = mbpf_package_parse_manifest(json, strlen(json), &mf);
    ASSERT_EQ(err, MBPF_OK);
    /* Name should be truncated to fit */
    ASSERT(strlen(mf.program_name) < 64);

    mbpf_manifest_free(&mf);
    return 0;
}

/* Test: Signature section verification */
TEST(edge_signature_section) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1,
                                          MBPF_FLAG_SIGNED, 2, 0);
    ASSERT(hdr_size > 0);

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 50, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, (uint32_t)hdr_size + 50, 64, 0);

    /* Check if package is signed */
    int is_signed = 0;
    int err = mbpf_package_is_signed(buf, sizeof(buf), &is_signed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(is_signed, 1);

    return 0;
}

/* Test: Package without signature section */
TEST(edge_unsigned_package) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 1, 0);
    ASSERT(hdr_size > 0);

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 50, 0);

    /* Check if package is signed */
    int is_signed = 1;  /* Set to 1 to verify it gets set to 0 */
    int err = mbpf_package_is_signed(buf, sizeof(buf), &is_signed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(is_signed, 0);

    return 0;
}

/* Test: CRC32 on empty data */
TEST(edge_crc32_empty) {
    uint32_t crc = mbpf_crc32("", 0);
    /* CRC32 of empty data should be 0 (standard CRC32 behavior) */
    ASSERT_EQ(crc, 0);

    return 0;
}

/* Test: CRC32 on single byte */
TEST(edge_crc32_single_byte) {
    uint8_t byte = 0x42;
    uint32_t crc = mbpf_crc32(&byte, 1);
    ASSERT_NE(crc, 0);

    /* Different byte should produce different CRC */
    byte = 0x43;
    uint32_t crc2 = mbpf_crc32(&byte, 1);
    ASSERT_NE(crc, crc2);

    return 0;
}

/* Test: Parse just header (minimal valid package) */
TEST(edge_minimal_header_only) {
    uint8_t buf[32];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, 0);
    ASSERT_EQ(hdr_size, sizeof(mbpf_file_header_t));

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.magic, MBPF_MAGIC);
    ASSERT_EQ(header.format_version, 1);
    ASSERT_EQ(header.section_count, 0);

    return 0;
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Package Parser Unit Tests\n");
    printf("===================================\n\n");

    printf("Valid package parsing tests:\n");
    RUN_TEST(valid_complete_package);
    RUN_TEST(valid_multiple_sections);
    RUN_TEST(valid_all_section_types);
    RUN_TEST(valid_manifest_full_fields);
    RUN_TEST(valid_manifest_with_maps);
    RUN_TEST(valid_crc32_computation);

    printf("\nInvalid input tests:\n");
    RUN_TEST(invalid_corrupted_magic);
    RUN_TEST(invalid_truncated_data);
    RUN_TEST(invalid_format_version);
    RUN_TEST(invalid_section_exceeds_file);
    RUN_TEST(invalid_overlapping_sections);
    RUN_TEST(invalid_json_manifest);
    RUN_TEST(invalid_manifest_missing_fields);
    RUN_TEST(invalid_null_pointers);
    RUN_TEST(invalid_section_not_found);
    RUN_TEST(invalid_header_size_mismatch);

    printf("\nEdge case tests:\n");
    RUN_TEST(edge_empty_section);
    RUN_TEST(edge_multiple_empty_sections);
    RUN_TEST(edge_section_at_boundary);
    RUN_TEST(edge_zero_sections);
    RUN_TEST(edge_max_section_count);
    RUN_TEST(edge_large_section_length);
    RUN_TEST(edge_sections_with_gaps);
    RUN_TEST(edge_sections_unordered);
    RUN_TEST(edge_unknown_section_types);
    RUN_TEST(edge_integer_overflow);
    RUN_TEST(edge_adjacent_sections);
    RUN_TEST(edge_manifest_empty_maps);
    RUN_TEST(edge_manifest_long_name);
    RUN_TEST(edge_signature_section);
    RUN_TEST(edge_unsigned_package);
    RUN_TEST(edge_crc32_empty);
    RUN_TEST(edge_crc32_single_byte);
    RUN_TEST(edge_minimal_header_only);

    printf("\n===================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
