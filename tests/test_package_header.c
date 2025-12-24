/*
 * microBPF Package Header Tests
 *
 * Tests for .mbpf file header parsing: magic number, version, section table.
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

    /* Write header fields */
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

/* ========================================================================== */
/* Test Cases */
/* ========================================================================== */

/* Test 1: Valid header with magic 0x4D425046 is parsed correctly */
TEST(valid_magic) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf),
                                          MBPF_MAGIC,  /* 0x4D425046 */
                                          1,           /* format_version */
                                          0,           /* flags */
                                          0,           /* section_count */
                                          0);          /* file_crc32 */
    ASSERT(hdr_size > 0);

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.magic, MBPF_MAGIC);

    return 0;
}

/* Test 2: Magic bytes are verified correctly (0x4D = 'M', 0x42 = 'B', etc.) */
TEST(magic_bytes_check) {
    uint8_t buf[256];
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, 0);

    /* Verify the raw bytes match expected magic */
    ASSERT_EQ(buf[0], 0x46);  /* 'F' in little-endian (lowest byte) */
    ASSERT_EQ(buf[1], 0x50);  /* 'P' */
    ASSERT_EQ(buf[2], 0x42);  /* 'B' */
    ASSERT_EQ(buf[3], 0x4D);  /* 'M' */

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test 3: Parser reads header_size correctly */
TEST(parse_header_size) {
    uint8_t buf[256];

    /* Header with 2 sections = 20 + 2*16 = 52 bytes */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 2, 0);
    /* Add section descriptors to reach proper offset */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 52, 10, 0);
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 62, 10, 0);

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.header_size, 52);

    return 0;
}

/* Test 4: Parser reads flags correctly */
TEST(parse_flags) {
    uint8_t buf[256];

    /* Test with SIGNED flag */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, MBPF_FLAG_SIGNED, 0, 0);

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.flags, MBPF_FLAG_SIGNED);

    /* Test with DEBUG flag */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, MBPF_FLAG_DEBUG, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.flags, MBPF_FLAG_DEBUG);

    /* Test with both flags */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1,
                       MBPF_FLAG_SIGNED | MBPF_FLAG_DEBUG, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.flags, MBPF_FLAG_SIGNED | MBPF_FLAG_DEBUG);

    return 0;
}

/* Test 5: Parser reads section_count correctly */
TEST(parse_section_count) {
    uint8_t buf[512];

    /* Test with 0 sections */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, 0);
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.section_count, 0);

    /* Test with 3 sections */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 3, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.section_count, 3);

    /* Test with 5 sections */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 5, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.section_count, 5);

    return 0;
}

/* Test 6: Parser reads file_crc32 correctly */
TEST(parse_file_crc32) {
    uint8_t buf[256];

    /* Test with specific CRC value */
    uint32_t test_crc = 0xDEADBEEF;
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, test_crc);

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.file_crc32, test_crc);

    /* Test with zero CRC (unused) */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.file_crc32, 0);

    return 0;
}

/* Test 7: Parser rejects files with invalid magic */
TEST(reject_invalid_magic) {
    uint8_t buf[256];
    mbpf_file_header_t header;
    int err;

    /* Wrong magic: "BAD!" */
    create_mbpf_header(buf, sizeof(buf), 0x21444142, 1, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);

    /* Wrong magic: all zeros */
    create_mbpf_header(buf, sizeof(buf), 0x00000000, 1, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);

    /* Wrong magic: similar but wrong */
    create_mbpf_header(buf, sizeof(buf), 0x4D425047, 1, 0, 0, 0);  /* 'MBPG' */
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);

    /* Wrong magic: reversed endianness */
    create_mbpf_header(buf, sizeof(buf), 0x4650424D, 1, 0, 0, 0);  /* byte-swapped */
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);

    return 0;
}

/* Test 8: Parser handles format_version=1 (current version) */
TEST(format_version_current) {
    uint8_t buf[256];
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, 0);

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.format_version, 1);

    return 0;
}

/* Test 9: Parser rejects format_version=0 */
TEST(reject_version_zero) {
    uint8_t buf[256];
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 0, 0, 0, 0);

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);

    return 0;
}

/* Test 10: Parser rejects unsupported future versions */
TEST(reject_future_version) {
    uint8_t buf[256];
    mbpf_file_header_t header;
    int err;

    /* Version 2 (future) */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 2, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);

    /* Very high version */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 100, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);

    /* Max uint16_t version */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 0xFFFF, 0, 0, 0);
    err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);

    return 0;
}

/* Test 11: Parser rejects NULL data */
TEST(reject_null_data) {
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(NULL, 100, &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test 12: Parser rejects data too small for header */
TEST(reject_too_small) {
    uint8_t buf[10] = {0};  /* Less than sizeof(mbpf_file_header_t) */
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test 13: Parser rejects NULL output header */
TEST(reject_null_output) {
    uint8_t buf[256];
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 0, 0);

    int err = mbpf_package_parse_header(buf, sizeof(buf), NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test 14: Parser rejects header_size that doesn't fit in buffer */
TEST(reject_header_exceeds_buffer) {
    uint8_t buf[256];

    /* Create header claiming 10 sections but buffer is small */
    create_mbpf_header(buf, sizeof(buf), MBPF_MAGIC, 1, 0, 10, 0);

    /* Buffer only has 50 bytes, but header claims 20 + 10*16 = 180 bytes */
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, 50, &header);
    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);

    return 0;
}

/* Test 15: Parser works with complete valid package structure */
TEST(complete_valid_package) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));

    /* Header with 2 sections: MANIFEST and BYTECODE */
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf),
                                          MBPF_MAGIC, 1,
                                          MBPF_FLAG_DEBUG,
                                          2, 0);

    /* Section 0: MANIFEST at offset 52, length 32 */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    /* Section 1: BYTECODE at offset 84, length 64 */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, (uint32_t)hdr_size + 32, 64, 0);

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.magic, MBPF_MAGIC);
    ASSERT_EQ(header.format_version, 1);
    ASSERT_EQ(header.header_size, hdr_size);
    ASSERT_EQ(header.flags, MBPF_FLAG_DEBUG);
    ASSERT_EQ(header.section_count, 2);

    return 0;
}

/* Test 16: Verify MBPF_MAGIC constant matches spec (0x4D425046 = "MBPF") */
TEST(magic_constant_value) {
    /* According to spec: magic is "MBPF" in little-endian = 0x4D425046 */
    ASSERT_EQ(MBPF_MAGIC, 0x4D425046);

    /* Verify byte layout: "FPBM" when read as bytes in memory (little-endian) */
    uint8_t expected[4] = {0x46, 0x50, 0x42, 0x4D};  /* "FPBM" */
    uint32_t magic_from_bytes = expected[0] | (expected[1] << 8) |
                                 (expected[2] << 16) | (expected[3] << 24);
    ASSERT_EQ(magic_from_bytes, MBPF_MAGIC);

    return 0;
}

/* Test 17: Verify format version constant */
TEST(format_version_constant) {
    ASSERT_EQ(MBPF_FORMAT_VERSION, 1);

    return 0;
}

/* Test 18: Read header from file (optional demonstration) */
TEST(all_header_fields_parsed) {
    uint8_t buf[256];

    /* Create header with all non-zero fields */
    create_mbpf_header(buf, sizeof(buf),
                       MBPF_MAGIC,           /* magic */
                       1,                     /* format_version */
                       MBPF_FLAG_SIGNED | MBPF_FLAG_DEBUG,  /* flags */
                       3,                     /* section_count */
                       0x12345678);           /* file_crc32 */

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(buf, sizeof(buf), &header);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify all fields */
    ASSERT_EQ(header.magic, MBPF_MAGIC);
    ASSERT_EQ(header.format_version, 1);
    ASSERT_EQ(header.header_size, 20 + 3 * 16);  /* header + 3 section descriptors */
    ASSERT_EQ(header.flags, MBPF_FLAG_SIGNED | MBPF_FLAG_DEBUG);
    ASSERT_EQ(header.section_count, 3);
    ASSERT_EQ(header.file_crc32, 0x12345678);

    return 0;
}

/* ========================================================================== */
/* Main */
/* ========================================================================== */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Package Header Tests\n");
    printf("=============================\n");

    /* Magic and basic parsing */
    RUN_TEST(valid_magic);
    RUN_TEST(magic_bytes_check);
    RUN_TEST(magic_constant_value);

    /* Header field parsing */
    RUN_TEST(parse_header_size);
    RUN_TEST(parse_flags);
    RUN_TEST(parse_section_count);
    RUN_TEST(parse_file_crc32);
    RUN_TEST(all_header_fields_parsed);

    /* Version handling */
    RUN_TEST(format_version_current);
    RUN_TEST(format_version_constant);
    RUN_TEST(reject_version_zero);
    RUN_TEST(reject_future_version);

    /* Invalid input rejection */
    RUN_TEST(reject_invalid_magic);
    RUN_TEST(reject_null_data);
    RUN_TEST(reject_too_small);
    RUN_TEST(reject_null_output);
    RUN_TEST(reject_header_exceeds_buffer);

    /* Complete package */
    RUN_TEST(complete_valid_package);

    printf("\nResults: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
