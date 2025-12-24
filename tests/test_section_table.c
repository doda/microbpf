/*
 * microBPF Section Table Tests
 *
 * Tests for .mbpf section descriptor parsing, bounds checking, and overlap detection.
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

/* Create a minimal valid .mbpf header */
static size_t create_mbpf_header(uint8_t *buf, size_t buflen,
                                  uint32_t section_count) {
    size_t header_size = sizeof(mbpf_file_header_t) +
                         section_count * sizeof(mbpf_section_desc_t);

    if (buflen < header_size) return 0;

    memset(buf, 0, buflen);

    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, 1);  /* format_version */
    write_le16(buf + 6, (uint16_t)header_size);
    write_le32(buf + 8, 0);  /* flags */
    write_le32(buf + 12, section_count);
    write_le32(buf + 16, 0); /* file_crc32 */

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

/* Test 1: Parse package with all five section types */
TEST(multiple_sections_all_types) {
    uint8_t buf[512];
    memset(buf, 0xAB, sizeof(buf));

    /* Header with 5 sections */
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 5);
    ASSERT(hdr_size > 0);

    /* Section layout: MANIFEST=32, BYTECODE=64, MAPS=16, DEBUG=32, SIG=64 */
    uint32_t offset = (uint32_t)hdr_size;
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 32, 0);
    offset += 32;
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 64, 0);
    offset += 64;
    add_section_desc(buf, 2, MBPF_SEC_MAPS, offset, 16, 0);
    offset += 16;
    add_section_desc(buf, 3, MBPF_SEC_DEBUG, offset, 32, 0);
    offset += 32;
    add_section_desc(buf, 4, MBPF_SEC_SIG, offset, 64, 0);

    mbpf_section_desc_t sections[5];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 5, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 5);

    /* Verify each section type and size */
    ASSERT_EQ(sections[0].type, MBPF_SEC_MANIFEST);
    ASSERT_EQ(sections[0].length, 32);
    ASSERT_EQ(sections[1].type, MBPF_SEC_BYTECODE);
    ASSERT_EQ(sections[1].length, 64);
    ASSERT_EQ(sections[2].type, MBPF_SEC_MAPS);
    ASSERT_EQ(sections[2].length, 16);
    ASSERT_EQ(sections[3].type, MBPF_SEC_DEBUG);
    ASSERT_EQ(sections[3].length, 32);
    ASSERT_EQ(sections[4].type, MBPF_SEC_SIG);
    ASSERT_EQ(sections[4].length, 64);

    return 0;
}

/* Test 2: Verify section type, offset, length, crc32 are read correctly */
TEST(read_section_fields) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2);
    ASSERT(hdr_size > 0);

    /* Section 0: type=1, offset=100, length=50, crc32=0x12345678 */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 50, 0x12345678);

    /* Section 1: type=2, offset=150, length=80, crc32=0xDEADBEEF */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 150, 80, 0xDEADBEEF);

    mbpf_section_desc_t sections[2];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 2, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 2);

    /* Verify section 0 */
    ASSERT_EQ(sections[0].type, MBPF_SEC_MANIFEST);
    ASSERT_EQ(sections[0].offset, 100);
    ASSERT_EQ(sections[0].length, 50);
    ASSERT_EQ(sections[0].crc32, 0x12345678);

    /* Verify section 1 */
    ASSERT_EQ(sections[1].type, MBPF_SEC_BYTECODE);
    ASSERT_EQ(sections[1].offset, 150);
    ASSERT_EQ(sections[1].length, 80);
    ASSERT_EQ(sections[1].crc32, 0xDEADBEEF);

    return 0;
}

/* Test 3: Validate section bounds don't exceed file size */
TEST(validate_section_bounds) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1);
    ASSERT(hdr_size > 0);

    /* Section that extends beyond file size */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 200, 100, 0);
    /* offset=200 + length=100 = 300, but file is only 256 bytes */

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_ERR_SECTION_BOUNDS);

    return 0;
}

/* Test 4: Validate bounds check at exact boundary */
TEST(validate_section_bounds_exact) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1);
    ASSERT(hdr_size > 0);

    /* Section that ends exactly at file boundary - should be valid */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 156, 0);
    /* offset=100 + length=156 = 256, exactly file size */

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);

    /* One byte over should fail */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 157, 0);
    err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_ERR_SECTION_BOUNDS);

    return 0;
}

/* Test 5: Detect overlapping sections */
TEST(detect_overlapping_sections) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2);
    ASSERT(hdr_size > 0);

    /* Sections that overlap: both claim bytes 100-150 */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 80, 40, 0);  /* 80-120 */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 100, 40, 0); /* 100-140 */
    /* These overlap at 100-120 */

    mbpf_section_desc_t sections[2];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 2, &count);
    ASSERT_EQ(err, MBPF_ERR_SECTION_OVERLAP);

    return 0;
}

/* Test 6: Adjacent sections (not overlapping) should be valid */
TEST(adjacent_sections_valid) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2);
    ASSERT(hdr_size > 0);

    /* Sections that are exactly adjacent: no overlap */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 80, 40, 0);   /* 80-120 */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 120, 40, 0);  /* 120-160 */

    mbpf_section_desc_t sections[2];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 2, &count);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test 7: Unknown section types are parsed correctly (not rejected) */
TEST(unknown_section_type_skipped) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 3);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 20, 0);
    offset += 20;
    add_section_desc(buf, 1, 99, offset, 30, 0);  /* Unknown type 99 */
    offset += 30;
    add_section_desc(buf, 2, MBPF_SEC_BYTECODE, offset, 40, 0);

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 3, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 3);

    /* Unknown section is read but type is preserved */
    ASSERT_EQ(sections[0].type, MBPF_SEC_MANIFEST);
    ASSERT_EQ(sections[1].type, 99);  /* Unknown type preserved */
    ASSERT_EQ(sections[2].type, MBPF_SEC_BYTECODE);

    return 0;
}

/* Test 8: Very high unknown section type values */
TEST(unknown_section_type_high_value) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1);
    ASSERT(hdr_size > 0);

    /* Section with max uint32 type value */
    add_section_desc(buf, 0, 0xFFFFFFFF, 100, 50, 0);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sections[0].type, 0xFFFFFFFF);

    return 0;
}

/* Test 9: Empty package (0 sections) */
TEST(zero_sections) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 0);
    ASSERT(hdr_size > 0);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 0);

    return 0;
}

/* Test 10: Just get count without reading sections */
TEST(get_count_only) {
    uint8_t buf[256];
    create_mbpf_header(buf, sizeof(buf), 5);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 10, 0);
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 110, 10, 0);
    add_section_desc(buf, 2, MBPF_SEC_MAPS, 120, 10, 0);
    add_section_desc(buf, 3, MBPF_SEC_DEBUG, 130, 10, 0);
    add_section_desc(buf, 4, MBPF_SEC_SIG, 140, 10, 0);

    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), NULL, 0, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 5);

    return 0;
}

/* Test 11: Buffer too small for requested sections */
TEST(buffer_too_small) {
    uint8_t buf[256];
    create_mbpf_header(buf, sizeof(buf), 5);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 10, 0);
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 110, 10, 0);
    add_section_desc(buf, 2, MBPF_SEC_MAPS, 120, 10, 0);
    add_section_desc(buf, 3, MBPF_SEC_DEBUG, 130, 10, 0);
    add_section_desc(buf, 4, MBPF_SEC_SIG, 140, 10, 0);

    mbpf_section_desc_t sections[3];  /* Only room for 3 */
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test 12: NULL data pointer */
TEST(null_data) {
    mbpf_section_desc_t sections[5];
    uint32_t count;
    int err = mbpf_package_parse_section_table(NULL, 256, sections, 5, &count);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test 13: NULL count pointer */
TEST(null_count) {
    uint8_t buf[256];
    create_mbpf_header(buf, sizeof(buf), 1);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 100, 10, 0);

    mbpf_section_desc_t sections[1];
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test 14: Section with offset inside header area */
TEST(section_offset_in_header) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1);
    ASSERT(hdr_size > 0);

    /* Section starting at offset 10, which is inside the header */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 10, 20, 0);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    /* This should technically work (bounds are within file)
       but the offset is before header ends. The parser accepts this
       since it only checks that section fits within file bounds. */
    int err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test 15: Section with zero length (empty section) */
TEST(empty_section) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 0, 0);  /* Empty */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 50, 0);

    mbpf_section_desc_t sections[2];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 2, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sections[0].length, 0);

    return 0;
}

/* Test 16: Two empty sections at same offset (not overlapping) */
TEST(two_empty_sections_same_offset) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 0, 0);  /* Empty */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 0, 0);  /* Empty */

    mbpf_section_desc_t sections[2];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 2, &count);
    /* Empty sections don't overlap */
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test 17: Overlapping with many sections */
TEST(overlap_in_many_sections) {
    uint8_t buf[512];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 5);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 20, 0);
    offset += 20;
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 40, 0);
    offset += 40;
    add_section_desc(buf, 2, MBPF_SEC_MAPS, offset, 30, 0);
    /* Section 3 overlaps with section 2 */
    add_section_desc(buf, 3, MBPF_SEC_DEBUG, offset + 10, 30, 0);
    offset += 60;
    add_section_desc(buf, 4, MBPF_SEC_SIG, offset, 40, 0);

    mbpf_section_desc_t sections[5];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 5, &count);
    ASSERT_EQ(err, MBPF_ERR_SECTION_OVERLAP);

    return 0;
}

/* Test 18: Non-contiguous sections (gaps between them) */
TEST(non_contiguous_sections) {
    uint8_t buf[512];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 3);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 20, 0);
    offset += 50;  /* 30 byte gap */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 40, 0);
    offset += 100; /* 60 byte gap */
    add_section_desc(buf, 2, MBPF_SEC_MAPS, offset, 30, 0);

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test 19: Sections out of order (by offset) */
TEST(sections_out_of_order) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 3);
    ASSERT(hdr_size > 0);

    /* Sections listed in non-ascending offset order */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 150, 20, 0);  /* highest */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, 100, 30, 0);  /* middle */
    add_section_desc(buf, 2, MBPF_SEC_MAPS, 180, 20, 0);       /* last */

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 3);

    /* Verify sections are returned in table order, not offset order */
    ASSERT_EQ(sections[0].offset, 150);
    ASSERT_EQ(sections[1].offset, 100);
    ASSERT_EQ(sections[2].offset, 180);

    return 0;
}

/* Test 20: Integer overflow in bounds check */
TEST(bounds_overflow) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1);
    ASSERT(hdr_size > 0);

    /* Section with offset+length that would overflow uint32 */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, 0xFFFFFFF0, 0x20, 0);
    /* 0xFFFFFFF0 + 0x20 = 0x100000010, which overflows to 0x10 */

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, 256, sections, 1, &count);
    /* This should fail because actual end > file size */
    ASSERT_EQ(err, MBPF_ERR_SECTION_BOUNDS);

    return 0;
}

/* Test 21: Use mbpf_package_get_section with parsed sections */
TEST(get_section_after_parse) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 3);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;

    /* Put recognizable data in each section */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 10, 0);
    memset(buf + offset, 0x11, 10);
    offset += 10;

    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 20, 0);
    memset(buf + offset, 0x22, 20);
    offset += 20;

    add_section_desc(buf, 2, MBPF_SEC_MAPS, offset, 15, 0);
    memset(buf + offset, 0x33, 15);

    /* Verify get_section finds each */
    const void *sec_data;
    size_t sec_len;

    int err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_MANIFEST,
                                        &sec_data, &sec_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sec_len, 10);
    ASSERT_EQ(((const uint8_t *)sec_data)[0], 0x11);

    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_BYTECODE,
                                    &sec_data, &sec_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sec_len, 20);
    ASSERT_EQ(((const uint8_t *)sec_data)[0], 0x22);

    err = mbpf_package_get_section(buf, sizeof(buf), MBPF_SEC_MAPS,
                                    &sec_data, &sec_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sec_len, 15);
    ASSERT_EQ(((const uint8_t *)sec_data)[0], 0x33);

    return 0;
}

/* Test 22: Verify CRC32 field is read correctly */
TEST(section_crc32_values) {
    uint8_t buf[256];
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 3);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 20, 0x11111111);
    offset += 20;
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 40, 0x22222222);
    offset += 40;
    add_section_desc(buf, 2, MBPF_SEC_MAPS, offset, 30, 0x33333333);

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(sections[0].crc32, 0x11111111);
    ASSERT_EQ(sections[1].crc32, 0x22222222);
    ASSERT_EQ(sections[2].crc32, 0x33333333);

    return 0;
}

/* ========================================================================== */
/* Main */
/* ========================================================================== */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Section Table Tests\n");
    printf("============================\n");

    /* Multiple section types */
    RUN_TEST(multiple_sections_all_types);
    RUN_TEST(read_section_fields);
    RUN_TEST(section_crc32_values);

    /* Bounds validation */
    RUN_TEST(validate_section_bounds);
    RUN_TEST(validate_section_bounds_exact);
    RUN_TEST(bounds_overflow);

    /* Overlap detection */
    RUN_TEST(detect_overlapping_sections);
    RUN_TEST(adjacent_sections_valid);
    RUN_TEST(overlap_in_many_sections);

    /* Unknown section types */
    RUN_TEST(unknown_section_type_skipped);
    RUN_TEST(unknown_section_type_high_value);

    /* Edge cases */
    RUN_TEST(zero_sections);
    RUN_TEST(get_count_only);
    RUN_TEST(buffer_too_small);
    RUN_TEST(null_data);
    RUN_TEST(null_count);
    RUN_TEST(section_offset_in_header);
    RUN_TEST(empty_section);
    RUN_TEST(two_empty_sections_same_offset);
    RUN_TEST(non_contiguous_sections);
    RUN_TEST(sections_out_of_order);

    /* Integration with get_section */
    RUN_TEST(get_section_after_parse);

    printf("\nResults: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
