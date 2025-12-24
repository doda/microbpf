/*
 * microBPF CRC32 Validation Tests
 *
 * Tests for file-level and per-section CRC32 validation.
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
                                  uint32_t section_count, uint32_t file_crc) {
    size_t header_size = sizeof(mbpf_file_header_t) +
                         section_count * sizeof(mbpf_section_desc_t);

    if (buflen < header_size) return 0;

    memset(buf, 0, buflen);

    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, 1);  /* format_version */
    write_le16(buf + 6, (uint16_t)header_size);
    write_le32(buf + 8, 0);  /* flags */
    write_le32(buf + 12, section_count);
    write_le32(buf + 16, file_crc); /* file_crc32 */

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

/*
 * Compute CRC32 over file data, skipping the file_crc32 field (bytes 16-19).
 * This is the same algorithm used by mbpf_package_validate_crc.
 */
static uint32_t compute_file_crc(const uint8_t *buf, size_t len) {
    /* Use mbpf_crc32 in two parts, skipping bytes 16-19 */
    /* Actually, we need to reimplement here since we can't call the internal func */

    /* CRC32 lookup table (IEEE polynomial) */
    static uint32_t crc32_table[256];
    static int table_init = 0;

    if (!table_init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int j = 0; j < 8; j++) {
                if (c & 1) {
                    c = 0xEDB88320 ^ (c >> 1);
                } else {
                    c >>= 1;
                }
            }
            crc32_table[i] = c;
        }
        table_init = 1;
    }

    uint32_t crc = 0xFFFFFFFF;

    /* Process bytes before file_crc32 field (bytes 0-15) */
    for (size_t i = 0; i < 16 && i < len; i++) {
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }

    /* Skip bytes 16-19 (file_crc32 field) */

    /* Process bytes after file_crc32 field (bytes 20 onwards) */
    for (size_t i = 20; i < len; i++) {
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

/* ========================================================================== */
/* Test Cases: Basic CRC32 function */
/* ========================================================================== */

/* Test: mbpf_crc32 produces expected values */
TEST(crc32_known_values) {
    /* CRC32 of "123456789" should be 0xCBF43926 (IEEE standard test vector) */
    const uint8_t test_vec[] = "123456789";
    uint32_t crc = mbpf_crc32(test_vec, 9);
    ASSERT_EQ(crc, 0xCBF43926);

    /* CRC32 of empty data should be 0 */
    crc = mbpf_crc32(test_vec, 0);
    ASSERT_EQ(crc, 0);

    /* CRC32 of a single byte */
    uint8_t single = 0x00;
    crc = mbpf_crc32(&single, 1);
    /* CRC of 0x00 is 0xD202EF8D */
    ASSERT_EQ(crc, 0xD202EF8D);

    return 0;
}

/* Test: mbpf_crc32 is deterministic */
TEST(crc32_deterministic) {
    uint8_t data[100];
    for (int i = 0; i < 100; i++) {
        data[i] = (uint8_t)(i * 7 + 13);
    }

    uint32_t crc1 = mbpf_crc32(data, sizeof(data));
    uint32_t crc2 = mbpf_crc32(data, sizeof(data));
    ASSERT_EQ(crc1, crc2);

    /* Change one byte, CRC should be different */
    data[50] ^= 0xFF;
    uint32_t crc3 = mbpf_crc32(data, sizeof(data));
    ASSERT_NE(crc1, crc3);

    return 0;
}

/* ========================================================================== */
/* Test Cases: File-level CRC validation */
/* ========================================================================== */

/* Test: Create .mbpf with valid CRC32 in header */
TEST(valid_file_crc) {
    uint8_t buf[256];
    memset(buf, 0xAA, sizeof(buf));

    /* Create header with 1 section, zero CRC initially */
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    /* Add section */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    /* Compute correct file CRC and write it */
    uint32_t file_crc = compute_file_crc(buf, sizeof(buf));
    write_le32(buf + 16, file_crc);

    /* Validate should pass */
    int err = mbpf_package_validate_crc(buf, sizeof(buf));
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test: Loader validates file_crc32 when non-zero */
TEST(file_crc_validation_enabled) {
    uint8_t buf[256];
    memset(buf, 0xBB, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    /* Set a non-zero but incorrect CRC */
    write_le32(buf + 16, 0xDEADBEEF);

    /* Validation should fail */
    int err = mbpf_package_validate_crc(buf, sizeof(buf));
    ASSERT_EQ(err, MBPF_ERR_CRC_MISMATCH);

    return 0;
}

/* Test: Zero file_crc32 means CRC is not checked */
TEST(file_crc_zero_not_checked) {
    uint8_t buf[256];
    memset(buf, 0xCC, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    /* Leave file_crc32 as 0 - validation should pass without checking */
    ASSERT_EQ(buf[16], 0);
    ASSERT_EQ(buf[17], 0);
    ASSERT_EQ(buf[18], 0);
    ASSERT_EQ(buf[19], 0);

    int err = mbpf_package_validate_crc(buf, sizeof(buf));
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test: File CRC rejects corrupted data */
TEST(file_crc_rejects_corruption) {
    uint8_t buf[256];
    memset(buf, 0xDD, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    /* Compute and set valid CRC */
    uint32_t file_crc = compute_file_crc(buf, sizeof(buf));
    write_le32(buf + 16, file_crc);

    /* Verify it passes */
    int err = mbpf_package_validate_crc(buf, sizeof(buf));
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt a byte in the data portion */
    buf[100] ^= 0xFF;

    /* Should now fail */
    err = mbpf_package_validate_crc(buf, sizeof(buf));
    ASSERT_EQ(err, MBPF_ERR_CRC_MISMATCH);

    return 0;
}

/* Test: File CRC covers header fields (except crc field itself) */
TEST(file_crc_covers_header) {
    uint8_t buf[256];
    memset(buf, 0xEE, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    uint32_t file_crc = compute_file_crc(buf, sizeof(buf));
    write_le32(buf + 16, file_crc);

    /* Verify passes */
    int err = mbpf_package_validate_crc(buf, sizeof(buf));
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt the flags field (bytes 8-11) */
    buf[8] ^= 0x01;

    /* Should fail because CRC covers header */
    err = mbpf_package_validate_crc(buf, sizeof(buf));
    ASSERT_EQ(err, MBPF_ERR_CRC_MISMATCH);

    return 0;
}

/* ========================================================================== */
/* Test Cases: Per-section CRC validation */
/* ========================================================================== */

/* Test: Create .mbpf with valid per-section CRC32 */
TEST(valid_section_crc) {
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    /* Put known data in section area */
    uint32_t sec_offset = (uint32_t)hdr_size;
    uint32_t sec_len = 32;
    memset(buf + sec_offset, 0x42, sec_len);

    /* Compute CRC of section data */
    uint32_t sec_crc = mbpf_crc32(buf + sec_offset, sec_len);

    /* Add section with correct CRC */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, sec_offset, sec_len, sec_crc);

    /* Parse sections */
    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 1);

    /* Validate section CRC - should pass */
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test: Loader validates per-section crc32 when non-zero */
TEST(section_crc_validation_enabled) {
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    uint32_t sec_offset = (uint32_t)hdr_size;
    uint32_t sec_len = 32;
    memset(buf + sec_offset, 0x43, sec_len);

    /* Set wrong CRC (non-zero) */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, sec_offset, sec_len, 0xBADC0DE);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);

    /* Validation should fail */
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_ERR_CRC_MISMATCH);

    return 0;
}

/* Test: Zero section crc32 means CRC is not checked */
TEST(section_crc_zero_not_checked) {
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    uint32_t sec_offset = (uint32_t)hdr_size;
    uint32_t sec_len = 32;
    memset(buf + sec_offset, 0x44, sec_len);

    /* Set CRC to 0 - means no validation */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, sec_offset, sec_len, 0);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sections[0].crc32, 0);

    /* Validation should pass (no check performed) */
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test: Section CRC rejects corrupted section data */
TEST(section_crc_rejects_corruption) {
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    uint32_t sec_offset = (uint32_t)hdr_size;
    uint32_t sec_len = 32;
    memset(buf + sec_offset, 0x45, sec_len);

    uint32_t sec_crc = mbpf_crc32(buf + sec_offset, sec_len);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, sec_offset, sec_len, sec_crc);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify passes initially */
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt section data */
    buf[sec_offset + 10] ^= 0xFF;

    /* Should fail now */
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_ERR_CRC_MISMATCH);

    return 0;
}

/* Test: Multiple sections with individual CRCs */
TEST(multiple_sections_with_crc) {
    uint8_t buf[512];
    memset(buf, 0x00, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 3, 0);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;

    /* Section 0: MANIFEST */
    uint32_t sec0_offset = offset;
    uint32_t sec0_len = 32;
    memset(buf + sec0_offset, 0x11, sec0_len);
    uint32_t sec0_crc = mbpf_crc32(buf + sec0_offset, sec0_len);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, sec0_offset, sec0_len, sec0_crc);
    offset += sec0_len;

    /* Section 1: BYTECODE */
    uint32_t sec1_offset = offset;
    uint32_t sec1_len = 64;
    memset(buf + sec1_offset, 0x22, sec1_len);
    uint32_t sec1_crc = mbpf_crc32(buf + sec1_offset, sec1_len);
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, sec1_offset, sec1_len, sec1_crc);
    offset += sec1_len;

    /* Section 2: DEBUG (no CRC) */
    uint32_t sec2_offset = offset;
    uint32_t sec2_len = 48;
    memset(buf + sec2_offset, 0x33, sec2_len);
    add_section_desc(buf, 2, MBPF_SEC_DEBUG, sec2_offset, sec2_len, 0);

    mbpf_section_desc_t sections[3];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 3, &count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(count, 3);

    /* All should validate */
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[1]);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[2]);
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt section 1 */
    buf[sec1_offset + 20] ^= 0xFF;

    /* Section 0 and 2 should still pass, section 1 should fail */
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[1]);
    ASSERT_EQ(err, MBPF_ERR_CRC_MISMATCH);
    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[2]);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* ========================================================================== */
/* Test Cases: Combined file and section CRC */
/* ========================================================================== */

/* Test: Both file and section CRCs valid */
TEST(both_file_and_section_crc_valid) {
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    uint32_t sec_offset = (uint32_t)hdr_size;
    uint32_t sec_len = 32;
    memset(buf + sec_offset, 0x55, sec_len);

    /* Set section CRC */
    uint32_t sec_crc = mbpf_crc32(buf + sec_offset, sec_len);
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, sec_offset, sec_len, sec_crc);

    /* Set file CRC (must be done after section CRC is written) */
    uint32_t file_crc = compute_file_crc(buf, sizeof(buf));
    write_le32(buf + 16, file_crc);

    /* Both should validate */
    int err = mbpf_package_validate_crc(buf, sizeof(buf));
    ASSERT_EQ(err, MBPF_OK);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test: File CRC valid but section CRC invalid */
TEST(file_crc_valid_section_invalid) {
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    uint32_t sec_offset = (uint32_t)hdr_size;
    uint32_t sec_len = 32;
    memset(buf + sec_offset, 0x66, sec_len);

    /* Set WRONG section CRC */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, sec_offset, sec_len, 0x12345678);

    /* Set correct file CRC */
    uint32_t file_crc = compute_file_crc(buf, sizeof(buf));
    write_le32(buf + 16, file_crc);

    /* File CRC should pass */
    int err = mbpf_package_validate_crc(buf, sizeof(buf));
    ASSERT_EQ(err, MBPF_OK);

    /* Section CRC should fail */
    mbpf_section_desc_t sections[1];
    uint32_t count;
    err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_ERR_CRC_MISMATCH);

    return 0;
}

/* ========================================================================== */
/* Test Cases: Edge cases */
/* ========================================================================== */

/* Test: Empty section CRC */
TEST(empty_section_crc) {
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    uint32_t sec_offset = (uint32_t)hdr_size;
    uint32_t sec_len = 0;  /* Empty section */

    /* CRC of empty data is 0 */
    uint32_t sec_crc = mbpf_crc32(buf + sec_offset, sec_len);
    ASSERT_EQ(sec_crc, 0);

    /* With CRC=0, validation is skipped, so this is somewhat meaningless
       But let's verify the behavior */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, sec_offset, sec_len, sec_crc);

    mbpf_section_desc_t sections[1];
    uint32_t count;
    int err = mbpf_package_parse_section_table(buf, sizeof(buf), sections, 1, &count);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_package_validate_section_crc(buf, sizeof(buf), &sections[0]);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test: Section CRC bounds check */
TEST(section_crc_bounds_check) {
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));

    /* Create a section descriptor that exceeds file bounds */
    mbpf_section_desc_t bad_section = {
        .type = MBPF_SEC_MANIFEST,
        .offset = 200,
        .length = 100,  /* 200+100 > 256 */
        .crc32 = 0x12345678
    };

    int err = mbpf_package_validate_section_crc(buf, sizeof(buf), &bad_section);
    ASSERT_EQ(err, MBPF_ERR_SECTION_BOUNDS);

    return 0;
}

/* Test: NULL pointer handling */
TEST(null_pointer_handling) {
    uint8_t buf[256];
    mbpf_section_desc_t section = { .type = 1, .offset = 50, .length = 10, .crc32 = 0x123 };

    int err = mbpf_package_validate_section_crc(NULL, 256, &section);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    err = mbpf_package_validate_section_crc(buf, 256, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test: Large file CRC */
TEST(large_file_crc) {
    size_t large_size = 64 * 1024;  /* 64KB */
    uint8_t *buf = malloc(large_size);
    ASSERT(buf != NULL);

    /* Fill with pattern */
    for (size_t i = 0; i < large_size; i++) {
        buf[i] = (uint8_t)(i * 31 + i / 256);
    }

    size_t hdr_size = create_mbpf_header(buf, large_size, 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 1024, 0);
    offset += 1024;
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 32768, 0);

    /* Compute and set file CRC */
    uint32_t file_crc = compute_file_crc(buf, large_size);
    write_le32(buf + 16, file_crc);

    /* Should validate */
    int err = mbpf_package_validate_crc(buf, large_size);
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt and verify failure */
    buf[large_size - 1] ^= 0xFF;
    err = mbpf_package_validate_crc(buf, large_size);
    ASSERT_EQ(err, MBPF_ERR_CRC_MISMATCH);

    free(buf);
    return 0;
}

/* ========================================================================== */
/* Main */
/* ========================================================================== */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF CRC32 Validation Tests\n");
    printf("================================\n");

    /* Basic CRC32 function tests */
    printf("\nBasic CRC32 function:\n");
    RUN_TEST(crc32_known_values);
    RUN_TEST(crc32_deterministic);

    /* File-level CRC tests */
    printf("\nFile-level CRC validation:\n");
    RUN_TEST(valid_file_crc);
    RUN_TEST(file_crc_validation_enabled);
    RUN_TEST(file_crc_zero_not_checked);
    RUN_TEST(file_crc_rejects_corruption);
    RUN_TEST(file_crc_covers_header);

    /* Per-section CRC tests */
    printf("\nPer-section CRC validation:\n");
    RUN_TEST(valid_section_crc);
    RUN_TEST(section_crc_validation_enabled);
    RUN_TEST(section_crc_zero_not_checked);
    RUN_TEST(section_crc_rejects_corruption);
    RUN_TEST(multiple_sections_with_crc);

    /* Combined tests */
    printf("\nCombined file and section CRC:\n");
    RUN_TEST(both_file_and_section_crc_valid);
    RUN_TEST(file_crc_valid_section_invalid);

    /* Edge cases */
    printf("\nEdge cases:\n");
    RUN_TEST(empty_section_crc);
    RUN_TEST(section_crc_bounds_check);
    RUN_TEST(null_pointer_handling);
    RUN_TEST(large_file_crc);

    printf("\n================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
