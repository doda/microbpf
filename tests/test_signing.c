/*
 * microBPF Ed25519 Signature Verification Tests
 *
 * Tests for .mbpf package signature verification.
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
 * RFC 8032 Ed25519 test vector 1:
 * SECRET KEY: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
 * PUBLIC KEY: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
 * MESSAGE: (empty)
 * SIGNATURE: e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
 */
static const uint8_t rfc_test_pubkey[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

static const uint8_t rfc_test_sig[64] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
};

/*
 * RFC 8032 Ed25519 test vector 2:
 * SECRET KEY: 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
 * PUBLIC KEY: 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
 * MESSAGE: 72 (single byte 0x72)
 * SIGNATURE: 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
 */
static const uint8_t rfc_test2_pubkey[32] = {
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
    0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
    0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
};

static const uint8_t rfc_test2_msg[1] = { 0x72 };

static const uint8_t rfc_test2_sig[64] = {
    0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
    0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
    0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
    0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
    0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
    0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
    0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
    0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00
};

/* Forward declaration of ed25519_verify for direct testing */
extern int ed25519_verify(const uint8_t *sig, const uint8_t *m, size_t n,
                          const uint8_t *pk);

/* ========================================================================== */
/* Test Cases: Ed25519 verification basics */
/* ========================================================================== */

/* Test: Ed25519 verification of empty message (RFC 8032 test vector 1) */
TEST(ed25519_empty_message) {
    int result = ed25519_verify(rfc_test_sig, NULL, 0, rfc_test_pubkey);
    ASSERT_EQ(result, 0);
    return 0;
}

/* Test: Ed25519 verification of single-byte message (RFC 8032 test vector 2) */
TEST(ed25519_single_byte) {
    int result = ed25519_verify(rfc_test2_sig, rfc_test2_msg, 1, rfc_test2_pubkey);
    ASSERT_EQ(result, 0);
    return 0;
}

/* Test: Ed25519 rejects corrupted signature */
TEST(ed25519_reject_bad_signature) {
    uint8_t bad_sig[64];
    memcpy(bad_sig, rfc_test_sig, 64);
    bad_sig[0] ^= 0x01;  /* Corrupt first byte */

    int result = ed25519_verify(bad_sig, NULL, 0, rfc_test_pubkey);
    ASSERT_NE(result, 0);
    return 0;
}

/* Test: Ed25519 rejects wrong public key */
TEST(ed25519_reject_wrong_pubkey) {
    int result = ed25519_verify(rfc_test_sig, NULL, 0, rfc_test2_pubkey);
    ASSERT_NE(result, 0);
    return 0;
}

/* ========================================================================== */
/* Test Cases: Package signing detection */
/* ========================================================================== */

/* Test: Detect unsigned package */
TEST(detect_unsigned_package) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    /* Create package with just a MANIFEST section (no SIG) */
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    int is_signed = -1;
    int err = mbpf_package_is_signed(buf, sizeof(buf), &is_signed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(is_signed, 0);

    return 0;
}

/* Test: Detect signed package */
TEST(detect_signed_package) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    /* Create package with MANIFEST and SIG sections */
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    int is_signed = -1;
    int err = mbpf_package_is_signed(buf, sizeof(buf), &is_signed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(is_signed, 1);

    return 0;
}

/* ========================================================================== */
/* Test Cases: Get signature section */
/* ========================================================================== */

/* Test: Get signature from signed package */
TEST(get_signature_section) {
    uint8_t buf[256];
    memset(buf, 0xAA, sizeof(buf));

    /* Create package with MANIFEST and SIG sections */
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;
    size_t file_len = sig_offset + 64;  /* Exact file length */

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    /* Put known signature data */
    memcpy(buf + sig_offset, rfc_test_sig, 64);

    const uint8_t *sig = NULL;
    size_t data_len = 0;
    int err = mbpf_package_get_signature(buf, file_len, &sig, &data_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT(sig != NULL);
    ASSERT_EQ(data_len, sig_offset);
    ASSERT_EQ(memcmp(sig, rfc_test_sig, 64), 0);

    return 0;
}

/* Test: Get signature from unsigned package fails */
TEST(get_signature_missing) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    const uint8_t *sig = NULL;
    size_t data_len = 0;
    int err = mbpf_package_get_signature(buf, sizeof(buf), &sig, &data_len);
    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);

    return 0;
}

/* Test: Reject wrong-size signature section */
TEST(reject_wrong_size_signature) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;
    size_t file_len = sig_offset + 32;  /* Wrong sig size */

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, sig_offset, 32, 0);  /* Wrong: should be 64 */

    const uint8_t *sig = NULL;
    size_t data_len = 0;
    int err = mbpf_package_get_signature(buf, file_len, &sig, &data_len);
    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);

    return 0;
}

/* Test: Reject signature section that doesn't end at file boundary */
TEST(reject_sig_not_at_end) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;
    size_t file_len = sig_offset + 64 + 100;  /* Extra 100 bytes after signature */

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    const uint8_t *sig = NULL;
    size_t data_len = 0;
    int err = mbpf_package_get_signature(buf, file_len, &sig, &data_len);
    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);  /* Signature must be at end */

    return 0;
}

/* ========================================================================== */
/* Test Cases: Package verification with signatures */
/* ========================================================================== */

/* Test: Package with invalid signature is rejected */
TEST(verify_invalid_signature) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;
    size_t file_len = sig_offset + 64;

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    /* Fill in some manifest data */
    memset(buf + manifest_offset, 0x42, 32);

    /* Put a bogus signature - this should fail verification */
    memset(buf + sig_offset, 0xFF, 64);

    mbpf_sig_verify_opts_t opts = {
        .public_key = rfc_test_pubkey,
        .allow_unsigned = 0,
        .production_mode = 0
    };

    int err = mbpf_package_verify_signature(buf, file_len, &opts);
    ASSERT_EQ(err, MBPF_ERR_SIGNATURE);  /* Should fail with invalid sig */

    return 0;
}

/* Test: Unsigned package rejected in production mode */
TEST(reject_unsigned_production) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    mbpf_sig_verify_opts_t opts = {
        .public_key = rfc_test_pubkey,
        .allow_unsigned = 0,
        .production_mode = 1
    };

    int err = mbpf_package_verify_signature(buf, sizeof(buf), &opts);
    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);

    return 0;
}

/* Test: Unsigned package allowed in development mode */
TEST(allow_unsigned_development) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    mbpf_sig_verify_opts_t opts = {
        .public_key = rfc_test_pubkey,
        .allow_unsigned = 1,
        .production_mode = 0
    };

    int err = mbpf_package_verify_signature(buf, sizeof(buf), &opts);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test: Signed package requires public key */
TEST(signed_requires_pubkey) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;
    size_t file_len = sig_offset + 64;

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    mbpf_sig_verify_opts_t opts = {
        .public_key = NULL,  /* No public key! */
        .allow_unsigned = 0,
        .production_mode = 0
    };

    int err = mbpf_package_verify_signature(buf, file_len, &opts);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test: Invalid signature rejected with correct error */
TEST(invalid_signature_rejected) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;
    size_t file_len = sig_offset + 64;

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    /* Put completely wrong signature */
    memset(buf + sig_offset, 0x00, 64);

    mbpf_sig_verify_opts_t opts = {
        .public_key = rfc_test_pubkey,
        .allow_unsigned = 0,
        .production_mode = 0
    };

    int err = mbpf_package_verify_signature(buf, file_len, &opts);
    ASSERT_EQ(err, MBPF_ERR_SIGNATURE);

    return 0;
}

/* ========================================================================== */
/* Test Cases: Edge cases */
/* ========================================================================== */

/* Test: NULL pointer handling */
TEST(null_pointer_handling) {
    uint8_t buf[256];
    int is_signed;
    const uint8_t *sig;
    size_t data_len;
    mbpf_sig_verify_opts_t opts = { .public_key = rfc_test_pubkey };

    /* mbpf_package_is_signed */
    ASSERT_EQ(mbpf_package_is_signed(NULL, 256, &is_signed), MBPF_ERR_INVALID_ARG);
    ASSERT_EQ(mbpf_package_is_signed(buf, 256, NULL), MBPF_ERR_INVALID_ARG);

    /* mbpf_package_get_signature */
    ASSERT_EQ(mbpf_package_get_signature(NULL, 256, &sig, &data_len), MBPF_ERR_INVALID_ARG);
    ASSERT_EQ(mbpf_package_get_signature(buf, 256, NULL, &data_len), MBPF_ERR_INVALID_ARG);
    ASSERT_EQ(mbpf_package_get_signature(buf, 256, &sig, NULL), MBPF_ERR_INVALID_ARG);

    /* mbpf_package_verify_signature */
    ASSERT_EQ(mbpf_package_verify_signature(NULL, 256, &opts), MBPF_ERR_INVALID_ARG);
    ASSERT_EQ(mbpf_package_verify_signature(buf, 256, NULL), MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test: Signature section with out-of-bounds offset */
TEST(signature_bounds_check) {
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = 200;  /* Out of bounds for 128-byte buffer */

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    const uint8_t *sig;
    size_t data_len;
    int err = mbpf_package_get_signature(buf, sizeof(buf), &sig, &data_len);
    ASSERT_EQ(err, MBPF_ERR_SECTION_BOUNDS);

    return 0;
}

/* Test: Multiple sections including signature */
TEST(multiple_sections_with_sig) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 4, 0);
    ASSERT(hdr_size > 0);

    uint32_t offset = (uint32_t)hdr_size;

    /* MANIFEST section */
    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, offset, 64, 0);
    offset += 64;

    /* BYTECODE section */
    add_section_desc(buf, 1, MBPF_SEC_BYTECODE, offset, 128, 0);
    offset += 128;

    /* DEBUG section */
    add_section_desc(buf, 2, MBPF_SEC_DEBUG, offset, 32, 0);
    offset += 32;

    /* SIG section (last) */
    uint32_t sig_offset = offset;
    add_section_desc(buf, 3, MBPF_SEC_SIG, sig_offset, 64, 0);
    size_t file_len = sig_offset + 64;

    int is_signed = 0;
    int err = mbpf_package_is_signed(buf, file_len, &is_signed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(is_signed, 1);

    const uint8_t *sig;
    size_t data_len;
    err = mbpf_package_get_signature(buf, file_len, &sig, &data_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(data_len, sig_offset);  /* Data length is everything before sig */

    return 0;
}

/* Test: Unsigned package default behavior (not allow_unsigned, not production) */
TEST(unsigned_default_rejected) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 1, 0);
    ASSERT(hdr_size > 0);

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, (uint32_t)hdr_size, 32, 0);

    mbpf_sig_verify_opts_t opts = {
        .public_key = rfc_test_pubkey,
        .allow_unsigned = 0,
        .production_mode = 0
    };

    /* Default: unsigned packages should be rejected */
    int err = mbpf_package_verify_signature(buf, sizeof(buf), &opts);
    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);

    return 0;
}

/* Test that signature data region calculation is correct */
TEST(signature_data_region) {
    uint8_t buf[256];
    memset(buf, 0x00, sizeof(buf));

    /* Create a 2-section package */
    size_t hdr_size = create_mbpf_header(buf, sizeof(buf), 2, 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t manifest_len = 48;
    uint32_t sig_offset = manifest_offset + manifest_len;
    size_t file_len = sig_offset + 64;

    add_section_desc(buf, 0, MBPF_SEC_MANIFEST, manifest_offset, manifest_len, 0);
    add_section_desc(buf, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    const uint8_t *sig;
    size_t data_len;
    int err = mbpf_package_get_signature(buf, file_len, &sig, &data_len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify the data_len is exactly sig_offset (everything before sig section) */
    ASSERT_EQ(data_len, sig_offset);

    /* This means the signature covers:
     * - The 20-byte header
     * - The section table (2 * 16 = 32 bytes)
     * - The manifest data (48 bytes)
     * Total: 20 + 32 + 48 = 100 bytes
     */
    ASSERT_EQ(data_len, hdr_size + manifest_len);

    return 0;
}

/* ========================================================================== */
/* Main */
/* ========================================================================== */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Ed25519 Signature Verification Tests\n");
    printf("==============================================\n");

    /* Ed25519 core verification tests */
    printf("\nEd25519 core verification:\n");
    RUN_TEST(ed25519_empty_message);
    RUN_TEST(ed25519_single_byte);
    RUN_TEST(ed25519_reject_bad_signature);
    RUN_TEST(ed25519_reject_wrong_pubkey);

    /* Package signing detection */
    printf("\nPackage signing detection:\n");
    RUN_TEST(detect_unsigned_package);
    RUN_TEST(detect_signed_package);

    /* Get signature section */
    printf("\nGet signature section:\n");
    RUN_TEST(get_signature_section);
    RUN_TEST(get_signature_missing);
    RUN_TEST(reject_wrong_size_signature);
    RUN_TEST(reject_sig_not_at_end);

    /* Package verification */
    printf("\nPackage verification:\n");
    RUN_TEST(verify_invalid_signature);
    RUN_TEST(reject_unsigned_production);
    RUN_TEST(allow_unsigned_development);
    RUN_TEST(signed_requires_pubkey);
    RUN_TEST(invalid_signature_rejected);

    /* Edge cases */
    printf("\nEdge cases:\n");
    RUN_TEST(null_pointer_handling);
    RUN_TEST(signature_bounds_check);
    RUN_TEST(multiple_sections_with_sig);
    RUN_TEST(unsigned_default_rejected);
    RUN_TEST(signature_data_region);

    printf("\n==============================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
