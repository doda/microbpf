/*
 * microBPF Toolchain Signing Tests
 *
 * Tests for Ed25519 keypair generation, package signing, and verification.
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include "ed25519.h"
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

/* ========================================================================== */
/* Test Cases: Ed25519 keypair generation */
/* ========================================================================== */

/* Test: Generate keypair from seed */
TEST(keypair_from_seed) {
    /* RFC 8032 test vector 1 seed */
    const uint8_t seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };

    /* Expected public key from RFC 8032 */
    const uint8_t expected_pubkey[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
    };

    uint8_t public_key[32];
    uint8_t secret_key[64];

    int result = ed25519_keypair_from_seed(public_key, secret_key, seed);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(memcmp(public_key, expected_pubkey, 32), 0);

    /* Verify secret key structure: seed || public_key */
    ASSERT_EQ(memcmp(secret_key, seed, 32), 0);
    ASSERT_EQ(memcmp(secret_key + 32, public_key, 32), 0);

    return 0;
}

/* Test: Sign and verify round trip with RFC 8032 test vector */
TEST(sign_verify_rfc8032_tv1) {
    /* RFC 8032 test vector 1 */
    const uint8_t seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };

    const uint8_t expected_sig[64] = {
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
        0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
        0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
    };

    uint8_t public_key[32];
    uint8_t secret_key[64];
    uint8_t signature[64];

    ed25519_keypair_from_seed(public_key, secret_key, seed);

    /* Sign empty message (RFC 8032 test vector 1) */
    int result = ed25519_sign(signature, NULL, 0, secret_key);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(memcmp(signature, expected_sig, 64), 0);

    /* Verify the signature */
    result = ed25519_verify(signature, NULL, 0, public_key);
    ASSERT_EQ(result, 0);

    return 0;
}

/* Test: Sign and verify round trip with RFC 8032 test vector 2 */
TEST(sign_verify_rfc8032_tv2) {
    /* RFC 8032 test vector 2 */
    const uint8_t seed[32] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
        0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
        0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
    };

    const uint8_t message[1] = { 0x72 };

    const uint8_t expected_sig[64] = {
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
        0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
        0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
        0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
        0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
        0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
        0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
        0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00
    };

    uint8_t public_key[32];
    uint8_t secret_key[64];
    uint8_t signature[64];

    ed25519_keypair_from_seed(public_key, secret_key, seed);

    /* Sign single-byte message */
    int result = ed25519_sign(signature, message, sizeof(message), secret_key);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(memcmp(signature, expected_sig, 64), 0);

    /* Verify the signature */
    result = ed25519_verify(signature, message, sizeof(message), public_key);
    ASSERT_EQ(result, 0);

    return 0;
}

/* Test: Sign and verify with arbitrary message */
TEST(sign_verify_arbitrary_message) {
    const uint8_t seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    const uint8_t message[] = "Hello, microBPF!";
    size_t message_len = strlen((const char *)message);

    uint8_t public_key[32];
    uint8_t secret_key[64];
    uint8_t signature[64];

    ed25519_keypair_from_seed(public_key, secret_key, seed);
    ed25519_sign(signature, message, message_len, secret_key);

    /* Verify the signature */
    int result = ed25519_verify(signature, message, message_len, public_key);
    ASSERT_EQ(result, 0);

    /* Corrupt signature and verify it fails */
    signature[0] ^= 0x01;
    result = ed25519_verify(signature, message, message_len, public_key);
    ASSERT_NE(result, 0);

    return 0;
}

/* ========================================================================== */
/* Test Cases: Package signing */
/* ========================================================================== */

/* Test: Sign a package and verify it */
TEST(sign_and_verify_package) {
    /* Generate a test keypair */
    const uint8_t seed[32] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };

    uint8_t public_key[32];
    uint8_t secret_key[64];
    ed25519_keypair_from_seed(public_key, secret_key, seed);

    /* Create an unsigned package */
    uint8_t unsigned_pkg[256];
    memset(unsigned_pkg, 0, sizeof(unsigned_pkg));

    size_t hdr_size = create_mbpf_header(unsigned_pkg, sizeof(unsigned_pkg), 2, 0);
    ASSERT(hdr_size > 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t manifest_len = 32;
    uint32_t bytecode_offset = manifest_offset + manifest_len;
    uint32_t bytecode_len = 64;

    add_section_desc(unsigned_pkg, 0, MBPF_SEC_MANIFEST, manifest_offset, manifest_len, 0);
    add_section_desc(unsigned_pkg, 1, MBPF_SEC_BYTECODE, bytecode_offset, bytecode_len, 0);

    /* Fill in some dummy section data */
    memset(unsigned_pkg + manifest_offset, 0xAA, manifest_len);
    memset(unsigned_pkg + bytecode_offset, 0xBB, bytecode_len);

    size_t unsigned_len = bytecode_offset + bytecode_len;

    /* Sign the package */
    uint8_t signature[64];
    ed25519_sign(signature, unsigned_pkg, unsigned_len, secret_key);

    /* Create a new signed package with signature section */
    uint8_t signed_pkg[512];
    memset(signed_pkg, 0, sizeof(signed_pkg));

    /* New header with 3 sections */
    size_t new_hdr_size = sizeof(mbpf_file_header_t) + 3 * sizeof(mbpf_section_desc_t);

    write_le32(signed_pkg + 0, MBPF_MAGIC);
    write_le16(signed_pkg + 4, 1);  /* format_version */
    write_le16(signed_pkg + 6, (uint16_t)new_hdr_size);
    write_le32(signed_pkg + 8, MBPF_FLAG_SIGNED);
    write_le32(signed_pkg + 12, 3);
    write_le32(signed_pkg + 16, 0);

    /* Adjust offsets for new header size */
    uint32_t new_manifest_offset = (uint32_t)new_hdr_size;
    uint32_t new_bytecode_offset = new_manifest_offset + manifest_len;
    uint32_t sig_offset = new_bytecode_offset + bytecode_len;

    add_section_desc(signed_pkg, 0, MBPF_SEC_MANIFEST, new_manifest_offset, manifest_len, 0);
    add_section_desc(signed_pkg, 1, MBPF_SEC_BYTECODE, new_bytecode_offset, bytecode_len, 0);
    add_section_desc(signed_pkg, 2, MBPF_SEC_SIG, sig_offset, 64, 0);

    /* Copy section data */
    memcpy(signed_pkg + new_manifest_offset, unsigned_pkg + manifest_offset, manifest_len);
    memcpy(signed_pkg + new_bytecode_offset, unsigned_pkg + bytecode_offset, bytecode_len);

    /* Re-sign the final package (everything before signature) */
    ed25519_sign(signature, signed_pkg, sig_offset, secret_key);
    memcpy(signed_pkg + sig_offset, signature, 64);

    size_t signed_len = sig_offset + 64;

    /* Verify the signed package */
    mbpf_sig_verify_opts_t opts = {
        .public_key = public_key,
        .allow_unsigned = 0,
        .production_mode = 0
    };

    int err = mbpf_package_verify_signature(signed_pkg, signed_len, &opts);
    ASSERT_EQ(err, MBPF_OK);

    return 0;
}

/* Test: Corrupt signature is rejected */
TEST(corrupted_signature_rejected) {
    const uint8_t seed[32] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };

    uint8_t public_key[32];
    uint8_t secret_key[64];
    ed25519_keypair_from_seed(public_key, secret_key, seed);

    /* Create a signed package */
    uint8_t pkg[256];
    memset(pkg, 0, sizeof(pkg));

    size_t hdr_size = sizeof(mbpf_file_header_t) + 2 * sizeof(mbpf_section_desc_t);

    write_le32(pkg + 0, MBPF_MAGIC);
    write_le16(pkg + 4, 1);
    write_le16(pkg + 6, (uint16_t)hdr_size);
    write_le32(pkg + 8, MBPF_FLAG_SIGNED);
    write_le32(pkg + 12, 2);
    write_le32(pkg + 16, 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;
    size_t pkg_len = sig_offset + 64;

    add_section_desc(pkg, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(pkg, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    memset(pkg + manifest_offset, 0x42, 32);

    /* Sign correctly */
    uint8_t signature[64];
    ed25519_sign(signature, pkg, sig_offset, secret_key);
    memcpy(pkg + sig_offset, signature, 64);

    /* Verify valid signature */
    mbpf_sig_verify_opts_t opts = {
        .public_key = public_key,
        .allow_unsigned = 0,
        .production_mode = 0
    };

    int err = mbpf_package_verify_signature(pkg, pkg_len, &opts);
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt the signature */
    pkg[sig_offset] ^= 0x01;
    err = mbpf_package_verify_signature(pkg, pkg_len, &opts);
    ASSERT_EQ(err, MBPF_ERR_SIGNATURE);

    return 0;
}

/* Test: Corrupted package data is rejected */
TEST(corrupted_data_rejected) {
    const uint8_t seed[32] = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };

    uint8_t public_key[32];
    uint8_t secret_key[64];
    ed25519_keypair_from_seed(public_key, secret_key, seed);

    /* Create a signed package */
    uint8_t pkg[256];
    memset(pkg, 0, sizeof(pkg));

    size_t hdr_size = sizeof(mbpf_file_header_t) + 2 * sizeof(mbpf_section_desc_t);

    write_le32(pkg + 0, MBPF_MAGIC);
    write_le16(pkg + 4, 1);
    write_le16(pkg + 6, (uint16_t)hdr_size);
    write_le32(pkg + 8, MBPF_FLAG_SIGNED);
    write_le32(pkg + 12, 2);
    write_le32(pkg + 16, 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;
    size_t pkg_len = sig_offset + 64;

    add_section_desc(pkg, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(pkg, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    memset(pkg + manifest_offset, 0x42, 32);

    /* Sign correctly */
    uint8_t signature[64];
    ed25519_sign(signature, pkg, sig_offset, secret_key);
    memcpy(pkg + sig_offset, signature, 64);

    /* Verify valid signature */
    mbpf_sig_verify_opts_t opts = {
        .public_key = public_key,
        .allow_unsigned = 0,
        .production_mode = 0
    };

    int err = mbpf_package_verify_signature(pkg, pkg_len, &opts);
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt the manifest data (not the signature) */
    pkg[manifest_offset + 5] ^= 0xFF;
    err = mbpf_package_verify_signature(pkg, pkg_len, &opts);
    ASSERT_EQ(err, MBPF_ERR_SIGNATURE);

    return 0;
}

/* Test: Wrong public key is rejected */
TEST(wrong_pubkey_rejected) {
    const uint8_t seed1[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    const uint8_t seed2[32] = {
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };

    uint8_t public_key1[32], secret_key1[64];
    uint8_t public_key2[32], secret_key2[64];

    ed25519_keypair_from_seed(public_key1, secret_key1, seed1);
    ed25519_keypair_from_seed(public_key2, secret_key2, seed2);

    /* Create package signed with key1 */
    uint8_t pkg[256];
    memset(pkg, 0, sizeof(pkg));

    size_t hdr_size = sizeof(mbpf_file_header_t) + 2 * sizeof(mbpf_section_desc_t);

    write_le32(pkg + 0, MBPF_MAGIC);
    write_le16(pkg + 4, 1);
    write_le16(pkg + 6, (uint16_t)hdr_size);
    write_le32(pkg + 8, MBPF_FLAG_SIGNED);
    write_le32(pkg + 12, 2);
    write_le32(pkg + 16, 0);

    uint32_t manifest_offset = (uint32_t)hdr_size;
    uint32_t sig_offset = manifest_offset + 32;
    size_t pkg_len = sig_offset + 64;

    add_section_desc(pkg, 0, MBPF_SEC_MANIFEST, manifest_offset, 32, 0);
    add_section_desc(pkg, 1, MBPF_SEC_SIG, sig_offset, 64, 0);

    memset(pkg + manifest_offset, 0x42, 32);

    /* Sign with key1 */
    uint8_t signature[64];
    ed25519_sign(signature, pkg, sig_offset, secret_key1);
    memcpy(pkg + sig_offset, signature, 64);

    /* Verify with correct key */
    mbpf_sig_verify_opts_t opts1 = {
        .public_key = public_key1,
        .allow_unsigned = 0,
        .production_mode = 0
    };
    int err = mbpf_package_verify_signature(pkg, pkg_len, &opts1);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify with wrong key */
    mbpf_sig_verify_opts_t opts2 = {
        .public_key = public_key2,
        .allow_unsigned = 0,
        .production_mode = 0
    };
    err = mbpf_package_verify_signature(pkg, pkg_len, &opts2);
    ASSERT_EQ(err, MBPF_ERR_SIGNATURE);

    return 0;
}

/* ========================================================================== */
/* Main */
/* ========================================================================== */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Toolchain Signing Tests\n");
    printf("================================\n");

    printf("\nEd25519 keypair generation:\n");
    RUN_TEST(keypair_from_seed);

    printf("\nEd25519 signing (RFC 8032 test vectors):\n");
    RUN_TEST(sign_verify_rfc8032_tv1);
    RUN_TEST(sign_verify_rfc8032_tv2);
    RUN_TEST(sign_verify_arbitrary_message);

    printf("\nPackage signing:\n");
    RUN_TEST(sign_and_verify_package);
    RUN_TEST(corrupted_signature_rejected);
    RUN_TEST(corrupted_data_rejected);
    RUN_TEST(wrong_pubkey_rejected);

    printf("\n================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
