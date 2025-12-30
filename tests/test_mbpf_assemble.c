/*
 * Package Assembly Tests
 *
 * Tests for the mbpf_package_assemble API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbpf.h"
#include "mbpf_package.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("ASSERT FAILED: %s at line %d\n", #cond, __LINE__); \
        return 0; \
    } \
} while (0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("ASSERT FAILED: (%s) == (%s) at line %d\n", #a, #b, __LINE__); \
        printf("  actual: %ld, expected: %ld\n", (long)(a), (long)(b)); \
        return 0; \
    } \
} while (0)

#define RUN_TEST(name) do { \
    printf("  %s... ", #name); \
    if (test_##name()) { \
        printf("PASS\n"); \
        tests_passed++; \
    } else { \
        printf("FAIL\n"); \
        tests_failed++; \
    } \
} while (0)

/* Sample manifest JSON - built dynamically with runtime word size */
static char sample_manifest[512];
static void init_sample_manifest(void) {
    const char *endianness_str = mbpf_runtime_endianness() == 0 ? "little" : "big";
    snprintf(sample_manifest, sizeof(sample_manifest),
        "{"
        "\"program_name\":\"test_prog\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":32769,"
        "\"target\":{\"word_size\":%u,\"endianness\":\"%s\"},"
        "\"mbpf_api_version\":65536,"
        "\"heap_size\":8192,"
        "\"budgets\":{\"max_steps\":10000,\"max_helpers\":100},"
        "\"capabilities\":[]"
        "}",
        mbpf_runtime_word_size(),
        endianness_str);
}

/* Sample bytecode (just placeholder bytes for testing) */
static const uint8_t sample_bytecode[] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x80};

/* Test basic assembly with manifest and bytecode */
static int test_basic_assemble(void) {
    mbpf_section_input_t sections[2];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = sample_manifest;
    sections[0].len = strlen(sample_manifest);
    sections[1].type = MBPF_SEC_BYTECODE;
    sections[1].data = sample_bytecode;
    sections[1].len = sizeof(sample_bytecode);

    /* Calculate required size */
    size_t required = mbpf_package_size(sections, 2);
    ASSERT(required > 0);
    ASSERT_EQ(required, 20 + 2*16 + strlen(sample_manifest) + sizeof(sample_bytecode));

    /* Allocate buffer and assemble */
    uint8_t *pkg = malloc(required);
    ASSERT(pkg != NULL);
    size_t len = required;

    int err = mbpf_package_assemble(sections, 2, NULL, pkg, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len, required);

    /* Verify we can parse the resulting package */
    mbpf_file_header_t header;
    err = mbpf_package_parse_header(pkg, len, &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.magic, MBPF_MAGIC);
    ASSERT_EQ(header.format_version, MBPF_FORMAT_VERSION);
    ASSERT_EQ(header.section_count, 2);
    ASSERT_EQ(header.flags, 0);
    ASSERT_EQ(header.file_crc32, 0);

    /* Verify sections can be retrieved */
    const void *manifest_data;
    size_t manifest_len;
    err = mbpf_package_get_section(pkg, len, MBPF_SEC_MANIFEST, &manifest_data, &manifest_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(manifest_len, strlen(sample_manifest));
    ASSERT(memcmp(manifest_data, sample_manifest, manifest_len) == 0);

    const void *bytecode_data;
    size_t bytecode_len;
    err = mbpf_package_get_section(pkg, len, MBPF_SEC_BYTECODE, &bytecode_data, &bytecode_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(bytecode_len, sizeof(sample_bytecode));
    ASSERT(memcmp(bytecode_data, sample_bytecode, bytecode_len) == 0);

    free(pkg);
    return 1;
}

/* Test assembly with CRC32 values */
static int test_assemble_with_crc(void) {
    mbpf_section_input_t sections[2];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = sample_manifest;
    sections[0].len = strlen(sample_manifest);
    sections[1].type = MBPF_SEC_BYTECODE;
    sections[1].data = sample_bytecode;
    sections[1].len = sizeof(sample_bytecode);

    size_t required = mbpf_package_size(sections, 2);
    uint8_t *pkg = malloc(required);
    ASSERT(pkg != NULL);
    size_t len = required;

    mbpf_assemble_opts_t opts = {
        .compute_file_crc = 1,
        .compute_section_crcs = 1,
        .flags = 0
    };

    int err = mbpf_package_assemble(sections, 2, &opts, pkg, &len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify file CRC is set */
    mbpf_file_header_t header;
    err = mbpf_package_parse_header(pkg, len, &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT(header.file_crc32 != 0);

    /* Verify file CRC validates */
    err = mbpf_package_validate_crc(pkg, len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify section CRCs */
    mbpf_section_desc_t sec_descs[2];
    uint32_t sec_count;
    err = mbpf_package_parse_section_table(pkg, len, sec_descs, 2, &sec_count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sec_count, 2);

    /* Each section should have non-zero CRC */
    ASSERT(sec_descs[0].crc32 != 0);
    ASSERT(sec_descs[1].crc32 != 0);

    /* Verify section CRCs validate */
    err = mbpf_package_validate_section_crc(pkg, len, &sec_descs[0]);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_package_validate_section_crc(pkg, len, &sec_descs[1]);
    ASSERT_EQ(err, MBPF_OK);

    free(pkg);
    return 1;
}

/* Test assembly with flags */
static int test_assemble_with_flags(void) {
    mbpf_section_input_t sections[2];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = sample_manifest;
    sections[0].len = strlen(sample_manifest);
    sections[1].type = MBPF_SEC_BYTECODE;
    sections[1].data = sample_bytecode;
    sections[1].len = sizeof(sample_bytecode);

    size_t required = mbpf_package_size(sections, 2);
    uint8_t *pkg = malloc(required);
    ASSERT(pkg != NULL);
    size_t len = required;

    mbpf_assemble_opts_t opts = {
        .compute_file_crc = 0,
        .compute_section_crcs = 0,
        .flags = MBPF_FLAG_DEBUG
    };

    int err = mbpf_package_assemble(sections, 2, &opts, pkg, &len);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_file_header_t header;
    err = mbpf_package_parse_header(pkg, len, &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.flags, MBPF_FLAG_DEBUG);

    free(pkg);
    return 1;
}

/* Test size calculation */
static int test_package_size(void) {
    mbpf_section_input_t sections[3];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = sample_manifest;
    sections[0].len = strlen(sample_manifest);
    sections[1].type = MBPF_SEC_BYTECODE;
    sections[1].data = sample_bytecode;
    sections[1].len = sizeof(sample_bytecode);
    sections[2].type = MBPF_SEC_DEBUG;
    sections[2].data = "debug info";
    sections[2].len = 10;

    /* Header: 20 bytes, 3 sections * 16 bytes = 48, plus data */
    size_t expected = 20 + 3*16 + strlen(sample_manifest) + sizeof(sample_bytecode) + 10;
    size_t actual = mbpf_package_size(sections, 3);
    ASSERT_EQ(actual, expected);

    /* Invalid inputs */
    ASSERT_EQ(mbpf_package_size(NULL, 1), 0);
    ASSERT_EQ(mbpf_package_size(sections, 0), 0);
    ASSERT_EQ(mbpf_package_size(sections, MBPF_MAX_SECTIONS + 1), 0);

    return 1;
}

/* Test error handling */
static int test_assemble_errors(void) {
    mbpf_section_input_t sections[2];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = sample_manifest;
    sections[0].len = strlen(sample_manifest);
    sections[1].type = MBPF_SEC_BYTECODE;
    sections[1].data = sample_bytecode;
    sections[1].len = sizeof(sample_bytecode);

    size_t len;

    /* NULL sections */
    len = 1000;
    ASSERT_EQ(mbpf_package_assemble(NULL, 2, NULL, NULL, &len), MBPF_ERR_INVALID_ARG);

    /* Zero sections */
    len = 1000;
    ASSERT_EQ(mbpf_package_assemble(sections, 0, NULL, NULL, &len), MBPF_ERR_INVALID_ARG);

    /* NULL out_len */
    ASSERT_EQ(mbpf_package_assemble(sections, 2, NULL, NULL, NULL), MBPF_ERR_INVALID_ARG);

    /* Too many sections */
    len = 1000;
    ASSERT_EQ(mbpf_package_assemble(sections, MBPF_MAX_SECTIONS + 1, NULL, NULL, &len), MBPF_ERR_INVALID_ARG);

    /* Section with data length but NULL data */
    mbpf_section_input_t bad_sections[2];
    bad_sections[0] = sections[0];
    bad_sections[1].type = MBPF_SEC_BYTECODE;
    bad_sections[1].data = NULL;
    bad_sections[1].len = sizeof(sample_bytecode);
    len = 1000;
    ASSERT_EQ(mbpf_package_assemble(bad_sections, 2, NULL, NULL, &len), MBPF_ERR_INVALID_ARG);

    /* Buffer too small */
    uint8_t small_buf[10];
    len = sizeof(small_buf);
    int err = mbpf_package_assemble(sections, 2, NULL, small_buf, &len);
    ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    /* len should be set to required size */
    ASSERT(len > sizeof(small_buf));

    /* NULL buffer returns required size */
    len = 0;
    err = mbpf_package_assemble(sections, 2, NULL, NULL, &len);
    ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    ASSERT(len > 0);

    return 1;
}

/* Test assembly with optional sections */
static int test_optional_sections(void) {
    const char *debug_info = "function_name:line_number";
    mbpf_section_input_t sections[3];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = sample_manifest;
    sections[0].len = strlen(sample_manifest);
    sections[1].type = MBPF_SEC_BYTECODE;
    sections[1].data = sample_bytecode;
    sections[1].len = sizeof(sample_bytecode);
    sections[2].type = MBPF_SEC_DEBUG;
    sections[2].data = debug_info;
    sections[2].len = strlen(debug_info);

    size_t required = mbpf_package_size(sections, 3);
    uint8_t *pkg = malloc(required);
    ASSERT(pkg != NULL);
    size_t len = required;

    int err = mbpf_package_assemble(sections, 3, NULL, pkg, &len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify all sections are retrievable */
    const void *data;
    size_t data_len;

    err = mbpf_package_get_section(pkg, len, MBPF_SEC_MANIFEST, &data, &data_len);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_package_get_section(pkg, len, MBPF_SEC_BYTECODE, &data, &data_len);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_package_get_section(pkg, len, MBPF_SEC_DEBUG, &data, &data_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(data_len, strlen(debug_info));
    ASSERT(memcmp(data, debug_info, data_len) == 0);

    /* Verify header has correct section count */
    mbpf_file_header_t header;
    err = mbpf_package_parse_header(pkg, len, &header);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(header.section_count, 3);

    free(pkg);
    return 1;
}

/* Test roundtrip: assemble then parse manifest */
static int test_roundtrip_manifest(void) {
    mbpf_section_input_t sections[2];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = sample_manifest;
    sections[0].len = strlen(sample_manifest);
    sections[1].type = MBPF_SEC_BYTECODE;
    sections[1].data = sample_bytecode;
    sections[1].len = sizeof(sample_bytecode);

    size_t required = mbpf_package_size(sections, 2);
    uint8_t *pkg = malloc(required);
    ASSERT(pkg != NULL);
    size_t len = required;

    int err = mbpf_package_assemble(sections, 2, NULL, pkg, &len);
    ASSERT_EQ(err, MBPF_OK);

    /* Get manifest section */
    const void *manifest_data;
    size_t manifest_len;
    err = mbpf_package_get_section(pkg, len, MBPF_SEC_MANIFEST, &manifest_data, &manifest_len);
    ASSERT_EQ(err, MBPF_OK);

    /* Parse manifest */
    mbpf_manifest_t manifest;
    err = mbpf_package_parse_manifest(manifest_data, manifest_len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify parsed values */
    ASSERT(strcmp(manifest.program_name, "test_prog") == 0);
    ASSERT(strcmp(manifest.program_version, "1.0.0") == 0);
    ASSERT_EQ(manifest.hook_type, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(manifest.hook_ctx_abi_version, 1);
    ASSERT_EQ(manifest.heap_size, 8192);
    ASSERT_EQ(manifest.budgets.max_steps, 10000);
    ASSERT_EQ(manifest.budgets.max_helpers, 100);

    mbpf_manifest_free(&manifest);
    free(pkg);
    return 1;
}

/* Test empty section data */
static int test_empty_section(void) {
    mbpf_section_input_t sections[2];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = sample_manifest;
    sections[0].len = strlen(sample_manifest);
    sections[1].type = MBPF_SEC_MAPS;
    sections[1].data = NULL;
    sections[1].len = 0;

    size_t required = mbpf_package_size(sections, 2);
    uint8_t *pkg = malloc(required);
    ASSERT(pkg != NULL);
    size_t len = required;

    int err = mbpf_package_assemble(sections, 2, NULL, pkg, &len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify empty section is present */
    mbpf_section_desc_t sec_descs[2];
    uint32_t sec_count;
    err = mbpf_package_parse_section_table(pkg, len, sec_descs, 2, &sec_count);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(sec_count, 2);
    ASSERT_EQ(sec_descs[1].type, MBPF_SEC_MAPS);
    ASSERT_EQ(sec_descs[1].length, 0);

    free(pkg);
    return 1;
}

int main(void) {
    /* Initialize sample manifest with runtime word size */
    init_sample_manifest();

    printf("microBPF Package Assembly Tests\n");
    printf("================================\n\n");

    printf("Basic assembly tests:\n");
    RUN_TEST(basic_assemble);
    RUN_TEST(package_size);
    RUN_TEST(assemble_errors);

    printf("\nCRC32 tests:\n");
    RUN_TEST(assemble_with_crc);

    printf("\nFlags tests:\n");
    RUN_TEST(assemble_with_flags);

    printf("\nOptional sections tests:\n");
    RUN_TEST(optional_sections);
    RUN_TEST(empty_section);

    printf("\nRoundtrip tests:\n");
    RUN_TEST(roundtrip_manifest);

    printf("\n================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
