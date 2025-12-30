/*
 * microBPF Manifest Generation Tests
 *
 * Tests for CBOR and JSON manifest generation APIs.
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include "mbpf_manifest_gen.h"
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
#define ASSERT_STR_EQ(a, b) ASSERT(strcmp((a), (b)) == 0)

/* ============================================================================
 * Test Cases
 * ============================================================================ */

/* Test: Initialize manifest with defaults */
TEST(init_defaults) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);

    ASSERT_STR_EQ(m.entry_symbol, "mbpf_prog");
    ASSERT_EQ(m.hook_ctx_abi_version, 1);
    ASSERT(m.target.word_size == 32 || m.target.word_size == 64);
    ASSERT_EQ(m.target.endianness, 0);
    ASSERT_EQ(m.mbpf_api_version, MBPF_API_VERSION);
    ASSERT_EQ(m.heap_size, MBPF_MIN_HEAP_SIZE);
    ASSERT_EQ(m.budgets.max_steps, 10000);
    ASSERT_EQ(m.budgets.max_helpers, 100);
    ASSERT_EQ(m.budgets.max_wall_time_us, 0);
    ASSERT_EQ(m.capabilities, 0);
    ASSERT_EQ(m.map_count, 0);
    ASSERT_EQ(m.helper_version_count, 0);

    return 0;
}

/* Test: Validate manifest with missing required fields */
TEST(validate_missing_fields) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);

    /* Should fail - missing program_name */
    ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_ERR_INVALID_ARG);

    strcpy(m.program_name, "test_prog");
    /* Should fail - missing program_version */
    ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_ERR_INVALID_ARG);

    strcpy(m.program_version, "1.0.0");
    /* Should fail - invalid hook_type (0) */
    ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_ERR_INVALID_ARG);

    m.hook_type = MBPF_HOOK_NET_RX;
    /* Should pass now */
    ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_OK);

    return 0;
}

/* Test: Validate manifest with invalid heap size */
TEST(validate_heap_too_small) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_NET_RX;
    m.heap_size = 1024;  /* Too small */

    ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_ERR_HEAP_TOO_SMALL);

    m.heap_size = MBPF_MIN_HEAP_SIZE;
    ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_OK);

    return 0;
}

/* Test: Validate manifest with invalid word size */
TEST(validate_invalid_word_size) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_NET_RX;
    m.target.word_size = 48;  /* Invalid */

    ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_ERR_INVALID_ARG);

    m.target.word_size = 32;
    ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_OK);

    m.target.word_size = 64;
    ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_OK);

    return 0;
}

/* Test: Generate CBOR manifest with minimal fields */
TEST(generate_cbor_minimal) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_NET_RX;

    size_t size = mbpf_manifest_cbor_size(&m);
    ASSERT(size > 0);

    uint8_t *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_cbor(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len, size);

    /* Verify it can be parsed back */
    mbpf_manifest_t parsed;
    err = mbpf_package_parse_manifest(buf, len, &parsed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_STR_EQ(parsed.program_name, "test_prog");
    ASSERT_STR_EQ(parsed.program_version, "1.0.0");
    ASSERT_EQ(parsed.hook_type, MBPF_HOOK_NET_RX);
    ASSERT_STR_EQ(parsed.entry_symbol, "mbpf_prog");

    mbpf_manifest_free(&parsed);
    free(buf);
    return 0;
}

/* Test: Generate CBOR manifest with all fields */
TEST(generate_cbor_complete) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "net_rx_filter");
    strcpy(m.program_version, "2.1.0");
    strcpy(m.entry_symbol, "custom_entry");
    m.hook_type = MBPF_HOOK_NET_RX;
    m.hook_ctx_abi_version = 1;
    m.heap_size = 32768;
    m.budgets.max_steps = 50000;
    m.budgets.max_helpers = 500;
    m.budgets.max_wall_time_us = 10000;
    m.capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE;

    size_t size = mbpf_manifest_cbor_size(&m);
    ASSERT(size > 0);

    uint8_t *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_cbor(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify it can be parsed back */
    mbpf_manifest_t parsed;
    err = mbpf_package_parse_manifest(buf, len, &parsed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_STR_EQ(parsed.program_name, "net_rx_filter");
    ASSERT_STR_EQ(parsed.program_version, "2.1.0");
    ASSERT_STR_EQ(parsed.entry_symbol, "custom_entry");
    ASSERT_EQ(parsed.hook_type, MBPF_HOOK_NET_RX);
    ASSERT_EQ(parsed.hook_ctx_abi_version, 1);
    ASSERT_EQ(parsed.heap_size, 32768);
    ASSERT_EQ(parsed.budgets.max_steps, 50000);
    ASSERT_EQ(parsed.budgets.max_helpers, 500);
    ASSERT_EQ(parsed.budgets.max_wall_time_us, 10000);
    ASSERT(parsed.capabilities & MBPF_CAP_LOG);
    ASSERT(parsed.capabilities & MBPF_CAP_MAP_READ);
    ASSERT(parsed.capabilities & MBPF_CAP_MAP_WRITE);
    ASSERT(!(parsed.capabilities & MBPF_CAP_EMIT));

    mbpf_manifest_free(&parsed);
    free(buf);
    return 0;
}

/* Test: Generate CBOR manifest with maps */
TEST(generate_cbor_with_maps) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_TRACEPOINT;

    mbpf_map_def_t maps[2];
    memset(maps, 0, sizeof(maps));
    strcpy(maps[0].name, "counters");
    maps[0].type = MBPF_MAP_TYPE_ARRAY;
    maps[0].key_size = 4;
    maps[0].value_size = 8;
    maps[0].max_entries = 10;

    strcpy(maps[1].name, "cache");
    maps[1].type = MBPF_MAP_TYPE_HASH;
    maps[1].key_size = 16;
    maps[1].value_size = 32;
    maps[1].max_entries = 100;

    m.maps = maps;
    m.map_count = 2;

    size_t size = mbpf_manifest_cbor_size(&m);
    ASSERT(size > 0);

    uint8_t *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_cbor(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify it can be parsed back */
    mbpf_manifest_t parsed;
    err = mbpf_package_parse_manifest(buf, len, &parsed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(parsed.map_count, 2);
    ASSERT_STR_EQ(parsed.maps[0].name, "counters");
    ASSERT_EQ(parsed.maps[0].type, MBPF_MAP_TYPE_ARRAY);
    ASSERT_STR_EQ(parsed.maps[1].name, "cache");
    ASSERT_EQ(parsed.maps[1].type, MBPF_MAP_TYPE_HASH);

    mbpf_manifest_free(&parsed);
    free(buf);
    return 0;
}

/* Test: Generate CBOR manifest with helper versions */
TEST(generate_cbor_with_helper_versions) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_TIMER;
    m.capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT;

    mbpf_helper_version_t hvs[2];
    strcpy(hvs[0].name, "log");
    hvs[0].version = (1 << 16) | 0;
    strcpy(hvs[1].name, "emit");
    hvs[1].version = (1 << 16) | 1;

    m.helper_versions = hvs;
    m.helper_version_count = 2;

    size_t size = mbpf_manifest_cbor_size(&m);
    ASSERT(size > 0);

    uint8_t *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_cbor(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify it can be parsed back */
    mbpf_manifest_t parsed;
    err = mbpf_package_parse_manifest(buf, len, &parsed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(parsed.helper_version_count, 2);

    mbpf_manifest_free(&parsed);
    free(buf);
    return 0;
}

/* Test: Generate JSON manifest with minimal fields */
TEST(generate_json_minimal) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_NET_RX;

    size_t size = mbpf_manifest_json_size(&m);
    ASSERT(size > 0);

    char *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_json(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len + 1, size);

    /* Verify it's valid JSON by parsing */
    mbpf_manifest_t parsed;
    err = mbpf_package_parse_manifest(buf, len, &parsed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_STR_EQ(parsed.program_name, "test_prog");
    ASSERT_STR_EQ(parsed.program_version, "1.0.0");
    ASSERT_EQ(parsed.hook_type, MBPF_HOOK_NET_RX);

    mbpf_manifest_free(&parsed);
    free(buf);
    return 0;
}

/* Test: JSON size includes null terminator */
TEST(generate_json_exact_size) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "exact_size");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_NET_RX;

    size_t size = mbpf_manifest_json_size(&m);
    ASSERT(size > 0);

    char *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_json(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(len + 1, size);
    ASSERT_EQ(buf[len], '\0');

    free(buf);
    return 0;
}

/* Test: Generate JSON manifest with all fields */
TEST(generate_json_complete) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "timer_handler");
    strcpy(m.program_version, "3.0.0");
    strcpy(m.entry_symbol, "timer_entry");
    m.hook_type = MBPF_HOOK_TIMER;
    m.hook_ctx_abi_version = 1;
    m.heap_size = 65536;
    m.budgets.max_steps = 100000;
    m.budgets.max_helpers = 1000;
    m.budgets.max_wall_time_us = 50000;
    m.capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME | MBPF_CAP_STATS;

    size_t size = mbpf_manifest_json_size(&m);
    ASSERT(size > 0);

    char *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_json(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify it's valid JSON by parsing */
    mbpf_manifest_t parsed;
    err = mbpf_package_parse_manifest(buf, len, &parsed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_STR_EQ(parsed.program_name, "timer_handler");
    ASSERT_STR_EQ(parsed.entry_symbol, "timer_entry");
    ASSERT_EQ(parsed.hook_type, MBPF_HOOK_TIMER);
    ASSERT_EQ(parsed.heap_size, 65536);
    ASSERT_EQ(parsed.budgets.max_wall_time_us, 50000);
    ASSERT(parsed.capabilities & MBPF_CAP_LOG);
    ASSERT(parsed.capabilities & MBPF_CAP_TIME);
    ASSERT(parsed.capabilities & MBPF_CAP_STATS);

    mbpf_manifest_free(&parsed);
    free(buf);
    return 0;
}

/* Test: Generate JSON manifest with maps */
TEST(generate_json_with_maps) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_SECURITY;

    mbpf_map_def_t maps[1];
    memset(maps, 0, sizeof(maps));
    strcpy(maps[0].name, "policy");
    maps[0].type = MBPF_MAP_TYPE_HASH;
    maps[0].key_size = 8;
    maps[0].value_size = 4;
    maps[0].max_entries = 50;

    m.maps = maps;
    m.map_count = 1;

    size_t size = mbpf_manifest_json_size(&m);
    ASSERT(size > 0);

    char *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_json(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify it's valid JSON by parsing */
    mbpf_manifest_t parsed;
    err = mbpf_package_parse_manifest(buf, len, &parsed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(parsed.map_count, 1);
    ASSERT_STR_EQ(parsed.maps[0].name, "policy");
    ASSERT_EQ(parsed.maps[0].type, MBPF_MAP_TYPE_HASH);

    mbpf_manifest_free(&parsed);
    free(buf);
    return 0;
}

/* Test: Buffer too small returns error and required size */
TEST(buffer_too_small) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_NET_RX;

    uint8_t small_buf[10];
    size_t len = sizeof(small_buf);
    int err = mbpf_manifest_generate_cbor(&m, small_buf, &len);
    ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    ASSERT(len > sizeof(small_buf));

    /* Allocate correct size and try again */
    uint8_t *buf = malloc(len);
    size_t full_len = len;
    err = mbpf_manifest_generate_cbor(&m, buf, &full_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(full_len, len);

    free(buf);
    return 0;
}

/* Test: NULL output buffer returns required size */
TEST(null_buffer_returns_size) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_NET_RX;

    size_t len = 0;
    int err = mbpf_manifest_generate_cbor(&m, NULL, &len);
    ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    ASSERT(len > 0);

    size_t expected = mbpf_manifest_cbor_size(&m);
    ASSERT_EQ(len, expected);

    return 0;
}

/* Test: All hook types */
TEST(all_hook_types) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");

    mbpf_hook_type_t hooks[] = {
        MBPF_HOOK_TRACEPOINT,
        MBPF_HOOK_TIMER,
        MBPF_HOOK_NET_RX,
        MBPF_HOOK_NET_TX,
        MBPF_HOOK_SECURITY,
        MBPF_HOOK_CUSTOM
    };

    for (size_t i = 0; i < sizeof(hooks)/sizeof(hooks[0]); i++) {
        m.hook_type = hooks[i];
        ASSERT_EQ(mbpf_manifest_validate(&m), MBPF_OK);

        size_t size = mbpf_manifest_cbor_size(&m);
        ASSERT(size > 0);

        uint8_t *buf = malloc(size);
        ASSERT(buf != NULL);

        size_t len = size;
        int err = mbpf_manifest_generate_cbor(&m, buf, &len);
        ASSERT_EQ(err, MBPF_OK);

        mbpf_manifest_t parsed;
        err = mbpf_package_parse_manifest(buf, len, &parsed);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(parsed.hook_type, hooks[i]);

        mbpf_manifest_free(&parsed);
        free(buf);
    }

    return 0;
}

/* Test: All capabilities */
TEST(all_capabilities) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_NET_RX;
    m.capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE |
                     MBPF_CAP_MAP_ITERATE | MBPF_CAP_EMIT | MBPF_CAP_TIME |
                     MBPF_CAP_STATS;

    size_t size = mbpf_manifest_cbor_size(&m);
    uint8_t *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_cbor(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_manifest_t parsed;
    err = mbpf_package_parse_manifest(buf, len, &parsed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(parsed.capabilities, m.capabilities);

    mbpf_manifest_free(&parsed);
    free(buf);
    return 0;
}

/* Test: Big endian target */
TEST(big_endian_target) {
    mbpf_manifest_t m;
    mbpf_manifest_init_defaults(&m);
    strcpy(m.program_name, "test_prog");
    strcpy(m.program_version, "1.0.0");
    m.hook_type = MBPF_HOOK_NET_RX;
    m.target.word_size = 32;
    m.target.endianness = 1;  /* big endian */

    size_t size = mbpf_manifest_cbor_size(&m);
    uint8_t *buf = malloc(size);
    ASSERT(buf != NULL);

    size_t len = size;
    int err = mbpf_manifest_generate_cbor(&m, buf, &len);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_manifest_t parsed;
    err = mbpf_package_parse_manifest(buf, len, &parsed);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(parsed.target.word_size, 32);
    ASSERT_EQ(parsed.target.endianness, 1);

    mbpf_manifest_free(&parsed);
    free(buf);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Manifest Generation Tests\n");
    printf("===================================\n\n");

    printf("Initialization and validation:\n");
    RUN_TEST(init_defaults);
    RUN_TEST(validate_missing_fields);
    RUN_TEST(validate_heap_too_small);
    RUN_TEST(validate_invalid_word_size);

    printf("\nCBOR generation:\n");
    RUN_TEST(generate_cbor_minimal);
    RUN_TEST(generate_cbor_complete);
    RUN_TEST(generate_cbor_with_maps);
    RUN_TEST(generate_cbor_with_helper_versions);

    printf("\nJSON generation:\n");
    RUN_TEST(generate_json_minimal);
    RUN_TEST(generate_json_exact_size);
    RUN_TEST(generate_json_complete);
    RUN_TEST(generate_json_with_maps);

    printf("\nError handling:\n");
    RUN_TEST(buffer_too_small);
    RUN_TEST(null_buffer_returns_size);

    printf("\nEdge cases:\n");
    RUN_TEST(all_hook_types);
    RUN_TEST(all_capabilities);
    RUN_TEST(big_endian_target);

    printf("\n===================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
