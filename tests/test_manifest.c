/*
 * microBPF Manifest Parsing Tests
 *
 * Tests for CBOR manifest parsing including all required and optional fields.
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
#define ASSERT_STR_EQ(a, b) ASSERT(strcmp((a), (b)) == 0)

/* ============================================================================
 * CBOR Encoding Helpers
 * ============================================================================
 * These helpers build CBOR-encoded manifests for testing.
 */

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} cbor_writer_t;

static void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap) {
    w->data = buf;
    w->len = 0;
    w->cap = cap;
}

static int cbor_write_byte(cbor_writer_t *w, uint8_t b) {
    if (w->len >= w->cap) return -1;
    w->data[w->len++] = b;
    return 0;
}

static int cbor_write_bytes(cbor_writer_t *w, const uint8_t *data, size_t len) {
    if (w->len + len > w->cap) return -1;
    memcpy(w->data + w->len, data, len);
    w->len += len;
    return 0;
}

static int cbor_write_uint_header(cbor_writer_t *w, uint8_t major, uint64_t val) {
    uint8_t initial = major << 5;
    if (val < 24) {
        return cbor_write_byte(w, initial | (uint8_t)val);
    } else if (val <= 0xFF) {
        if (cbor_write_byte(w, initial | 24) != 0) return -1;
        return cbor_write_byte(w, (uint8_t)val);
    } else if (val <= 0xFFFF) {
        if (cbor_write_byte(w, initial | 25) != 0) return -1;
        if (cbor_write_byte(w, (val >> 8) & 0xFF) != 0) return -1;
        return cbor_write_byte(w, val & 0xFF);
    } else if (val <= 0xFFFFFFFF) {
        if (cbor_write_byte(w, initial | 26) != 0) return -1;
        if (cbor_write_byte(w, (val >> 24) & 0xFF) != 0) return -1;
        if (cbor_write_byte(w, (val >> 16) & 0xFF) != 0) return -1;
        if (cbor_write_byte(w, (val >> 8) & 0xFF) != 0) return -1;
        return cbor_write_byte(w, val & 0xFF);
    } else {
        if (cbor_write_byte(w, initial | 27) != 0) return -1;
        for (int i = 7; i >= 0; i--) {
            if (cbor_write_byte(w, (val >> (i * 8)) & 0xFF) != 0) return -1;
        }
        return 0;
    }
}

static int cbor_write_unsigned(cbor_writer_t *w, uint64_t val) {
    return cbor_write_uint_header(w, 0, val);
}

static int cbor_write_text_string(cbor_writer_t *w, const char *str) {
    size_t len = strlen(str);
    if (cbor_write_uint_header(w, 3, len) != 0) return -1;
    return cbor_write_bytes(w, (const uint8_t *)str, len);
}

static int cbor_write_map_header(cbor_writer_t *w, uint64_t count) {
    return cbor_write_uint_header(w, 5, count);
}

static int cbor_write_array_header(cbor_writer_t *w, uint64_t count) {
    return cbor_write_uint_header(w, 4, count);
}

/* Build a complete valid manifest with all required fields */
static size_t build_complete_manifest(uint8_t *buf, size_t cap) {
    cbor_writer_t w;
    cbor_writer_init(&w, buf, cap);

    /* Top-level map with 11 required entries + 1 optional (maps) */
    cbor_write_map_header(&w, 12);

    /* program_name */
    cbor_write_text_string(&w, "program_name");
    cbor_write_text_string(&w, "net_rx_filter");

    /* program_version */
    cbor_write_text_string(&w, "program_version");
    cbor_write_text_string(&w, "1.0.0");

    /* hook_type */
    cbor_write_text_string(&w, "hook_type");
    cbor_write_unsigned(&w, MBPF_HOOK_NET_RX);

    /* hook_ctx_abi_version */
    cbor_write_text_string(&w, "hook_ctx_abi_version");
    cbor_write_unsigned(&w, 1);

    /* entry_symbol */
    cbor_write_text_string(&w, "entry_symbol");
    cbor_write_text_string(&w, "my_entry_func");

    /* mquickjs_bytecode_version */
    cbor_write_text_string(&w, "mquickjs_bytecode_version");
    cbor_write_unsigned(&w, 42);

    /* target */
    cbor_write_text_string(&w, "target");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "word_size");
    cbor_write_unsigned(&w, 64);
    cbor_write_text_string(&w, "endianness");
    cbor_write_text_string(&w, "little");

    /* mbpf_api_version */
    cbor_write_text_string(&w, "mbpf_api_version");
    cbor_write_unsigned(&w, (1 << 16) | 2);  /* major=1, minor=2 */

    /* heap_size */
    cbor_write_text_string(&w, "heap_size");
    cbor_write_unsigned(&w, 32768);

    /* budgets */
    cbor_write_text_string(&w, "budgets");
    cbor_write_map_header(&w, 3);
    cbor_write_text_string(&w, "max_steps");
    cbor_write_unsigned(&w, 50000);
    cbor_write_text_string(&w, "max_helpers");
    cbor_write_unsigned(&w, 500);
    cbor_write_text_string(&w, "max_wall_time_us");
    cbor_write_unsigned(&w, 10000);

    /* capabilities */
    cbor_write_text_string(&w, "capabilities");
    cbor_write_array_header(&w, 3);
    cbor_write_text_string(&w, "CAP_LOG");
    cbor_write_text_string(&w, "CAP_MAP_READ");
    cbor_write_text_string(&w, "CAP_MAP_WRITE");

    /* maps (optional but we include it) */
    cbor_write_text_string(&w, "maps");
    cbor_write_array_header(&w, 2);
    /* Map 1 */
    cbor_write_map_header(&w, 5);
    cbor_write_text_string(&w, "name");
    cbor_write_text_string(&w, "counters");
    cbor_write_text_string(&w, "type");
    cbor_write_unsigned(&w, MBPF_MAP_TYPE_ARRAY);
    cbor_write_text_string(&w, "key_size");
    cbor_write_unsigned(&w, 4);
    cbor_write_text_string(&w, "value_size");
    cbor_write_unsigned(&w, 8);
    cbor_write_text_string(&w, "max_entries");
    cbor_write_unsigned(&w, 100);
    /* Map 2 */
    cbor_write_map_header(&w, 5);
    cbor_write_text_string(&w, "name");
    cbor_write_text_string(&w, "cache");
    cbor_write_text_string(&w, "type");
    cbor_write_unsigned(&w, MBPF_MAP_TYPE_HASH);
    cbor_write_text_string(&w, "key_size");
    cbor_write_unsigned(&w, 16);
    cbor_write_text_string(&w, "value_size");
    cbor_write_unsigned(&w, 64);
    cbor_write_text_string(&w, "max_entries");
    cbor_write_unsigned(&w, 1000);

    return w.len;
}

/* Build manifest with helper_versions */
static size_t build_manifest_with_helper_versions(uint8_t *buf, size_t cap) {
    cbor_writer_t w;
    cbor_writer_init(&w, buf, cap);

    cbor_write_map_header(&w, 11);

    /* Required fields */
    cbor_write_text_string(&w, "program_name");
    cbor_write_text_string(&w, "test_prog");
    cbor_write_text_string(&w, "program_version");
    cbor_write_text_string(&w, "2.0.0");
    cbor_write_text_string(&w, "hook_type");
    cbor_write_unsigned(&w, MBPF_HOOK_TIMER);
    cbor_write_text_string(&w, "hook_ctx_abi_version");
    cbor_write_unsigned(&w, 2);
    cbor_write_text_string(&w, "mquickjs_bytecode_version");
    cbor_write_unsigned(&w, 100);
    cbor_write_text_string(&w, "mbpf_api_version");
    cbor_write_unsigned(&w, (2 << 16) | 0);
    cbor_write_text_string(&w, "heap_size");
    cbor_write_unsigned(&w, 65536);
    cbor_write_text_string(&w, "budgets");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "max_steps");
    cbor_write_unsigned(&w, 100000);
    cbor_write_text_string(&w, "max_helpers");
    cbor_write_unsigned(&w, 1000);
    cbor_write_text_string(&w, "capabilities");
    cbor_write_array_header(&w, 2);
    cbor_write_text_string(&w, "CAP_TIME");
    cbor_write_text_string(&w, "CAP_STATS");
    cbor_write_text_string(&w, "target");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "word_size");
    cbor_write_unsigned(&w, 32);
    cbor_write_text_string(&w, "endianness");
    cbor_write_unsigned(&w, 0); /* numeric 0 = little */

    /* helper_versions (optional) */
    cbor_write_text_string(&w, "helper_versions");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "log");
    cbor_write_unsigned(&w, (1 << 16) | 0);
    cbor_write_text_string(&w, "emit");
    cbor_write_unsigned(&w, (1 << 16) | 1);

    return w.len;
}

/* Build manifest missing a required field */
static size_t build_manifest_missing_program_name(uint8_t *buf, size_t cap) {
    cbor_writer_t w;
    cbor_writer_init(&w, buf, cap);

    cbor_write_map_header(&w, 9);  /* Missing program_name */

    cbor_write_text_string(&w, "program_version");
    cbor_write_text_string(&w, "1.0.0");
    cbor_write_text_string(&w, "hook_type");
    cbor_write_unsigned(&w, MBPF_HOOK_NET_RX);
    cbor_write_text_string(&w, "hook_ctx_abi_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "mquickjs_bytecode_version");
    cbor_write_unsigned(&w, 42);
    cbor_write_text_string(&w, "mbpf_api_version");
    cbor_write_unsigned(&w, 0x00010001);
    cbor_write_text_string(&w, "heap_size");
    cbor_write_unsigned(&w, 16384);
    cbor_write_text_string(&w, "budgets");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "max_steps");
    cbor_write_unsigned(&w, 10000);
    cbor_write_text_string(&w, "max_helpers");
    cbor_write_unsigned(&w, 100);
    cbor_write_text_string(&w, "capabilities");
    cbor_write_array_header(&w, 0);
    cbor_write_text_string(&w, "target");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "word_size");
    cbor_write_unsigned(&w, 64);
    cbor_write_text_string(&w, "endianness");
    cbor_write_text_string(&w, "little");

    return w.len;
}

/* ============================================================================
 * Test Cases
 * ============================================================================ */

/* Test: Parse complete CBOR manifest with all required fields */
TEST(parse_complete_manifest) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));
    ASSERT(len > 0);

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify all fields */
    ASSERT_STR_EQ(manifest.program_name, "net_rx_filter");
    ASSERT_STR_EQ(manifest.program_version, "1.0.0");
    ASSERT_EQ(manifest.hook_type, MBPF_HOOK_NET_RX);
    ASSERT_EQ(manifest.hook_ctx_abi_version, 1);
    ASSERT_STR_EQ(manifest.entry_symbol, "my_entry_func");

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Extract program_name, program_version, hook_type */
TEST(extract_basic_fields) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_STR_EQ(manifest.program_name, "net_rx_filter");
    ASSERT_STR_EQ(manifest.program_version, "1.0.0");
    ASSERT_EQ(manifest.hook_type, MBPF_HOOK_NET_RX);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Extract hook_ctx_abi_version, entry_symbol */
TEST(extract_hook_and_entry) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(manifest.hook_ctx_abi_version, 1);
    ASSERT_STR_EQ(manifest.entry_symbol, "my_entry_func");

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Extract mquickjs_bytecode_version and target */
TEST(extract_bytecode_and_target) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(manifest.mquickjs_bytecode_version, 42);
    ASSERT_EQ(manifest.target.word_size, 64);
    ASSERT_EQ(manifest.target.endianness, 0);  /* little */

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Extract mbpf_api_version, heap_size */
TEST(extract_api_version_and_heap) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(manifest.mbpf_api_version, (1 << 16) | 2);
    ASSERT_EQ(manifest.heap_size, 32768);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Extract budgets (max_steps, max_helpers, max_wall_time_us) */
TEST(extract_budgets) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(manifest.budgets.max_steps, 50000);
    ASSERT_EQ(manifest.budgets.max_helpers, 500);
    ASSERT_EQ(manifest.budgets.max_wall_time_us, 10000);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Extract capabilities array */
TEST(extract_capabilities) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    /* Should have CAP_LOG | CAP_MAP_READ | CAP_MAP_WRITE */
    ASSERT(manifest.capabilities & MBPF_CAP_LOG);
    ASSERT(manifest.capabilities & MBPF_CAP_MAP_READ);
    ASSERT(manifest.capabilities & MBPF_CAP_MAP_WRITE);
    ASSERT(!(manifest.capabilities & MBPF_CAP_EMIT));

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Extract optional helper_versions map */
TEST(extract_helper_versions) {
    uint8_t buf[2048];
    size_t len = build_manifest_with_helper_versions(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(manifest.helper_version_count, 2);
    ASSERT(manifest.helper_versions != NULL);

    /* Check helper versions (order may vary) */
    bool found_log = false, found_emit = false;
    for (uint32_t i = 0; i < manifest.helper_version_count; i++) {
        if (strcmp(manifest.helper_versions[i].name, "log") == 0) {
            ASSERT_EQ(manifest.helper_versions[i].version, (1 << 16) | 0);
            found_log = true;
        } else if (strcmp(manifest.helper_versions[i].name, "emit") == 0) {
            ASSERT_EQ(manifest.helper_versions[i].version, (1 << 16) | 1);
            found_emit = true;
        }
    }
    ASSERT(found_log);
    ASSERT(found_emit);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Extract maps array definitions */
TEST(extract_maps_array) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(manifest.map_count, 2);
    ASSERT(manifest.maps != NULL);

    /* Map 1: counters */
    ASSERT_STR_EQ(manifest.maps[0].name, "counters");
    ASSERT_EQ(manifest.maps[0].type, MBPF_MAP_TYPE_ARRAY);
    ASSERT_EQ(manifest.maps[0].key_size, 4);
    ASSERT_EQ(manifest.maps[0].value_size, 8);
    ASSERT_EQ(manifest.maps[0].max_entries, 100);

    /* Map 2: cache */
    ASSERT_STR_EQ(manifest.maps[1].name, "cache");
    ASSERT_EQ(manifest.maps[1].type, MBPF_MAP_TYPE_HASH);
    ASSERT_EQ(manifest.maps[1].key_size, 16);
    ASSERT_EQ(manifest.maps[1].value_size, 64);
    ASSERT_EQ(manifest.maps[1].max_entries, 1000);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Reject manifest missing required fields */
TEST(reject_missing_required_fields) {
    uint8_t buf[2048];
    size_t len = build_manifest_missing_program_name(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);

    return 0;
}

/* Test: Reject empty manifest */
TEST(reject_empty_manifest) {
    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(NULL, 0, &manifest);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    uint8_t buf[1] = {0};
    err = mbpf_package_parse_manifest(buf, 0, &manifest);
    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);

    return 0;
}

/* Test: Reject null output parameter */
TEST(reject_null_output) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));

    int err = mbpf_package_parse_manifest(buf, len, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test: Default entry_symbol when not specified */
TEST(default_entry_symbol) {
    cbor_writer_t w;
    uint8_t buf[2048];
    cbor_writer_init(&w, buf, sizeof(buf));

    /* Build manifest without entry_symbol */
    cbor_write_map_header(&w, 10);
    cbor_write_text_string(&w, "program_name");
    cbor_write_text_string(&w, "test");
    cbor_write_text_string(&w, "program_version");
    cbor_write_text_string(&w, "1.0");
    cbor_write_text_string(&w, "hook_type");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "hook_ctx_abi_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "mquickjs_bytecode_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "mbpf_api_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "heap_size");
    cbor_write_unsigned(&w, 16384);
    cbor_write_text_string(&w, "budgets");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "max_steps");
    cbor_write_unsigned(&w, 1000);
    cbor_write_text_string(&w, "max_helpers");
    cbor_write_unsigned(&w, 100);
    cbor_write_text_string(&w, "capabilities");
    cbor_write_array_header(&w, 0);
    cbor_write_text_string(&w, "target");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "word_size");
    cbor_write_unsigned(&w, 64);
    cbor_write_text_string(&w, "endianness");
    cbor_write_text_string(&w, "little");

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, w.len, &manifest);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_STR_EQ(manifest.entry_symbol, "mbpf_prog");

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Big endianness with string value */
TEST(parse_big_endian_target) {
    cbor_writer_t w;
    uint8_t buf[2048];
    cbor_writer_init(&w, buf, sizeof(buf));

    cbor_write_map_header(&w, 10);
    cbor_write_text_string(&w, "program_name");
    cbor_write_text_string(&w, "test");
    cbor_write_text_string(&w, "program_version");
    cbor_write_text_string(&w, "1.0");
    cbor_write_text_string(&w, "hook_type");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "hook_ctx_abi_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "mquickjs_bytecode_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "mbpf_api_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "heap_size");
    cbor_write_unsigned(&w, 16384);
    cbor_write_text_string(&w, "budgets");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "max_steps");
    cbor_write_unsigned(&w, 1000);
    cbor_write_text_string(&w, "max_helpers");
    cbor_write_unsigned(&w, 100);
    cbor_write_text_string(&w, "capabilities");
    cbor_write_array_header(&w, 0);
    cbor_write_text_string(&w, "target");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "word_size");
    cbor_write_unsigned(&w, 32);
    cbor_write_text_string(&w, "endianness");
    cbor_write_text_string(&w, "big");

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, w.len, &manifest);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(manifest.target.word_size, 32);
    ASSERT_EQ(manifest.target.endianness, 1);  /* big */

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: All capabilities */
TEST(parse_all_capabilities) {
    cbor_writer_t w;
    uint8_t buf[2048];
    cbor_writer_init(&w, buf, sizeof(buf));

    cbor_write_map_header(&w, 10);
    cbor_write_text_string(&w, "program_name");
    cbor_write_text_string(&w, "test");
    cbor_write_text_string(&w, "program_version");
    cbor_write_text_string(&w, "1.0");
    cbor_write_text_string(&w, "hook_type");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "hook_ctx_abi_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "mquickjs_bytecode_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "mbpf_api_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "heap_size");
    cbor_write_unsigned(&w, 16384);
    cbor_write_text_string(&w, "budgets");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "max_steps");
    cbor_write_unsigned(&w, 1000);
    cbor_write_text_string(&w, "max_helpers");
    cbor_write_unsigned(&w, 100);
    cbor_write_text_string(&w, "capabilities");
    cbor_write_array_header(&w, 7);
    cbor_write_text_string(&w, "CAP_LOG");
    cbor_write_text_string(&w, "CAP_MAP_READ");
    cbor_write_text_string(&w, "CAP_MAP_WRITE");
    cbor_write_text_string(&w, "CAP_MAP_ITERATE");
    cbor_write_text_string(&w, "CAP_EMIT");
    cbor_write_text_string(&w, "CAP_TIME");
    cbor_write_text_string(&w, "CAP_STATS");
    cbor_write_text_string(&w, "target");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "word_size");
    cbor_write_unsigned(&w, 64);
    cbor_write_text_string(&w, "endianness");
    cbor_write_unsigned(&w, 0);

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, w.len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    uint32_t expected = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE |
                        MBPF_CAP_MAP_ITERATE | MBPF_CAP_EMIT | MBPF_CAP_TIME |
                        MBPF_CAP_STATS;
    ASSERT_EQ(manifest.capabilities, expected);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Manifest free is safe to call multiple times */
TEST(manifest_free_safe) {
    uint8_t buf[2048];
    size_t len = build_complete_manifest(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_manifest_free(&manifest);
    mbpf_manifest_free(&manifest);  /* Second call should be safe */
    mbpf_manifest_free(NULL);       /* NULL should be safe */

    return 0;
}

/* Test: Budgets without optional max_wall_time_us */
TEST(budgets_without_wall_time) {
    uint8_t buf[2048];
    size_t len = build_manifest_with_helper_versions(buf, sizeof(buf));

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, len, &manifest);
    ASSERT_EQ(err, MBPF_OK);

    /* max_wall_time_us should be 0 (not specified) */
    ASSERT_EQ(manifest.budgets.max_wall_time_us, 0);
    ASSERT_EQ(manifest.budgets.max_steps, 100000);
    ASSERT_EQ(manifest.budgets.max_helpers, 1000);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: Reject manifest missing target field */
TEST(reject_missing_target) {
    cbor_writer_t w;
    uint8_t buf[2048];
    cbor_writer_init(&w, buf, sizeof(buf));

    /* Build manifest without target field */
    cbor_write_map_header(&w, 9);  /* Missing target */
    cbor_write_text_string(&w, "program_name");
    cbor_write_text_string(&w, "test");
    cbor_write_text_string(&w, "program_version");
    cbor_write_text_string(&w, "1.0");
    cbor_write_text_string(&w, "hook_type");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "hook_ctx_abi_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "mquickjs_bytecode_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "mbpf_api_version");
    cbor_write_unsigned(&w, 1);
    cbor_write_text_string(&w, "heap_size");
    cbor_write_unsigned(&w, 16384);
    cbor_write_text_string(&w, "budgets");
    cbor_write_map_header(&w, 2);
    cbor_write_text_string(&w, "max_steps");
    cbor_write_unsigned(&w, 1000);
    cbor_write_text_string(&w, "max_helpers");
    cbor_write_unsigned(&w, 100);
    cbor_write_text_string(&w, "capabilities");
    cbor_write_array_header(&w, 0);

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(buf, w.len, &manifest);
    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);

    return 0;
}

/* ============================================================================
 * JSON Manifest Tests
 * ============================================================================ */

/* Build a complete JSON manifest string */
static const char *build_json_manifest(void) {
    return
        "{\n"
        "  \"program_name\": \"json_test_prog\",\n"
        "  \"program_version\": \"2.0.0\",\n"
        "  \"hook_type\": 3,\n"
        "  \"hook_ctx_abi_version\": 1,\n"
        "  \"entry_symbol\": \"json_entry\",\n"
        "  \"mquickjs_bytecode_version\": 99,\n"
        "  \"target\": {\n"
        "    \"word_size\": 64,\n"
        "    \"endianness\": \"little\"\n"
        "  },\n"
        "  \"mbpf_api_version\": 65538,\n"
        "  \"heap_size\": 65536,\n"
        "  \"budgets\": {\n"
        "    \"max_steps\": 200000,\n"
        "    \"max_helpers\": 2000,\n"
        "    \"max_wall_time_us\": 50000\n"
        "  },\n"
        "  \"capabilities\": [\"CAP_LOG\", \"CAP_TIME\"]\n"
        "}";
}

/* Test: Parse JSON manifest */
TEST(parse_json_manifest) {
    const char *json = build_json_manifest();

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(json, strlen(json), &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_STR_EQ(manifest.program_name, "json_test_prog");
    ASSERT_STR_EQ(manifest.program_version, "2.0.0");
    ASSERT_EQ(manifest.hook_type, 3);
    ASSERT_EQ(manifest.hook_ctx_abi_version, 1);
    ASSERT_STR_EQ(manifest.entry_symbol, "json_entry");
    ASSERT_EQ(manifest.mquickjs_bytecode_version, 99);
    ASSERT_EQ(manifest.target.word_size, 64);
    ASSERT_EQ(manifest.target.endianness, 0);
    ASSERT_EQ(manifest.mbpf_api_version, 65538);
    ASSERT_EQ(manifest.heap_size, 65536);
    ASSERT_EQ(manifest.budgets.max_steps, 200000);
    ASSERT_EQ(manifest.budgets.max_helpers, 2000);
    ASSERT_EQ(manifest.budgets.max_wall_time_us, 50000);
    ASSERT(manifest.capabilities & MBPF_CAP_LOG);
    ASSERT(manifest.capabilities & MBPF_CAP_TIME);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: JSON with maps array */
TEST(parse_json_with_maps) {
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
        "\"budgets\":{\"max_steps\":1000,\"max_helpers\":100},"
        "\"capabilities\":[],"
        "\"maps\":["
        "{\"name\":\"counter\",\"type\":1,\"key_size\":4,\"value_size\":8,\"max_entries\":10},"
        "{\"name\":\"lookup\",\"type\":2,\"key_size\":16,\"value_size\":32,\"max_entries\":100}"
        "]"
        "}";

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(json, strlen(json), &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(manifest.map_count, 2);
    ASSERT_STR_EQ(manifest.maps[0].name, "counter");
    ASSERT_EQ(manifest.maps[0].type, 1);
    ASSERT_EQ(manifest.maps[0].key_size, 4);
    ASSERT_EQ(manifest.maps[0].value_size, 8);
    ASSERT_EQ(manifest.maps[0].max_entries, 10);
    ASSERT_STR_EQ(manifest.maps[1].name, "lookup");
    ASSERT_EQ(manifest.maps[1].type, 2);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* Test: JSON missing required target field */
TEST(reject_json_missing_target) {
    const char *json =
        "{"
        "\"program_name\":\"test\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":16384,"
        "\"budgets\":{\"max_steps\":1000,\"max_helpers\":100},"
        "\"capabilities\":[]"
        "}";

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(json, strlen(json), &manifest);
    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);

    return 0;
}

/* Test: JSON with helper_versions */
TEST(parse_json_helper_versions) {
    const char *json =
        "{"
        "\"program_name\":\"test\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":32,\"endianness\":\"big\"},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":16384,"
        "\"budgets\":{\"max_steps\":1000,\"max_helpers\":100},"
        "\"capabilities\":[\"CAP_EMIT\"],"
        "\"helper_versions\":{\"log\":65536,\"emit\":65537}"
        "}";

    mbpf_manifest_t manifest;
    int err = mbpf_package_parse_manifest(json, strlen(json), &manifest);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(manifest.target.word_size, 32);
    ASSERT_EQ(manifest.target.endianness, 1);  /* big */
    ASSERT_EQ(manifest.helper_version_count, 2);
    ASSERT(manifest.capabilities & MBPF_CAP_EMIT);

    mbpf_manifest_free(&manifest);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Manifest Parsing Tests\n");
    printf("================================\n");

    /* Basic field extraction */
    RUN_TEST(parse_complete_manifest);
    RUN_TEST(extract_basic_fields);
    RUN_TEST(extract_hook_and_entry);
    RUN_TEST(extract_bytecode_and_target);
    RUN_TEST(extract_api_version_and_heap);
    RUN_TEST(extract_budgets);
    RUN_TEST(extract_capabilities);

    /* Optional fields */
    RUN_TEST(extract_helper_versions);
    RUN_TEST(extract_maps_array);

    /* Validation */
    RUN_TEST(reject_missing_required_fields);
    RUN_TEST(reject_empty_manifest);
    RUN_TEST(reject_null_output);
    RUN_TEST(reject_missing_target);

    /* Edge cases */
    RUN_TEST(default_entry_symbol);
    RUN_TEST(parse_big_endian_target);
    RUN_TEST(parse_all_capabilities);
    RUN_TEST(manifest_free_safe);
    RUN_TEST(budgets_without_wall_time);

    /* JSON parsing */
    RUN_TEST(parse_json_manifest);
    RUN_TEST(parse_json_with_maps);
    RUN_TEST(reject_json_missing_target);
    RUN_TEST(parse_json_helper_versions);

    printf("\nResults: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
