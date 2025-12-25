/*
 * microBPF Debug Symbols Tests
 *
 * Tests for the observability-debug-symbols task:
 * 1. Create package with DEBUG section containing symbol names
 * 2. Load package and verify debug info is available
 * 3. Verify source hash for provenance tracking
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

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
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)
#define ASSERT_STREQ(a, b) ASSERT(strcmp((a), (b)) == 0)

/* Build a minimal valid JSON manifest */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    const char *json =
        "{"
        "\"program_name\":\"debug_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"entry_symbol\":\"mbpf_prog\","
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"],"
        "\"maps\":["
        "{\"name\":\"counter\",\"type\":1,\"key_size\":4,\"value_size\":8,\"max_entries\":10,\"flags\":0},"
        "{\"name\":\"data\",\"type\":2,\"key_size\":16,\"value_size\":64,\"max_entries\":100,\"flags\":0}"
        "]"
        "}";
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Sample bytecode (minimal valid for testing - fake bytecode) */
static const uint8_t sample_bytecode[] = {
    0x02,  /* JS_BYTECODE_VERSION */
    0x00, 0x00, 0x00, 0x00,  /* bytecode header bytes */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_debug.js";
    const char *bc_file = "/tmp/test_debug.qjbc";

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

/* Build a complete .mbpf package with bytecode and debug section */
static size_t build_mbpf_package_with_debug(uint8_t *buf, size_t cap,
                                             const uint8_t *bytecode, size_t bc_len,
                                             const uint8_t *debug, size_t debug_len) {
    if (cap < 256) return 0;

    uint8_t manifest[1024];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
    if (manifest_len == 0) return 0;

    /* Calculate offsets */
    uint32_t header_size = 20 + 3 * 16;  /* header + 3 section descriptors */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t debug_offset = bytecode_offset + (uint32_t)bc_len;
    uint32_t total_size = debug_offset + (uint32_t)debug_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    /* magic "MBPF" in little-endian: 0x4D425046 */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    /* format_version = 1 */
    *p++ = 0x01; *p++ = 0x00;
    /* header_size */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    /* flags = 0 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* section_count = 3 */
    *p++ = 0x03; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* file_crc32 = 0 (disabled) */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 0: MANIFEST (type=1) */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Section 2: DEBUG (type=4) */
    *p++ = 0x04; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = debug_offset & 0xFF; *p++ = (debug_offset >> 8) & 0xFF;
    *p++ = (debug_offset >> 16) & 0xFF; *p++ = (debug_offset >> 24) & 0xFF;
    *p++ = debug_len & 0xFF; *p++ = (debug_len >> 8) & 0xFF;
    *p++ = (debug_len >> 16) & 0xFF; *p++ = (debug_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Manifest section data */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    /* Bytecode section data */
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    /* Debug section data */
    memcpy(p, debug, debug_len);
    p += debug_len;

    return (size_t)(p - buf);
}

/* Build a complete .mbpf package without debug section */
static size_t build_mbpf_package_no_debug(uint8_t *buf, size_t cap,
                                           const uint8_t *bytecode, size_t bc_len) {
    if (cap < 256) return 0;

    uint8_t manifest[1024];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
    if (manifest_len == 0) return 0;

    /* Calculate offsets */
    uint32_t header_size = 20 + 2 * 16;  /* header + 2 section descriptors */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

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

    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* Helper to write little-endian u32 */
static void write_le32(uint8_t *buf, uint32_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

/*
 * Create a debug section binary blob.
 *
 * Format:
 *   [4 bytes: flags]
 *   [32 bytes: source_hash]
 *   [4 bytes: entry_symbol_len]
 *   [entry_symbol_len bytes: entry_symbol (null-terminated)]
 *   [4 bytes: hook_name_len]
 *   [hook_name_len bytes: hook_name (null-terminated)]
 *   [4 bytes: map_count]
 *   For each map:
 *     [4 bytes: name_len]
 *     [name_len bytes: name (null-terminated)]
 */
static uint8_t *create_debug_section(
    uint32_t flags,
    const uint8_t *source_hash,  /* 32 bytes or NULL */
    const char *entry_symbol,
    const char *hook_name,
    const char **map_names,
    uint32_t map_count,
    size_t *out_len
) {
    /* Calculate size */
    size_t entry_len = entry_symbol ? strlen(entry_symbol) + 1 : 0;
    size_t hook_len = hook_name ? strlen(hook_name) + 1 : 0;
    size_t size = 4 + 32 + 4 + entry_len + 4 + hook_len + 4;
    for (uint32_t i = 0; i < map_count; i++) {
        size += 4 + (map_names[i] ? strlen(map_names[i]) + 1 : 0);
    }

    uint8_t *buf = calloc(1, size);
    if (!buf) return NULL;

    uint8_t *p = buf;

    /* Flags */
    write_le32(p, flags);
    p += 4;

    /* Source hash */
    if (source_hash) {
        memcpy(p, source_hash, 32);
    }
    p += 32;

    /* Entry symbol */
    write_le32(p, (uint32_t)entry_len);
    p += 4;
    if (entry_len > 0) {
        memcpy(p, entry_symbol, entry_len);
        p += entry_len;
    }

    /* Hook name */
    write_le32(p, (uint32_t)hook_len);
    p += 4;
    if (hook_len > 0) {
        memcpy(p, hook_name, hook_len);
        p += hook_len;
    }

    /* Map count */
    write_le32(p, map_count);
    p += 4;

    /* Map names */
    for (uint32_t i = 0; i < map_count; i++) {
        size_t len = map_names[i] ? strlen(map_names[i]) + 1 : 0;
        write_le32(p, (uint32_t)len);
        p += 4;
        if (len > 0) {
            memcpy(p, map_names[i], len);
            p += len;
        }
    }

    *out_len = size;
    return buf;
}

/* Helper to create a complete package with debug section (for package-level tests) */
static uint8_t *create_package_with_debug(
    const uint8_t *debug_section,
    size_t debug_len,
    size_t *out_pkg_len
) {
    uint8_t manifest[1024];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
    if (manifest_len == 0) return NULL;

    mbpf_section_input_t sections[3];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = manifest;
    sections[0].len = manifest_len;
    sections[1].type = MBPF_SEC_BYTECODE;
    sections[1].data = sample_bytecode;
    sections[1].len = sizeof(sample_bytecode);
    sections[2].type = MBPF_SEC_DEBUG;
    sections[2].data = debug_section;
    sections[2].len = debug_len;

    size_t required = mbpf_package_size(sections, 3);
    uint8_t *pkg = malloc(required);
    if (!pkg) return NULL;
    size_t len = required;

    int err = mbpf_package_assemble(sections, 3, NULL, pkg, &len);
    if (err != MBPF_OK) {
        free(pkg);
        return NULL;
    }

    *out_pkg_len = len;
    return pkg;
}

/* ============================================================================
 * Tests
 * ============================================================================ */

/* Test parsing a minimal debug section */
TEST(parse_minimal_debug_section) {
    uint8_t source_hash[32];
    memset(source_hash, 0, sizeof(source_hash));

    size_t debug_len;
    uint8_t *debug = create_debug_section(0, source_hash, "", "", NULL, 0, &debug_len);
    ASSERT_NOT_NULL(debug);

    mbpf_debug_info_t info;
    int err = mbpf_debug_info_parse(debug, debug_len, &info);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(info.flags, 0);
    ASSERT_EQ(info.map_count, 0);
    ASSERT(info.entry_symbol[0] == '\0');
    ASSERT(info.hook_name[0] == '\0');

    mbpf_debug_info_free(&info);
    free(debug);
    return 0;
}

/* Test parsing debug section with all fields */
TEST(parse_full_debug_section) {
    uint8_t source_hash[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    const char *map_names[] = { "counter", "data", "events" };

    size_t debug_len;
    uint8_t *debug = create_debug_section(
        MBPF_DEBUG_FLAG_HAS_SOURCE_HASH,
        source_hash,
        "mbpf_prog",
        "NET_RX",
        map_names,
        3,
        &debug_len
    );
    ASSERT_NOT_NULL(debug);

    mbpf_debug_info_t info;
    int err = mbpf_debug_info_parse(debug, debug_len, &info);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(info.flags, MBPF_DEBUG_FLAG_HAS_SOURCE_HASH);
    ASSERT(memcmp(info.source_hash, source_hash, 32) == 0);
    ASSERT_STREQ(info.entry_symbol, "mbpf_prog");
    ASSERT_STREQ(info.hook_name, "NET_RX");
    ASSERT_EQ(info.map_count, 3);
    ASSERT_NOT_NULL(info.map_names);
    ASSERT_STREQ(info.map_names[0], "counter");
    ASSERT_STREQ(info.map_names[1], "data");
    ASSERT_STREQ(info.map_names[2], "events");

    mbpf_debug_info_free(&info);
    free(debug);
    return 0;
}

/* Test package has_debug check */
TEST(package_has_debug) {
    uint8_t source_hash[32] = {0};
    size_t debug_len;
    uint8_t *debug = create_debug_section(0, source_hash, "test", "hook", NULL, 0, &debug_len);
    ASSERT_NOT_NULL(debug);

    size_t pkg_len;
    uint8_t *pkg = create_package_with_debug(debug, debug_len, &pkg_len);
    ASSERT_NOT_NULL(pkg);

    int has_debug = 0;
    int err = mbpf_package_has_debug(pkg, pkg_len, &has_debug);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(has_debug, 1);

    free(pkg);
    free(debug);
    return 0;
}

/* Test package without debug section */
TEST(package_no_debug) {
    uint8_t manifest[1024];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    mbpf_section_input_t sections[2];
    sections[0].type = MBPF_SEC_MANIFEST;
    sections[0].data = manifest;
    sections[0].len = manifest_len;
    sections[1].type = MBPF_SEC_BYTECODE;
    sections[1].data = sample_bytecode;
    sections[1].len = sizeof(sample_bytecode);

    size_t required = mbpf_package_size(sections, 2);
    uint8_t *pkg = malloc(required);
    ASSERT_NOT_NULL(pkg);
    size_t len = required;

    int err = mbpf_package_assemble(sections, 2, NULL, pkg, &len);
    ASSERT_EQ(err, MBPF_OK);

    int has_debug = 1;
    err = mbpf_package_has_debug(pkg, len, &has_debug);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(has_debug, 0);

    mbpf_debug_info_t info;
    err = mbpf_package_get_debug_info(pkg, len, &info);
    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);

    free(pkg);
    return 0;
}

/* Test getting debug info from package */
TEST(package_get_debug_info) {
    uint8_t source_hash[32] = { 0xAB, 0xCD, 0xEF, 0x12 };
    const char *map_names[] = { "mymap" };

    size_t debug_len;
    uint8_t *debug = create_debug_section(
        MBPF_DEBUG_FLAG_HAS_SOURCE_HASH,
        source_hash,
        "custom_entry",
        "TRACEPOINT",
        map_names,
        1,
        &debug_len
    );
    ASSERT_NOT_NULL(debug);

    size_t pkg_len;
    uint8_t *pkg = create_package_with_debug(debug, debug_len, &pkg_len);
    ASSERT_NOT_NULL(pkg);

    mbpf_debug_info_t info;
    int err = mbpf_package_get_debug_info(pkg, pkg_len, &info);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_STREQ(info.entry_symbol, "custom_entry");
    ASSERT_STREQ(info.hook_name, "TRACEPOINT");
    ASSERT_EQ(info.map_count, 1);
    ASSERT_STREQ(info.map_names[0], "mymap");

    mbpf_debug_info_free(&info);
    free(pkg);
    free(debug);
    return 0;
}

/* Test source hash for provenance */
TEST(source_hash_provenance) {
    /* Create a unique source hash */
    uint8_t source_hash[32];
    for (int i = 0; i < 32; i++) {
        source_hash[i] = (uint8_t)(i * 7 + 0x42);
    }

    size_t debug_len;
    uint8_t *debug = create_debug_section(
        MBPF_DEBUG_FLAG_HAS_SOURCE_HASH,
        source_hash,
        "mbpf_prog",
        "NET_RX",
        NULL,
        0,
        &debug_len
    );
    ASSERT_NOT_NULL(debug);

    mbpf_debug_info_t info;
    int err = mbpf_debug_info_parse(debug, debug_len, &info);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT(info.flags & MBPF_DEBUG_FLAG_HAS_SOURCE_HASH);

    /* Verify source hash matches */
    ASSERT(memcmp(info.source_hash, source_hash, 32) == 0);

    mbpf_debug_info_free(&info);
    free(debug);
    return 0;
}

/* Test invalid debug section (too short) */
TEST(parse_invalid_too_short) {
    uint8_t short_data[10] = {0};
    mbpf_debug_info_t info;
    int err = mbpf_debug_info_parse(short_data, sizeof(short_data), &info);
    ASSERT_EQ(err, MBPF_ERR_INVALID_PACKAGE);
    return 0;
}

/* Test debug info free with zeroed struct */
TEST(free_zeroed_struct) {
    mbpf_debug_info_t info;
    memset(&info, 0, sizeof(info));
    mbpf_debug_info_free(&info);  /* Should not crash */
    return 0;
}

/* Test program debug info API with runtime */
TEST(program_debug_info_api) {
    /* Initialize runtime */
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG,
        .require_signatures = false,
        .debug_mode = true
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    /* Create debug section */
    uint8_t source_hash[32] = { 0xDE, 0xAD, 0xBE, 0xEF };
    const char *map_names[] = { "counter", "data" };
    size_t debug_len;
    uint8_t *debug = create_debug_section(
        MBPF_DEBUG_FLAG_HAS_SOURCE_HASH,
        source_hash,
        "mbpf_prog",
        "TRACEPOINT",
        map_names,
        2,
        &debug_len
    );
    ASSERT_NOT_NULL(debug);

    /* Compile simple JS to bytecode */
    const char *js_code = "function mbpf_prog(ctx) { return 0; }";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    if (!bytecode) {
        mbpf_runtime_shutdown(rt);
        free(debug);
        return -1;
    }

    /* Create package with debug info */
    uint8_t pkg_buf[16384];
    size_t pkg_len = build_mbpf_package_with_debug(pkg_buf, sizeof(pkg_buf),
                                                    bytecode, bc_len,
                                                    debug, debug_len);
    ASSERT(pkg_len > 0);

    /* Load program */
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg_buf, pkg_len, NULL, &prog);
    if (err != MBPF_OK) {
        printf("mbpf_program_load failed: %d\n", err);
        free(bytecode);
        free(debug);
        mbpf_runtime_shutdown(rt);
        return -1;
    }
    ASSERT_NOT_NULL(prog);

    /* Verify debug info is available through program API */
    ASSERT(mbpf_program_has_debug_info(prog));

    const char *entry = mbpf_program_debug_entry_symbol(prog);
    ASSERT_NOT_NULL(entry);
    ASSERT_STREQ(entry, "mbpf_prog");

    const char *hook = mbpf_program_debug_hook_name(prog);
    ASSERT_NOT_NULL(hook);
    ASSERT_STREQ(hook, "TRACEPOINT");

    uint8_t hash_out[32];
    err = mbpf_program_debug_source_hash(prog, hash_out);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT(memcmp(hash_out, source_hash, 32) == 0);

    ASSERT_EQ(mbpf_program_debug_map_count(prog), 2);
    ASSERT_STREQ(mbpf_program_debug_map_name(prog, 0), "counter");
    ASSERT_STREQ(mbpf_program_debug_map_name(prog, 1), "data");
    ASSERT(mbpf_program_debug_map_name(prog, 2) == NULL);  /* Out of bounds */

    /* Cleanup */
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    free(debug);
    return 0;
}

/* Test program without debug info */
TEST(program_no_debug_info) {
    /* Initialize runtime */
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG,
        .require_signatures = false,
        .debug_mode = true
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    /* Compile simple JS to bytecode */
    const char *js_code = "function mbpf_prog(ctx) { return 0; }";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    if (!bytecode) {
        mbpf_runtime_shutdown(rt);
        return -1;
    }

    /* Create package without debug info */
    uint8_t pkg_buf[16384];
    size_t pkg_len = build_mbpf_package_no_debug(pkg_buf, sizeof(pkg_buf),
                                                  bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Load program */
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg_buf, pkg_len, NULL, &prog);
    if (err != MBPF_OK) {
        printf("mbpf_program_load failed: %d\n", err);
        free(bytecode);
        mbpf_runtime_shutdown(rt);
        return -1;
    }
    ASSERT_NOT_NULL(prog);

    /* Verify no debug info */
    ASSERT(!mbpf_program_has_debug_info(prog));
    ASSERT(mbpf_program_debug_entry_symbol(prog) == NULL);
    ASSERT(mbpf_program_debug_hook_name(prog) == NULL);

    uint8_t hash_out[32];
    err = mbpf_program_debug_source_hash(prog, hash_out);
    ASSERT_EQ(err, MBPF_ERR_MISSING_SECTION);

    ASSERT_EQ(mbpf_program_debug_map_count(prog), 0);
    ASSERT(mbpf_program_debug_map_name(prog, 0) == NULL);

    /* Cleanup */
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test NULL handling in debug API */
TEST(null_handling) {
    ASSERT(!mbpf_program_has_debug_info(NULL));
    ASSERT(mbpf_program_debug_entry_symbol(NULL) == NULL);
    ASSERT(mbpf_program_debug_hook_name(NULL) == NULL);

    int err = mbpf_program_debug_source_hash(NULL, NULL);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    ASSERT_EQ(mbpf_program_debug_map_count(NULL), 0);
    ASSERT(mbpf_program_debug_map_name(NULL, 0) == NULL);

    mbpf_debug_info_free(NULL);  /* Should not crash */

    int has_debug = 1;
    err = mbpf_package_has_debug(NULL, 0, &has_debug);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    mbpf_debug_info_t info;
    err = mbpf_debug_info_parse(NULL, 0, &info);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

int main(void) {
    int passed = 0, failed = 0;

    printf("microBPF Debug Symbols Tests\n");
    printf("============================\n\n");

    printf("Debug section parsing:\n");
    RUN_TEST(parse_minimal_debug_section);
    RUN_TEST(parse_full_debug_section);
    RUN_TEST(parse_invalid_too_short);
    RUN_TEST(free_zeroed_struct);

    printf("\nPackage debug section:\n");
    RUN_TEST(package_has_debug);
    RUN_TEST(package_no_debug);
    RUN_TEST(package_get_debug_info);
    RUN_TEST(source_hash_provenance);

    printf("\nProgram debug info API:\n");
    RUN_TEST(program_debug_info_api);
    RUN_TEST(program_no_debug_info);
    RUN_TEST(null_handling);

    printf("\n============================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
