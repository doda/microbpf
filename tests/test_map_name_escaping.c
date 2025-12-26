/*
 * microBPF Map Name Escaping Security Tests
 *
 * Tests for map name escaping and validation to prevent JS injection:
 * 1. Reject map names with single quotes (')
 * 2. Reject map names with double quotes (")
 * 3. Reject map names with backslashes (\)
 * 4. Reject map names with control characters (0x00-0x1F, 0x7F)
 * 5. Reject empty map names
 * 6. Accept valid map names with alphanumeric characters
 * 7. Accept valid map names with underscores and hyphens
 * 8. Verify escaped names work correctly in generated JS
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
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Helper to build a JSON manifest with a map name (escaped in JSON context) */
static size_t build_manifest_with_raw_map_name(uint8_t *buf, size_t cap, int hook_type,
                                                const char *map_name_json_escaped) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"map_escape_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":1,\"key_size\":4,\"value_size\":4,\"max_entries\":10,\"flags\":0}]"
        "}",
        hook_type,
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name_json_escaped);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with the given manifest */
static size_t build_mbpf_package_with_manifest(uint8_t *buf, size_t cap,
                                                const uint8_t *manifest, size_t manifest_len,
                                                const uint8_t *bytecode, size_t bc_len) {
    if (cap < 256) return 0;

    /* Calculate offsets */
    uint32_t header_size = 20 + 2 * 16;  /* header + 2 section descriptors */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header (20 bytes) */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;  /* magic "MBPF" LE */
    *p++ = 0x01; *p++ = 0x00;  /* format_version = 1 */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* flags = 0 */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* section_count = 2 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* file_crc32 = 0 */

    /* Section 0: MANIFEST (type=1) */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 = 0 */

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 = 0 */

    /* Copy manifest data */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    /* Copy bytecode */
    memcpy(p, bytecode, bc_len);

    return total_size;
}

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_map_escape.js";
    const char *bc_file = "/tmp/test_map_escape.qjbc";

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

/* ============================================================================
 * Map Name Rejection Tests
 * ============================================================================ */

/*
 * Test 1: Reject map name with single quote
 *
 * A map name like "test'map" could be used for JS injection if not properly
 * escaped. The parser should reject such names.
 */
TEST(reject_single_quote) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build manifest with map name containing single quote (JSON-escaped) */
    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        "test\\'map"  /* JSON escape for single quote */
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Should fail to load due to invalid map name */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Reject map name with double quote
 */
TEST(reject_double_quote) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build manifest with map name containing double quote (JSON-escaped) */
    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        "test\\\"map"  /* JSON escape for double quote */
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Should fail to load due to invalid map name */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Reject map name with backslash
 */
TEST(reject_backslash) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build manifest with map name containing backslash (JSON-escaped) */
    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        "test\\\\map"  /* JSON escape for backslash */
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Should fail to load due to invalid map name */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Reject map name with newline control character
 */
TEST(reject_newline) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build manifest with map name containing newline (JSON-escaped) */
    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        "test\\nmap"  /* JSON escape for newline */
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Should fail to load due to invalid map name */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Reject map name with tab control character
 */
TEST(reject_tab) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build manifest with map name containing tab (JSON-escaped) */
    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        "test\\tmap"  /* JSON escape for tab */
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Should fail to load due to invalid map name */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Reject empty map name
 */
TEST(reject_empty_name) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build manifest with empty map name */
    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        ""  /* Empty map name */
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Should fail to load due to empty map name */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Valid Map Name Tests
 * ============================================================================ */

/*
 * Test 7: Accept valid alphanumeric map name
 */
TEST(accept_alphanumeric) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build manifest with valid alphanumeric map name */
    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        "myMap123"
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Should successfully load */
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Accept valid map name with underscore
 */
TEST(accept_underscore) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build manifest with valid map name containing underscore */
    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        "my_map_name"
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Should successfully load */
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Accept valid map name with hyphen
 */
TEST(accept_hyphen) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build manifest with valid map name containing hyphen */
    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        "my-map-name"
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Should successfully load */
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Map with valid name can be used in JS
 *
 * Verify that a map with a valid name works correctly in generated JS code.
 */
TEST(valid_map_accessible_in_js) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    buf[0] = 42;\n"
        "    if (!maps.mymap.update(0, buf)) return -1;\n"
        "    var out = new Uint8Array(4);\n"
        "    if (!maps.mymap.lookup(0, out)) return -2;\n"
        "    if (out[0] !== 42) return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_raw_map_name(
        manifest, sizeof(manifest),
        MBPF_HOOK_TRACEPOINT,
        "mymap"
    );
    ASSERT(manifest_len > 0);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_manifest(
        pkg, sizeof(pkg), manifest, manifest_len, bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Map Name Escaping Security Tests\n");
    printf("==========================================\n");

    printf("\nRejection tests (invalid map names):\n");
    RUN_TEST(reject_single_quote);
    RUN_TEST(reject_double_quote);
    RUN_TEST(reject_backslash);
    RUN_TEST(reject_newline);
    RUN_TEST(reject_tab);
    RUN_TEST(reject_empty_name);

    printf("\nAcceptance tests (valid map names):\n");
    RUN_TEST(accept_alphanumeric);
    RUN_TEST(accept_underscore);
    RUN_TEST(accept_hyphen);

    printf("\nFunctional tests:\n");
    RUN_TEST(valid_map_accessible_in_js);

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
