/*
 * microBPF Bytecode Section Tests
 *
 * Tests for bytecode section handling including:
 * - Loading valid MQuickJS bytecode
 * - Copying bytecode to writable buffer
 * - Calling JS_RelocateBytecode
 * - Calling JS_LoadBytecode to obtain main_func
 * - Rejecting invalid bytecode (JS_IsBytecode check)
 * - Rejecting mismatched bytecode version
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include "mquickjs.h"
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

/* ============================================================================
 * Test bytecode (compiled from a simple program)
 * ============================================================================
 * This is pre-compiled bytecode for a simple program.
 * We compile it at test runtime using the mqjs compiler.
 */

/* Helper to build a minimal valid CBOR manifest for bytecode tests */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    /* Minimal CBOR manifest with all required fields */
    const char *json =
        "{"
        "\"program_name\":\"test\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[]"
        "}";
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode */
static size_t build_mbpf_with_bytecode(uint8_t *buf, size_t cap,
                                        const uint8_t *bytecode, size_t bc_len) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
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
    /* magic */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;  /* "MBPF" LE */
    /* format_version = 1 */
    *p++ = 0x01; *p++ = 0x00;
    /* header_size */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    /* flags = 0 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* section_count = 2 */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* file_crc32 = 0 */
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

    /* Manifest section */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    /* Bytecode section */
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* Compile a JS program and return bytecode */
static uint8_t *compile_js(const char *js_code, size_t *out_len) {
    /* Write JS to temp file */
    const char *js_file = "/tmp/test_prog.js";
    const char *bc_file = "/tmp/test_prog.qjbc";

    FILE *f = fopen(js_file, "w");
    if (!f) return NULL;
    fputs(js_code, f);
    fclose(f);

    /* Compile using mqjs */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "./deps/mquickjs/mqjs --no-column -o %s %s 2>/dev/null",
             bc_file, js_file);
    int ret = system(cmd);
    if (ret != 0) return NULL;

    /* Read bytecode */
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
 * Test Cases
 * ============================================================================ */

/* Test: Create .mbpf with valid MQuickJS bytecode section */
TEST(valid_bytecode_package) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);
    ASSERT(bc_len > 0);

    /* Build .mbpf package */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_bytecode(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Verify we can parse the header and section table */
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(pkg, pkg_len, &header);
    ASSERT_EQ(err, MBPF_OK);

    /* Get bytecode section */
    const void *bc_data;
    size_t bc_data_len;
    err = mbpf_package_get_section(pkg, pkg_len, MBPF_SEC_BYTECODE,
                                   &bc_data, &bc_data_len);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(bc_data_len, bc_len);

    free(bytecode);
    return 0;
}

/* Test: Verify loader copies bytecode into writable buffer */
TEST(bytecode_copied_to_buffer) {
    const char *js_code = "function mbpf_prog(ctx) { return 42; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build .mbpf package */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_bytecode(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Create runtime and load program */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify program was loaded (bytecode was copied and relocated) */
    ASSERT(prog != NULL);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Verify loader calls JS_RelocateBytecode on the copy */
TEST(bytecode_relocated) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var x = 1 + 2;\n"
        "    return x;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build .mbpf package */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_bytecode(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Create runtime and load program */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* If we got here without error, JS_RelocateBytecode succeeded */
    /* (it's called inside mbpf_program_load -> mbpf_bytecode_load) */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Verify loader calls JS_LoadBytecode and obtains main_func */
TEST(bytecode_loaded_main_func) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 123;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build .mbpf package */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_bytecode(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Create runtime and load program */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* mbpf_program_load internally calls mbpf_bytecode_load which:
     * 1. Calls JS_IsBytecode
     * 2. Calls JS_RelocateBytecode
     * 3. Calls JS_LoadBytecode to get main_func
     * If any of these fail, err would not be MBPF_OK
     */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Verify loader rejects bytecode that fails JS_IsBytecode check */
TEST(reject_invalid_bytecode) {
    /* Create invalid bytecode (random data without proper header) */
    uint8_t invalid_bytecode[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };

    /* Build .mbpf package with invalid bytecode */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_bytecode(pkg, sizeof(pkg),
                                               invalid_bytecode,
                                               sizeof(invalid_bytecode));
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_INVALID_BYTECODE);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Verify mbpf_bytecode_check detects invalid bytecode */
TEST(bytecode_check_invalid) {
    uint8_t invalid[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00 };

    mbpf_bytecode_info_t info;
    int err = mbpf_bytecode_check(invalid, sizeof(invalid), &info);
    ASSERT_EQ(err, MBPF_ERR_INVALID_BYTECODE);
    ASSERT_EQ(info.is_valid, 0);

    return 0;
}

/* Test: Verify mbpf_bytecode_check passes valid bytecode */
TEST(bytecode_check_valid) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    mbpf_bytecode_info_t info;
    int err = mbpf_bytecode_check(bytecode, bc_len, &info);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(info.is_valid, 1);
    ASSERT(info.bytecode_version != 0);  /* Version should be extracted */

    free(bytecode);
    return 0;
}

/* Test: Verify loader rejects bytecode with wrong magic */
TEST(reject_wrong_magic) {
    /* Bytecode with wrong magic number (not 0xACFB) */
    uint8_t wrong_magic[] = {
        0xFF, 0xFF,  /* Wrong magic */
        0x01, 0x80,  /* version */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* base_addr */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* unique_strings */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* main_func */
    };

    mbpf_bytecode_info_t info;
    int err = mbpf_bytecode_check(wrong_magic, sizeof(wrong_magic), &info);
    ASSERT_EQ(err, MBPF_ERR_INVALID_BYTECODE);

    return 0;
}

/* Test: Verify mbpf_bytecode_version returns a value */
TEST(bytecode_version_function) {
    uint16_t version = mbpf_bytecode_version();
    /* Version should be non-zero (actual value depends on MQuickJS version) */
    ASSERT(version != 0);

    return 0;
}

/* Test: Verify loader rejects bytecode with wrong version */
TEST(reject_wrong_version) {
    /*
     * Create bytecode with valid magic but wrong version.
     * We use the opposite word-size version:
     * - If runtime is 64-bit (0x8001), we use 32-bit version (0x0001)
     * - If runtime is 32-bit (0x0001), we use 64-bit version (0x8001)
     */
    uint16_t runtime_version = mbpf_bytecode_version();
    uint16_t wrong_version = (runtime_version == 0x8001) ? 0x0001 : 0x8001;

    /* Build bytecode header with correct magic but wrong version */
    uint8_t wrong_ver_bc[32];
    memset(wrong_ver_bc, 0, sizeof(wrong_ver_bc));

    /* Magic = 0xACFB (little-endian) */
    wrong_ver_bc[0] = 0xFB;
    wrong_ver_bc[1] = 0xAC;

    /* Version (little-endian) */
    wrong_ver_bc[2] = wrong_version & 0xFF;
    wrong_ver_bc[3] = (wrong_version >> 8) & 0xFF;

    /* Create a minimal JS context for testing */
    extern const JSSTDLibraryDef *mbpf_get_js_stdlib(void);
    size_t heap_size = 16384;
    void *heap = malloc(heap_size);
    ASSERT(heap != NULL);

    JSContext *ctx = JS_NewContext(heap, heap_size, mbpf_get_js_stdlib());
    ASSERT(ctx != NULL);

    /* Try to load - should fail with MBPF_ERR_UNSUPPORTED_VER */
    mbpf_bytecode_info_t info;
    JSValue main_func;
    int err = mbpf_bytecode_load(ctx, wrong_ver_bc, sizeof(wrong_ver_bc),
                                  &info, &main_func);
    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);
    ASSERT_EQ(info.bytecode_version, wrong_version);

    JS_FreeContext(ctx);
    free(heap);

    return 0;
}

/* Test: Program with complex bytecode loads correctly */
TEST(complex_bytecode_loads) {
    const char *js_code =
        "var counter = 0;\n"
        "\n"
        "function mbpf_prog(ctx) {\n"
        "    counter++;\n"
        "    if (counter > 10) {\n"
        "        return 1;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build .mbpf package */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_bytecode(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Create runtime and load program */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Bytecode too short fails */
TEST(bytecode_too_short) {
    uint8_t too_short[] = { 0xFB, 0xAC };  /* Just magic, no header */

    mbpf_bytecode_info_t info;
    int err = mbpf_bytecode_check(too_short, sizeof(too_short), &info);
    ASSERT_EQ(err, MBPF_ERR_INVALID_BYTECODE);

    return 0;
}

/* Test: NULL bytecode is rejected */
TEST(null_bytecode_rejected) {
    mbpf_bytecode_info_t info;
    int err = mbpf_bytecode_check(NULL, 0, &info);
    ASSERT_EQ(err, MBPF_ERR_INVALID_BYTECODE);

    return 0;
}

/* Test: Program unload properly cleans up JS context */
TEST(program_unload_cleanup) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build .mbpf package */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_bytecode(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Create runtime and load program */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Unload the program */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Runtime should still be valid */
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Multiple programs can be loaded */
TEST(multiple_programs) {
    const char *js_code1 = "function mbpf_prog(ctx) { return 1; }\n";
    const char *js_code2 = "function mbpf_prog(ctx) { return 2; }\n";

    size_t bc_len1, bc_len2;
    uint8_t *bytecode1 = compile_js(js_code1, &bc_len1);
    uint8_t *bytecode2 = compile_js(js_code2, &bc_len2);
    ASSERT(bytecode1 != NULL);
    ASSERT(bytecode2 != NULL);

    uint8_t pkg1[8192], pkg2[8192];
    size_t pkg_len1 = build_mbpf_with_bytecode(pkg1, sizeof(pkg1), bytecode1, bc_len1);
    size_t pkg_len2 = build_mbpf_with_bytecode(pkg2, sizeof(pkg2), bytecode2, bc_len2);
    ASSERT(pkg_len1 > 0);
    ASSERT(pkg_len2 > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog1, *prog2;
    int err = mbpf_program_load(rt, pkg1, pkg_len1, NULL, &prog1);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_load(rt, pkg2, pkg_len2, NULL, &prog2);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT(prog1 != prog2);

    mbpf_runtime_shutdown(rt);
    free(bytecode1);
    free(bytecode2);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Bytecode Section Tests\n");
    printf("================================\n");

    /* Bytecode package creation */
    RUN_TEST(valid_bytecode_package);

    /* Bytecode loading steps */
    RUN_TEST(bytecode_copied_to_buffer);
    RUN_TEST(bytecode_relocated);
    RUN_TEST(bytecode_loaded_main_func);

    /* Bytecode validation */
    RUN_TEST(bytecode_check_valid);
    RUN_TEST(bytecode_check_invalid);
    RUN_TEST(reject_invalid_bytecode);
    RUN_TEST(reject_wrong_magic);
    RUN_TEST(bytecode_too_short);
    RUN_TEST(null_bytecode_rejected);

    /* Utility functions */
    RUN_TEST(bytecode_version_function);
    RUN_TEST(reject_wrong_version);

    /* Complex scenarios */
    RUN_TEST(complex_bytecode_loads);
    RUN_TEST(program_unload_cleanup);
    RUN_TEST(multiple_programs);

    printf("\nResults: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
