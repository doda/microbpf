/*
 * microBPF Array Map Tests
 *
 * Tests for array map type with lookup and update operations:
 * 1. Define array map in program manifest with max_entries=10, value_size=4
 * 2. Load program and verify map is created
 * 3. Call maps.myarray.lookup(0, outBuffer) - verify returns false initially
 * 4. Call maps.myarray.update(0, valueBuffer) - verify success
 * 5. Call maps.myarray.lookup(0, outBuffer) - verify returns true with correct data
 * 6. Verify index bounds checking (reject negative, >= max_entries)
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

/* Helper to build a manifest with array map definition */
static size_t build_manifest_with_map(uint8_t *buf, size_t cap, int hook_type,
                                       const char *map_name, uint32_t max_entries,
                                       uint32_t value_size) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"map_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":1,\"key_size\":4,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type,
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and map */
static size_t build_mbpf_package_with_map(uint8_t *buf, size_t cap,
                                           const uint8_t *bytecode, size_t bc_len,
                                           int hook_type,
                                           const char *map_name, uint32_t max_entries,
                                           uint32_t value_size) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_map(manifest, sizeof(manifest),
                                                   hook_type, map_name,
                                                   max_entries, value_size);
    if (manifest_len == 0) return 0;

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
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Manifest section data */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    /* Bytecode section data */
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_map.js";
    const char *bc_file = "/tmp/test_map.qjbc";

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
 * Test Cases - map-array-basic
 * ============================================================================ */

/*
 * Test 1: Map is created and accessible
 *
 * Verification: Program can access maps object and named map
 */
TEST(map_created) {
    /* Program checks if maps.myarray exists */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof maps === 'undefined') return -1;\n"
        "    if (typeof maps.myarray === 'undefined') return -2;\n"
        "    if (typeof maps.myarray.lookup !== 'function') return -3;\n"
        "    if (typeof maps.myarray.update !== 'function') return -4;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* All checks passed */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Lookup returns false initially
 *
 * Verification: lookup on unwritten slot returns false
 */
TEST(lookup_returns_false_initially) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var outBuf = new Uint8Array(4);\n"
        "    var found = maps.myarray.lookup(0, outBuf);\n"
        "    return found ? 1 : 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* lookup returned false */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Update succeeds
 *
 * Verification: update returns true
 */
TEST(update_succeeds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var valueBuf = new Uint8Array([0x12, 0x34, 0x56, 0x78]);\n"
        "    var success = maps.myarray.update(0, valueBuf);\n"
        "    return success ? 1 : 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);  /* update returned true */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Lookup returns true after update with correct data
 *
 * Verification: lookup returns true and data matches what was written
 */
TEST(lookup_returns_correct_data) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var valueBuf = new Uint8Array([0x12, 0x34, 0x56, 0x78]);\n"
        "    maps.myarray.update(0, valueBuf);\n"
        "    \n"
        "    var outBuf = new Uint8Array(4);\n"
        "    var found = maps.myarray.lookup(0, outBuf);\n"
        "    if (!found) return -1;\n"
        "    \n"
        "    /* Verify data matches */\n"
        "    if (outBuf[0] !== 0x12) return -2;\n"
        "    if (outBuf[1] !== 0x34) return -3;\n"
        "    if (outBuf[2] !== 0x56) return -4;\n"
        "    if (outBuf[3] !== 0x78) return -5;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* All checks passed */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Bounds checking - reject negative index
 *
 * Verification: lookup/update with negative index throws RangeError
 */
TEST(bounds_check_negative) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    try {\n"
        "        maps.myarray.lookup(-1, buf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -2;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* RangeError was caught */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Bounds checking - reject index >= max_entries
 *
 * Verification: lookup/update with index >= max_entries throws RangeError
 */
TEST(bounds_check_over_max) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    /* max_entries is 10, so index 10 is out of bounds */\n"
        "    try {\n"
        "        maps.myarray.lookup(10, buf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -2;\n"
        "    }\n"
        "    try {\n"
        "        maps.myarray.update(10, buf);\n"
        "        return -3;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -4;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* RangeErrors were caught */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Valid index at max_entries-1 works
 *
 * Verification: index 9 (when max is 10) is valid
 */
TEST(bounds_check_at_max_minus_one) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var valueBuf = new Uint8Array([0xAB, 0xCD, 0xEF, 0x01]);\n"
        "    maps.myarray.update(9, valueBuf);  /* Index 9 is last valid */\n"
        "    \n"
        "    var outBuf = new Uint8Array(4);\n"
        "    var found = maps.myarray.lookup(9, outBuf);\n"
        "    if (!found) return -1;\n"
        "    if (outBuf[0] !== 0xAB) return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Multiple entries work independently
 *
 * Verification: Different indices store different values
 */
TEST(multiple_entries) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Write different values to different indices */\n"
        "    maps.myarray.update(0, new Uint8Array([0x11, 0x11, 0x11, 0x11]));\n"
        "    maps.myarray.update(5, new Uint8Array([0x55, 0x55, 0x55, 0x55]));\n"
        "    maps.myarray.update(9, new Uint8Array([0x99, 0x99, 0x99, 0x99]));\n"
        "    \n"
        "    /* Verify each independently */\n"
        "    var buf = new Uint8Array(4);\n"
        "    \n"
        "    maps.myarray.lookup(0, buf);\n"
        "    if (buf[0] !== 0x11) return -1;\n"
        "    \n"
        "    maps.myarray.lookup(5, buf);\n"
        "    if (buf[0] !== 0x55) return -2;\n"
        "    \n"
        "    maps.myarray.lookup(9, buf);\n"
        "    if (buf[0] !== 0x99) return -3;\n"
        "    \n"
        "    /* Index 3 was never written, should return false */\n"
        "    if (maps.myarray.lookup(3, buf)) return -4;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Type checking - non-number index
 *
 * Verification: non-number index throws TypeError
 */
TEST(type_check_index) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    try {\n"
        "        maps.myarray.lookup('hello', buf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof TypeError)) return -2;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Type checking - non-Uint8Array buffer
 *
 * Verification: non-Uint8Array buffer throws TypeError
 */
TEST(type_check_buffer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        maps.myarray.lookup(0, 'not a buffer');\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof TypeError)) return -2;\n"
        "    }\n"
        "    try {\n"
        "        maps.myarray.update(0, [1, 2, 3, 4]);  /* Array, not Uint8Array */\n"
        "        return -3;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof TypeError)) return -4;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Buffer size validation
 *
 * Verification: buffer too small throws RangeError
 */
TEST(buffer_size_check) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var smallBuf = new Uint8Array(2);  /* value_size is 4 */\n"
        "    try {\n"
        "        maps.myarray.lookup(0, smallBuf);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -2;\n"
        "    }\n"
        "    try {\n"
        "        maps.myarray.update(0, smallBuf);\n"
        "        return -3;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (!(e instanceof RangeError)) return -4;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Data persists across invocations
 *
 * Verification: Data written in one run is readable in the next
 */
TEST(data_persists_across_runs) {
    /* First program writes data */
    const char *write_code =
        "var invocation = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    invocation++;\n"
        "    if (invocation === 1) {\n"
        "        maps.myarray.update(0, new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]));\n"
        "        return 1;  /* First run: wrote data */\n"
        "    } else {\n"
        "        var buf = new Uint8Array(4);\n"
        "        if (!maps.myarray.lookup(0, buf)) return -1;\n"
        "        if (buf[0] !== 0xDE) return -2;\n"
        "        if (buf[1] !== 0xAD) return -3;\n"
        "        if (buf[2] !== 0xBE) return -4;\n"
        "        if (buf[3] !== 0xEF) return -5;\n"
        "        return 2;  /* Second run: data verified */\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(write_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  "myarray", 10, 4);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;

    /* First run: write data */
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);  /* Wrote data */

    /* Second run: verify data */
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);  /* Data verified */

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

    printf("microBPF Array Map Tests\n");
    printf("========================\n");

    printf("\nMap creation tests:\n");
    RUN_TEST(map_created);

    printf("\nLookup tests:\n");
    RUN_TEST(lookup_returns_false_initially);
    RUN_TEST(lookup_returns_correct_data);

    printf("\nUpdate tests:\n");
    RUN_TEST(update_succeeds);

    printf("\nBounds checking tests:\n");
    RUN_TEST(bounds_check_negative);
    RUN_TEST(bounds_check_over_max);
    RUN_TEST(bounds_check_at_max_minus_one);

    printf("\nMultiple entries test:\n");
    RUN_TEST(multiple_entries);

    printf("\nType checking tests:\n");
    RUN_TEST(type_check_index);
    RUN_TEST(type_check_buffer);
    RUN_TEST(buffer_size_check);

    printf("\nPersistence tests:\n");
    RUN_TEST(data_persists_across_runs);

    printf("\n========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
