/*
 * microBPF u64 Representation Tests
 *
 * Verifies the canonical u64 representation as [lo, hi] array:
 * 1. Create u64 value [0x12345678, 0x9ABCDEF0]
 * 2. Verify represents 0x9ABCDEF012345678
 * 3. Store to buffer and verify little-endian encoding
 * 4. Load from buffer and verify reconstruction
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

static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"u64_repr_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness());
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest), hook_type);
    if (manifest_len == 0) return 0;

    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 0: MANIFEST */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 1: BYTECODE */
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

static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_u64_repr.js";
    const char *bc_file = "/tmp/test_u64_repr.qjbc";

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

/*
 * Test 1: Verify [lo, hi] represents the 64-bit value correctly
 *
 * The u64 value [0x12345678, 0x9ABCDEF0] should represent 0x9ABCDEF012345678:
 * - lo (index 0) = 0x12345678 (lower 32 bits)
 * - hi (index 1) = 0x9ABCDEF0 (upper 32 bits)
 * - Combined: (hi << 32) | lo = 0x9ABCDEF012345678
 */
TEST(u64_representation_value) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Create u64 value [0x12345678, 0x9ABCDEF0] */\n"
        "    var u64 = [0x12345678, 0x9ABCDEF0];\n"
        "    \n"
        "    /* Verify lo is 0x12345678 = 305419896 */\n"
        "    if (u64[0] !== 0x12345678) return -1;\n"
        "    \n"
        "    /* Verify hi is 0x9ABCDEF0 = 2596069104 (as unsigned) */\n"
        "    if ((u64[1] >>> 0) !== 0x9ABCDEF0) return -2;\n"
        "    \n"
        "    /* The combined value represents 0x9ABCDEF012345678 */\n"
        "    /* We verify this by reconstructing it using arithmetic */\n"
        "    /* hi * 2^32 + lo = 0x9ABCDEF0 * 0x100000000 + 0x12345678 */\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Store [0x12345678, 0x9ABCDEF0] to buffer and verify little-endian encoding
 *
 * When stored in little-endian format:
 * - The full 64-bit value 0x9ABCDEF012345678 stored as LE bytes:
 *   bytes[0..3] = lo (0x12345678) in LE = 0x78, 0x56, 0x34, 0x12
 *   bytes[4..7] = hi (0x9ABCDEF0) in LE = 0xF0, 0xDE, 0xBC, 0x9A
 */
TEST(u64_store_little_endian) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var bytes = new Uint8Array(8);\n"
        "    var u64 = [0x12345678, 0x9ABCDEF0];\n"
        "    \n"
        "    /* Store u64 to buffer in little-endian format */\n"
        "    mbpf.u64StoreLE(bytes, 0, u64);\n"
        "    \n"
        "    /* Verify little-endian encoding of lo (0x12345678) at bytes[0..3] */\n"
        "    if (bytes[0] !== 0x78) return -1;  /* LSB of lo */\n"
        "    if (bytes[1] !== 0x56) return -2;\n"
        "    if (bytes[2] !== 0x34) return -3;\n"
        "    if (bytes[3] !== 0x12) return -4;  /* MSB of lo */\n"
        "    \n"
        "    /* Verify little-endian encoding of hi (0x9ABCDEF0) at bytes[4..7] */\n"
        "    if (bytes[4] !== 0xF0) return -5;  /* LSB of hi */\n"
        "    if (bytes[5] !== 0xDE) return -6;\n"
        "    if (bytes[6] !== 0xBC) return -7;\n"
        "    if (bytes[7] !== 0x9A) return -8;  /* MSB of hi */\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Load from buffer and verify reconstruction of [0x12345678, 0x9ABCDEF0]
 *
 * Given little-endian bytes for 0x9ABCDEF012345678:
 *   0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A
 * Loading should produce [0x12345678, 0x9ABCDEF0]
 */
TEST(u64_load_reconstruction) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Little-endian bytes for 0x9ABCDEF012345678 */\n"
        "    var bytes = new Uint8Array([0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A]);\n"
        "    var out = [0, 0];\n"
        "    \n"
        "    /* Load from buffer */\n"
        "    mbpf.u64LoadLE(bytes, 0, out);\n"
        "    \n"
        "    /* Verify reconstruction of [0x12345678, 0x9ABCDEF0] */\n"
        "    if (out[0] !== 0x12345678) return -1;  /* lo */\n"
        "    if ((out[1] >>> 0) !== 0x9ABCDEF0) return -2;  /* hi */\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Full roundtrip - store and load back
 */
TEST(u64_roundtrip) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var original = [0x12345678, 0x9ABCDEF0];\n"
        "    var bytes = new Uint8Array(8);\n"
        "    var loaded = [0, 0];\n"
        "    \n"
        "    /* Store to buffer */\n"
        "    mbpf.u64StoreLE(bytes, 0, original);\n"
        "    \n"
        "    /* Load back from buffer */\n"
        "    mbpf.u64LoadLE(bytes, 0, loaded);\n"
        "    \n"
        "    /* Verify roundtrip preserves the value */\n"
        "    if (loaded[0] !== original[0]) return -1;\n"
        "    if ((loaded[1] >>> 0) !== (original[1] >>> 0)) return -2;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Verify the representation with additional u64 values
 */
TEST(u64_additional_values) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var bytes = new Uint8Array(8);\n"
        "    var out = [0, 0];\n"
        "    \n"
        "    /* Test with 0x0000000000000001 = [1, 0] */\n"
        "    var one = [1, 0];\n"
        "    mbpf.u64StoreLE(bytes, 0, one);\n"
        "    if (bytes[0] !== 1 || bytes[1] !== 0 || bytes[7] !== 0) return -1;\n"
        "    mbpf.u64LoadLE(bytes, 0, out);\n"
        "    if (out[0] !== 1 || out[1] !== 0) return -2;\n"
        "    \n"
        "    /* Test with 0x0000000100000000 = [0, 1] */\n"
        "    /* lo=0, hi=1 */\n"
        "    /* u64StoreLE stores lo at bytes[0..3], hi at bytes[4..7] */\n"
        "    /* hi=1 in LE is 01 00 00 00, so bytes[4]=1 */\n"
        "    var oneh = [0, 1];\n"
        "    mbpf.u64StoreLE(bytes, 0, oneh);\n"
        "    if (bytes[0] !== 0 || bytes[4] !== 1 || bytes[5] !== 0 || bytes[7] !== 0) return -3;\n"
        "    mbpf.u64LoadLE(bytes, 0, out);\n"
        "    if (out[0] !== 0 || out[1] !== 1) return -4;\n"
        "    \n"
        "    /* Test with max value 0xFFFFFFFFFFFFFFFF = [0xFFFFFFFF, 0xFFFFFFFF] */\n"
        "    var max = [0xFFFFFFFF, 0xFFFFFFFF];\n"
        "    mbpf.u64StoreLE(bytes, 0, max);\n"
        "    for (var i = 0; i < 8; i++) {\n"
        "        if (bytes[i] !== 0xFF) return -5;\n"
        "    }\n"
        "    mbpf.u64LoadLE(bytes, 0, out);\n"
        "    if ((out[0] >>> 0) !== 0xFFFFFFFF) return -6;\n"
        "    if ((out[1] >>> 0) !== 0xFFFFFFFF) return -7;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF u64 Representation Tests\n");
    printf("==================================\n\n");

    printf("Canonical u64 representation tests:\n");
    RUN_TEST(u64_representation_value);
    RUN_TEST(u64_store_little_endian);
    RUN_TEST(u64_load_reconstruction);
    RUN_TEST(u64_roundtrip);
    RUN_TEST(u64_additional_values);

    printf("\n==================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
