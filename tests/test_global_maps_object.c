/*
 * microBPF Global Maps Object Tests
 *
 * Verifies the maps global object with program's maps:
 * 1. Define two maps in manifest: myarray and myhash
 * 2. Load program
 * 3. Verify maps.myarray object exists with lookup/update methods
 * 4. Verify maps.myhash object exists with lookup/update/delete methods
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
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/*
 * Helper to build a manifest with TWO maps: myarray (array) and myhash (hash)
 */
static size_t build_manifest_with_two_maps(uint8_t *buf, size_t cap, int hook_type) {
    const char *json =
        "{"
        "\"program_name\":\"two_maps_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":["
            "{\"name\":\"myarray\",\"type\":1,\"key_size\":4,\"value_size\":4,\"max_entries\":10,\"flags\":0},"
            "{\"name\":\"myhash\",\"type\":2,\"key_size\":8,\"value_size\":16,\"max_entries\":100,\"flags\":0}"
        "]"
        "}";

    char formatted[2048];
    int len = snprintf(formatted, sizeof(formatted), json, hook_type,
                       mbpf_runtime_word_size(), mbpf_runtime_endianness());
    if ((size_t)len >= cap) return 0;
    memcpy(buf, formatted, len);
    return (size_t)len;
}

/*
 * Build a complete .mbpf package with bytecode and two maps
 */
static size_t build_mbpf_package_with_two_maps(uint8_t *buf, size_t cap,
                                                const uint8_t *bytecode, size_t bc_len,
                                                int hook_type) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_two_maps(manifest, sizeof(manifest), hook_type);
    if (manifest_len == 0) return 0;

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

    memcpy(p, manifest, manifest_len);
    p += manifest_len;
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_global_maps.js";
    const char *bc_file = "/tmp/test_global_maps.qjbc";

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
 * Test Cases
 * ============================================================================ */

/*
 * Test 1: Both maps exist and are accessible as properties
 *
 * Verification: maps global object has both myarray and myhash
 */
TEST(both_maps_exist) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof maps === 'undefined') return -1;\n"
        "    if (typeof maps.myarray === 'undefined') return -2;\n"
        "    if (typeof maps.myhash === 'undefined') return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_two_maps(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT);
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
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: myarray has lookup and update methods
 *
 * Verification: maps.myarray.lookup and maps.myarray.update are functions
 */
TEST(myarray_has_lookup_update) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof maps.myarray.lookup !== 'function') return -1;\n"
        "    if (typeof maps.myarray.update !== 'function') return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_two_maps(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT);
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
 * Test 3: myhash has lookup, update, and delete methods
 *
 * Verification: maps.myhash.lookup, .update, and .delete are functions
 */
TEST(myhash_has_lookup_update_delete) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof maps.myhash.lookup !== 'function') return -1;\n"
        "    if (typeof maps.myhash.update !== 'function') return -2;\n"
        "    if (typeof maps.myhash.delete !== 'function') return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_two_maps(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT);
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
 * Test 4: myarray lookup/update operations work
 *
 * Verification: can update and lookup array map entries
 */
TEST(myarray_operations_work) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var value = new Uint8Array([0x11, 0x22, 0x33, 0x44]);\n"
        "    var out = new Uint8Array(4);\n"
        "    \n"
        "    /* Initially lookup returns false */\n"
        "    if (maps.myarray.lookup(0, out)) return -1;\n"
        "    \n"
        "    /* Update should succeed */\n"
        "    if (!maps.myarray.update(0, value)) return -2;\n"
        "    \n"
        "    /* Lookup should now succeed */\n"
        "    if (!maps.myarray.lookup(0, out)) return -3;\n"
        "    \n"
        "    /* Verify data */\n"
        "    if (out[0] !== 0x11) return -4;\n"
        "    if (out[1] !== 0x22) return -5;\n"
        "    if (out[2] !== 0x33) return -6;\n"
        "    if (out[3] !== 0x44) return -7;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_two_maps(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT);
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
 * Test 5: myhash lookup/update/delete operations work
 *
 * Verification: can update, lookup, and delete hash map entries
 */
TEST(myhash_operations_work) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "    var value = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,\n"
        "                                0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00]);\n"
        "    var out = new Uint8Array(16);\n"
        "    \n"
        "    /* Initially lookup returns false */\n"
        "    if (maps.myhash.lookup(key, out)) return -1;\n"
        "    \n"
        "    /* Update should succeed */\n"
        "    if (!maps.myhash.update(key, value)) return -2;\n"
        "    \n"
        "    /* Lookup should now succeed */\n"
        "    if (!maps.myhash.lookup(key, out)) return -3;\n"
        "    \n"
        "    /* Verify data */\n"
        "    if (out[0] !== 0xAA) return -4;\n"
        "    if (out[15] !== 0x00) return -5;\n"
        "    \n"
        "    /* Delete should succeed */\n"
        "    if (!maps.myhash.delete(key)) return -6;\n"
        "    \n"
        "    /* Lookup should fail after delete */\n"
        "    if (maps.myhash.lookup(key, out)) return -7;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_two_maps(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT);
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
 * Test 6: Both maps work independently and simultaneously
 *
 * Verification: can use both maps in the same program
 */
TEST(both_maps_work_together) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Use array map */\n"
        "    var arrVal = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    var arrOut = new Uint8Array(4);\n"
        "    if (!maps.myarray.update(5, arrVal)) return -1;\n"
        "    if (!maps.myarray.lookup(5, arrOut)) return -2;\n"
        "    if (arrOut[0] !== 0xAA) return -3;\n"
        "    \n"
        "    /* Use hash map */\n"
        "    var hashKey = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);\n"
        "    var hashVal = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,\n"
        "                                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);\n"
        "    var hashOut = new Uint8Array(16);\n"
        "    if (!maps.myhash.update(hashKey, hashVal)) return -4;\n"
        "    if (!maps.myhash.lookup(hashKey, hashOut)) return -5;\n"
        "    if (hashOut[0] !== 0x01) return -6;\n"
        "    \n"
        "    /* Verify array data is still there */\n"
        "    if (!maps.myarray.lookup(5, arrOut)) return -7;\n"
        "    if (arrOut[0] !== 0xAA) return -8;\n"
        "    \n"
        "    /* Verify hash data is still there */\n"
        "    if (!maps.myhash.lookup(hashKey, hashOut)) return -9;\n"
        "    if (hashOut[0] !== 0x01) return -10;\n"
        "    \n"
        "    /* Delete from hash should work */\n"
        "    if (!maps.myhash.delete(hashKey)) return -11;\n"
        "    if (maps.myhash.lookup(hashKey, hashOut)) return -12;\n"
        "    \n"
        "    /* Array should be unaffected */\n"
        "    if (!maps.myarray.lookup(5, arrOut)) return -13;\n"
        "    if (arrOut[0] !== 0xAA) return -14;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_two_maps(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT);
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
 * Test 7: Data persists across invocations for both maps
 *
 * Verification: data written persists between mbpf_run calls
 */
TEST(data_persists_in_both_maps) {
    const char *js_code =
        "var invocation = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    invocation++;\n"
        "    \n"
        "    if (invocation === 1) {\n"
        "        /* First run: write to both maps */\n"
        "        maps.myarray.update(0, new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]));\n"
        "        var hashKey = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "        maps.myhash.update(hashKey, new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0,\n"
        "                                                     0, 0, 0, 0, 0, 0, 0, 0]));\n"
        "        return 1;\n"
        "    } else {\n"
        "        /* Second run: verify data */\n"
        "        var arrOut = new Uint8Array(4);\n"
        "        if (!maps.myarray.lookup(0, arrOut)) return -1;\n"
        "        if (arrOut[0] !== 0xDE) return -2;\n"
        "        if (arrOut[1] !== 0xAD) return -3;\n"
        "        \n"
        "        var hashKey = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);\n"
        "        var hashOut = new Uint8Array(16);\n"
        "        if (!maps.myhash.lookup(hashKey, hashOut)) return -4;\n"
        "        if (hashOut[0] !== 0xCA) return -5;\n"
        "        if (hashOut[1] !== 0xFE) return -6;\n"
        "        \n"
        "        return 2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_two_maps(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT);
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
    ASSERT_EQ(out_rc, 1);

    /* Second run: verify data */
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);

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

    printf("microBPF Global Maps Object Tests\n");
    printf("==================================\n");

    printf("\nMaps existence tests:\n");
    RUN_TEST(both_maps_exist);

    printf("\nMaps method tests:\n");
    RUN_TEST(myarray_has_lookup_update);
    RUN_TEST(myhash_has_lookup_update_delete);

    printf("\nMaps operation tests:\n");
    RUN_TEST(myarray_operations_work);
    RUN_TEST(myhash_operations_work);

    printf("\nMaps integration tests:\n");
    RUN_TEST(both_maps_work_together);
    RUN_TEST(data_persists_in_both_maps);

    printf("\n==================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
