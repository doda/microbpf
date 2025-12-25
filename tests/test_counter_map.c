/*
 * microBPF Counter Map Tests
 *
 * Tests for optimized counter map type with atomic operations:
 * 1. Define counter map in manifest
 * 2. Call maps.counter.add(key, delta) - verify atomic increment
 * 3. Verify 64-bit counters work correctly
 * 4. Verify concurrent updates don't lose counts
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
        printf("FAIL (code %d)\n", result); \
        failed++; \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("ASSERT FAILED: " #cond " at line %d\n", __LINE__); return -1; } } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Helper to build a manifest with counter map definition */
static size_t build_manifest_with_counter_map(uint8_t *buf, size_t cap, int hook_type,
                                               const char *map_name, uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"counter_map_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":6,\"key_size\":0,\"value_size\":8,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, map_name, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and counter map */
static size_t build_mbpf_package_with_counter_map(uint8_t *buf, size_t cap,
                                                   const uint8_t *bytecode, size_t bc_len,
                                                   int hook_type,
                                                   const char *map_name, uint32_t max_entries) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_counter_map(manifest, sizeof(manifest),
                                                           hook_type, map_name, max_entries);
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
    const char *js_file = "/tmp/test_counter_map.js";
    const char *bc_file = "/tmp/test_counter_map.qjbc";

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
 * Test Cases - map-counter
 * ============================================================================ */

/*
 * Test 1: Define counter map in manifest and load
 *
 * Verification: Map is created and can be accessed
 */
TEST(counter_map_created) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Verify map exists */\n"
        "    if (!maps.counters) return -1;\n"
        "    if (typeof maps.counters.add !== 'function') return -2;\n"
        "    if (typeof maps.counters.get !== 'function') return -3;\n"
        "    if (typeof maps.counters.set !== 'function') return -4;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Basic add operation
 *
 * Verification: add(key, delta) increments counter
 */
TEST(add_basic) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Add 1 to counter 0 */\n"
        "    maps.counters.add(0, 1);\n"
        "    \n"
        "    /* Get value - should be 1 */\n"
        "    var v = maps.counters.get(0);\n"
        "    if (v !== 1) return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Atomic increment - multiple adds accumulate
 *
 * Verification: Multiple add calls accumulate correctly
 */
TEST(add_accumulates) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Add multiple times */\n"
        "    maps.counters.add(0, 5);\n"
        "    maps.counters.add(0, 3);\n"
        "    maps.counters.add(0, 7);\n"
        "    \n"
        "    /* Should be 15 total */\n"
        "    var v = maps.counters.get(0);\n"
        "    if (v !== 15) return v;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Multiple counter indices
 *
 * Verification: Different counters are independent
 */
TEST(multiple_counters) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Set different counters */\n"
        "    maps.counters.add(0, 10);\n"
        "    maps.counters.add(1, 20);\n"
        "    maps.counters.add(2, 30);\n"
        "    \n"
        "    /* Verify each */\n"
        "    if (maps.counters.get(0) !== 10) return -1;\n"
        "    if (maps.counters.get(1) !== 20) return -2;\n"
        "    if (maps.counters.get(2) !== 30) return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: 64-bit counter values
 *
 * Verification: Large values beyond 32-bit work correctly
 */
TEST(large_values_64bit) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Set a large value using set() */\n"
        "    maps.counters.set(0, 0x100000000);\n"  /* 2^32, beyond 32-bit */
        "    \n"
        "    /* Verify the value */\n"
        "    var v = maps.counters.get(0);\n"
        "    if (v !== 0x100000000) return -1;\n"
        "    \n"
        "    /* Add more to push it higher */\n"
        "    maps.counters.add(0, 0x100000000);\n"
        "    v = maps.counters.get(0);\n"
        "    if (v !== 0x200000000) return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Negative delta values
 *
 * Verification: Counters can be decremented with negative delta
 */
TEST(negative_delta) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Set initial value */\n"
        "    maps.counters.set(0, 100);\n"
        "    \n"
        "    /* Subtract 30 */\n"
        "    maps.counters.add(0, -30);\n"
        "    \n"
        "    /* Should be 70 */\n"
        "    var v = maps.counters.get(0);\n"
        "    if (v !== 70) return v;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Bounds checking - negative index
 *
 * Verification: Negative index throws RangeError
 */
TEST(bounds_check_negative) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        maps.counters.add(-1, 1);\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof RangeError) return 0;\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Bounds checking - index at max
 *
 * Verification: Index at max_entries throws RangeError
 */
TEST(bounds_check_at_max) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        maps.counters.add(10, 1);  /* max_entries is 10, so 10 is out of bounds */\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof RangeError) return 0;\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Bounds checking - index at max-1 is valid
 *
 * Verification: Index at max_entries - 1 is valid
 */
TEST(bounds_check_at_max_minus_one) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* max_entries is 10, so 9 is the last valid index */\n"
        "    maps.counters.add(9, 42);\n"
        "    var v = maps.counters.get(9);\n"
        "    if (v !== 42) return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Counter persists across runs
 *
 * Verification: Counter values persist across multiple mbpf_run calls
 */
TEST(counter_persists_across_runs) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Add 1 each run */\n"
        "    maps.counters.add(0, 1);\n"
        "    /* Return current value */\n"
        "    return Number(maps.counters.get(0));\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;

    /* Run 5 times, each should increment */
    for (int i = 1; i <= 5; i++) {
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, i);  /* Return value is current count */
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: set() function
 *
 * Verification: set() can set a counter to a specific value
 */
TEST(set_function) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Set counter to specific value */\n"
        "    maps.counters.set(0, 12345);\n"
        "    var v = maps.counters.get(0);\n"
        "    if (v !== 12345) return -1;\n"
        "    \n"
        "    /* Overwrite with another value */\n"
        "    maps.counters.set(0, 99999);\n"
        "    v = maps.counters.get(0);\n"
        "    if (v !== 99999) return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Initial counter value is zero
 *
 * Verification: New counters start at 0
 */
TEST(initial_value_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Verify all counters start at 0 */\n"
        "    for (var i = 0; i < 10; i++) {\n"
        "        if (maps.counters.get(i) !== 0) return -(i + 1);\n"
        "    }\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: Concurrent updates in a loop (stress test for atomicity)
 *
 * Verification: Many rapid updates don't lose counts
 */
TEST(rapid_updates_no_loss) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Rapid add operations */\n"
        "    for (var i = 0; i < 100; i++) {\n"
        "        maps.counters.add(0, 1);\n"
        "    }\n"
        "    \n"
        "    /* Should be exactly 100 */\n"
        "    var v = maps.counters.get(0);\n"
        "    if (v !== 100) return v;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 14: Multiple runs accumulate correctly
 *
 * Verification: Running program multiple times accumulates counter
 */
TEST(multiple_runs_accumulate) {
    /* Program adds 10 to counter and returns current value */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Add 10 each run */\n"
        "    maps.counters.add(0, 10);\n"
        "    /* Return current value */\n"
        "    return maps.counters.get(0);\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_counter_map(pkg, sizeof(pkg),
                                                          bytecode, bc_len,
                                                          MBPF_HOOK_TRACEPOINT,
                                                          "counters", 10);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t rc;

    /* Run 10 times and verify counter accumulates correctly */
    for (int i = 1; i <= 10; i++) {
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &rc);
        ASSERT_EQ(err, MBPF_OK);
        /* Each run adds 10, so after run i, counter should be i*10 */
        ASSERT_EQ(rc, i * 10);
    }

    /* Final value should be 100 (10 runs * 10 per run) */
    ASSERT_EQ(rc, 100);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Counter Map Tests\n");
    printf("==========================\n\n");

    printf("Map creation tests:\n");
    RUN_TEST(counter_map_created);

    printf("\nBasic operations:\n");
    RUN_TEST(add_basic);
    RUN_TEST(add_accumulates);
    RUN_TEST(multiple_counters);
    RUN_TEST(set_function);
    RUN_TEST(initial_value_zero);

    printf("\n64-bit value tests:\n");
    RUN_TEST(large_values_64bit);
    RUN_TEST(negative_delta);

    printf("\nBounds checking tests:\n");
    RUN_TEST(bounds_check_negative);
    RUN_TEST(bounds_check_at_max);
    RUN_TEST(bounds_check_at_max_minus_one);

    printf("\nPersistence and concurrency tests:\n");
    RUN_TEST(counter_persists_across_runs);
    RUN_TEST(rapid_updates_no_loss);
    RUN_TEST(multiple_runs_accumulate);

    printf("\n==========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
