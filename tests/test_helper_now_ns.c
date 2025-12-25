/*
 * microBPF Helper nowNs Tests
 *
 * Tests for mbpf.nowNs(out) helper:
 * 1. Request CAP_TIME capability
 * 2. Call mbpf.nowNs(out) where out is [0, 0]
 * 3. Verify out contains monotonic time in nanoseconds as u64
 * 4. Call twice and verify second value >= first
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

/* Helper to build a manifest with specified capabilities */
static size_t build_manifest_with_caps(uint8_t *buf, size_t cap, int hook_type,
                                       const char *capabilities) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"nowns_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[%s]"
        "}",
        hook_type, capabilities);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type, const char *capabilities) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_caps(manifest, sizeof(manifest),
                                                    hook_type, capabilities);
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
    const char *js_file = "/tmp/test_nowns.js";
    const char *bc_file = "/tmp/test_nowns.qjbc";

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
 * Test Cases - helper-now-ns
 * ============================================================================ */

/*
 * Test 1: nowNs function exists when CAP_TIME is granted
 */
TEST(function_exists_with_cap_time) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.nowNs !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

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
 * Test 2: nowNs function does NOT exist without CAP_TIME
 */
TEST(function_not_exists_without_cap_time) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.nowNs === 'undefined') return 0;\n"
        "    return -1;  /* Should not have nowNs */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\"");  /* No CAP_TIME */
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

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
 * Test 3: nowNs writes to out array
 */
TEST(nowns_writes_to_out) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var out = [0, 0];\n"
        "    mbpf.nowNs(out);\n"
        "    /* After call, at least lo should be non-zero (unless running at ns 0) */\n"
        "    /* We check that at least one of them is non-zero (time > 0) */\n"
        "    if (out[0] === 0 && out[1] === 0) return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

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
 * Test 4: Second call returns value >= first
 */
TEST(nowns_monotonic) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var t1 = [0, 0];\n"
        "    var t2 = [0, 0];\n"
        "    mbpf.nowNs(t1);\n"
        "    mbpf.nowNs(t2);\n"
        "    /* Compare as u64: t2 >= t1 */\n"
        "    /* First compare hi, if equal compare lo */\n"
        "    if (t2[1] > t1[1]) return 0;  /* t2 > t1 */\n"
        "    if (t2[1] < t1[1]) return -1; /* t2 < t1 - monotonic violation */\n"
        "    /* hi equal, compare lo */\n"
        "    if (t2[0] >= t1[0]) return 0; /* t2 >= t1 */\n"
        "    return -2; /* t2 < t1 - monotonic violation */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

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
 * Test 5: nowNs returns reasonable value (not zero, not too large)
 * The value should represent a monotonic clock in nanoseconds.
 * We expect it to be > 0. The hi part depends on system time so we just check it's reasonable.
 * For ~136 years, hi would be ~1000000, so we allow up to 10000000 for safety margin.
 */
TEST(nowns_reasonable_value) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var out = [0, 0];\n"
        "    mbpf.nowNs(out);\n"
        "    /* Check that value is > 0 */\n"
        "    if (out[0] === 0 && out[1] === 0) return -1;\n"
        "    /* Check that hi part is not ridiculously large */\n"
        "    /* 10000000 * 2^32 ns ~ 1361 years - very safe upper bound */\n"
        "    if (out[1] > 10000000) return -2;  /* Sanity check */\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

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
 * Test 6: TypeError for invalid out argument (not array)
 */
TEST(type_error_not_array) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        mbpf.nowNs('not an array');\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) return 0;\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

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
 * Test 7: TypeError for array too short
 */
TEST(type_error_short_array) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        mbpf.nowNs([0]);  /* Only 1 element */\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) return 0;\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

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
 * Test 8: Multiple calls in sequence show increasing values
 */
TEST(nowns_multiple_calls_increasing) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var t1 = [0, 0];\n"
        "    var t2 = [0, 0];\n"
        "    var t3 = [0, 0];\n"
        "    mbpf.nowNs(t1);\n"
        "    mbpf.nowNs(t2);\n"
        "    mbpf.nowNs(t3);\n"
        "    /* Helper to compare u64 as [lo, hi] pairs */\n"
        "    function cmp64(a, b) {\n"
        "        if (a[1] > b[1]) return 1;\n"
        "        if (a[1] < b[1]) return -1;\n"
        "        if (a[0] > b[0]) return 1;\n"
        "        if (a[0] < b[0]) return -1;\n"
        "        return 0;\n"
        "    }\n"
        "    /* t2 >= t1 and t3 >= t2 */\n"
        "    if (cmp64(t2, t1) < 0) return -1;\n"
        "    if (cmp64(t3, t2) < 0) return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

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
 * Test 9: nowNs across runs shows increasing values
 */
TEST(nowns_across_runs_increasing) {
    const char *js_code =
        "var global_time = [0, 0];\n"
        "function mbpf_prog(ctx) {\n"
        "    var prev = [global_time[0], global_time[1]];\n"
        "    mbpf.nowNs(global_time);\n"
        "    /* On first run, prev is [0,0], should be less */\n"
        "    if (prev[0] === 0 && prev[1] === 0) return 0;\n"
        "    /* On subsequent runs, global_time >= prev */\n"
        "    if (global_time[1] > prev[1]) return 0;\n"
        "    if (global_time[1] < prev[1]) return -1;\n"
        "    if (global_time[0] >= prev[0]) return 0;\n"
        "    return -2;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times and check each returns success */
    for (int i = 0; i < 5; i++) {
        int32_t rc = -99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 0);
    }

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: nowNs with larger array works (writes only first 2 elements)
 */
TEST(nowns_larger_array) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var out = [1, 2, 3, 4];\n"
        "    mbpf.nowNs(out);\n"
        "    /* out[0] and out[1] should be written */\n"
        "    /* out[2] and out[3] should be unchanged */\n"
        "    if (out[2] !== 3) return -1;\n"
        "    if (out[3] !== 4) return -2;\n"
        "    /* out[0] and out[1] should have time values (non-zero) */\n"
        "    if (out[0] === 1 && out[1] === 2) return -3;  /* Unchanged = bad */\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

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

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Helper nowNs Tests\n");
    printf("===========================\n\n");

    printf("Capability gating tests:\n");
    RUN_TEST(function_exists_with_cap_time);
    RUN_TEST(function_not_exists_without_cap_time);

    printf("\nBasic functionality tests:\n");
    RUN_TEST(nowns_writes_to_out);
    RUN_TEST(nowns_monotonic);
    RUN_TEST(nowns_reasonable_value);

    printf("\nType error tests:\n");
    RUN_TEST(type_error_not_array);
    RUN_TEST(type_error_short_array);

    printf("\nAdvanced tests:\n");
    RUN_TEST(nowns_multiple_calls_increasing);
    RUN_TEST(nowns_across_runs_increasing);
    RUN_TEST(nowns_larger_array);

    printf("\n===========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
