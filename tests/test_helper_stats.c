/*
 * microBPF Helper Stats Tests
 *
 * Tests for mbpf.stats() helper:
 * 1. Request CAP_STATS capability
 * 2. Call mbpf.stats() - verify returns platform-defined stats object
 * 3. Verify invocation counts, error counts, etc. are accessible
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
        "\"program_name\":\"stats_test\","
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
    const char *js_file = "/tmp/test_stats.js";
    const char *bc_file = "/tmp/test_stats.qjbc";

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
 * Test Cases - helper-stats
 * ============================================================================ */

/*
 * Test 1: stats function exists when CAP_STATS is granted
 */
TEST(function_exists_with_cap_stats) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.stats !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
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
 * Test 2: stats function does NOT exist without CAP_STATS
 */
TEST(function_not_exists_without_cap_stats) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.stats === 'undefined') return 0;\n"
        "    return -1;  /* Should not have stats */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\"");  /* No CAP_STATS */
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
 * Test 3: stats returns an object with expected properties
 */
TEST(stats_returns_object_with_properties) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s = mbpf.stats();\n"
        "    if (typeof s !== 'object') return -1;\n"
        "    if (!Array.isArray(s.invocations)) return -2;\n"
        "    if (!Array.isArray(s.successes)) return -3;\n"
        "    if (!Array.isArray(s.exceptions)) return -4;\n"
        "    if (!Array.isArray(s.oom_errors)) return -5;\n"
        "    if (!Array.isArray(s.budget_exceeded)) return -6;\n"
        "    if (!Array.isArray(s.nested_dropped)) return -7;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
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
 * Test 4: stats values are u64 pairs (arrays of length 2)
 */
TEST(stats_values_are_u64_pairs) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s = mbpf.stats();\n"
        "    if (s.invocations.length !== 2) return -1;\n"
        "    if (s.successes.length !== 2) return -2;\n"
        "    if (s.exceptions.length !== 2) return -3;\n"
        "    if (s.oom_errors.length !== 2) return -4;\n"
        "    if (s.budget_exceeded.length !== 2) return -5;\n"
        "    if (s.nested_dropped.length !== 2) return -6;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
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
 * Test 5: invocation count starts at 0 on first run
 * (stats is read before invocation is incremented, so first run sees 0)
 */
TEST(invocation_count_starts_zero) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s = mbpf.stats();\n"
        "    /* On first run, invocations should be 0 (not yet incremented) */\n"
        "    if (s.invocations[0] !== 0 || s.invocations[1] !== 0) return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
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
 * Test 6: invocation count increments correctly
 */
TEST(invocation_count_increments) {
    const char *js_code =
        "var run_num = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    var s = mbpf.stats();\n"
        "    /* Stats are updated before invocation++ so we see run_num */\n"
        "    if (s.invocations[0] !== run_num) return -1;\n"
        "    run_num++;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
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
 * Test 7: success count tracks successful runs
 */
TEST(success_count_tracks) {
    const char *js_code =
        "var run_num = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    var s = mbpf.stats();\n"
        "    /* Successes should equal run_num (previous successful runs) */\n"
        "    if (s.successes[0] !== run_num) return -1;\n"
        "    run_num++;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
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
 * Test 8: stats returns fresh copies (not references)
 */
TEST(stats_returns_fresh_copies) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s1 = mbpf.stats();\n"
        "    var s2 = mbpf.stats();\n"
        "    /* Modifying s1 should not affect s2 */\n"
        "    s1.invocations[0] = 999;\n"
        "    if (s2.invocations[0] === 999) return -1;  /* Shared reference! */\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
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
 * Test 9: exception count is initially 0
 */
TEST(exception_count_zero_initially) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s = mbpf.stats();\n"
        "    if (s.exceptions[0] !== 0 || s.exceptions[1] !== 0) return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
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
 * Test 10: All stats counters are accessible
 */
TEST(all_counters_accessible) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s = mbpf.stats();\n"
        "    /* All should be numbers (lo parts) */\n"
        "    if (typeof s.invocations[0] !== 'number') return -1;\n"
        "    if (typeof s.invocations[1] !== 'number') return -2;\n"
        "    if (typeof s.successes[0] !== 'number') return -3;\n"
        "    if (typeof s.successes[1] !== 'number') return -4;\n"
        "    if (typeof s.exceptions[0] !== 'number') return -5;\n"
        "    if (typeof s.exceptions[1] !== 'number') return -6;\n"
        "    if (typeof s.oom_errors[0] !== 'number') return -7;\n"
        "    if (typeof s.oom_errors[1] !== 'number') return -8;\n"
        "    if (typeof s.budget_exceeded[0] !== 'number') return -9;\n"
        "    if (typeof s.budget_exceeded[1] !== 'number') return -10;\n"
        "    if (typeof s.nested_dropped[0] !== 'number') return -11;\n"
        "    if (typeof s.nested_dropped[1] !== 'number') return -12;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
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
 * Test 11: Stats match host-side stats API
 */
TEST(stats_match_host_api) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_STATS,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times */
    for (int i = 0; i < 3; i++) {
        int32_t rc = -99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 0);
    }

    /* Check host-side stats */
    mbpf_stats_t host_stats;
    err = mbpf_program_stats(prog, &host_stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(host_stats.invocations, 3);
    ASSERT_EQ(host_stats.successes, 3);
    ASSERT_EQ(host_stats.exceptions, 0);

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

    printf("microBPF Helper Stats Tests\n");
    printf("===========================\n\n");

    printf("Capability gating tests:\n");
    RUN_TEST(function_exists_with_cap_stats);
    RUN_TEST(function_not_exists_without_cap_stats);

    printf("\nBasic functionality tests:\n");
    RUN_TEST(stats_returns_object_with_properties);
    RUN_TEST(stats_values_are_u64_pairs);
    RUN_TEST(all_counters_accessible);

    printf("\nCounter tracking tests:\n");
    RUN_TEST(invocation_count_starts_zero);
    RUN_TEST(invocation_count_increments);
    RUN_TEST(success_count_tracks);
    RUN_TEST(exception_count_zero_initially);

    printf("\nAdvanced tests:\n");
    RUN_TEST(stats_returns_fresh_copies);
    RUN_TEST(stats_match_host_api);

    printf("\n===========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
