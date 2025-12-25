/*
 * microBPF Heap Size Enforcement Tests
 *
 * Tests for the memory-heap-size task:
 * 1. Load program with heap_size=16384 (16KB)
 * 2. Run program that allocates within limit - verify works
 * 3. Run program that tries to allocate beyond limit - verify OOM
 * 4. Verify OOM is counted in stats
 * 5. Verify safe default returned on OOM
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
#define ASSERT_GT(a, b) ASSERT((a) > (b))

/* Helper to compile JavaScript to bytecode */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_heap.js";
    const char *bc_file = "/tmp/test_heap.qjbc";

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

/* Helper to build manifest with specific heap_size */
static size_t build_manifest_with_heap(uint8_t *buf, size_t cap, uint32_t heap_size) {
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"heap_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":%u,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        heap_size);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package_with_heap(uint8_t *buf, size_t cap,
                                            const uint8_t *bytecode, size_t bc_len,
                                            uint32_t heap_size) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_heap(manifest, sizeof(manifest), heap_size);
    if (manifest_len == 0) return 0;

    uint32_t header_size = 20 + 2 * 16;
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

/* ============================================================================
 * Test: Load program with heap_size=16384 (16KB)
 * ============================================================================ */

TEST(load_with_16kb_heap) {
    /* Simple program that returns 0 */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);
    ASSERT_GT(bc_len, 0);

    uint8_t package[4096];
    size_t pkg_len = build_mbpf_package_with_heap(package, sizeof(package),
                                                   bytecode, bc_len, 16384);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Verify heap size was applied */
    size_t heap_size = mbpf_program_instance_heap_size(prog, 0);
    ASSERT_EQ(heap_size, 16384);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Run program that allocates within limit - verify works
 * ============================================================================ */

TEST(allocation_within_limit) {
    /* Program that creates a small array (well within 16KB) */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var arr = [];\n"
        "    for (var i = 0; i < 100; i++) {\n"
        "        arr.push(i);\n"
        "    }\n"
        "    return arr.length;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[4096];
    size_t pkg_len = build_mbpf_package_with_heap(package, sizeof(package),
                                                   bytecode, bc_len, 16384);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, 1);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -1;
    err = mbpf_run(rt, 1, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 100);  /* Should return array length */

    /* Check stats - should have 1 success, 0 OOM */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.oom_errors, 0);

    mbpf_program_detach(rt, prog, 1);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Run program that tries to allocate beyond limit - verify OOM
 * ============================================================================ */

TEST(allocation_exceeds_limit) {
    /* Program that tries to allocate a huge array (way beyond 16KB)
     * Each array element takes several bytes, so 10000+ elements should exceed 16KB */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var arr = [];\n"
        "    for (var i = 0; i < 50000; i++) {\n"
        "        arr.push('string_value_' + i);\n"
        "    }\n"
        "    return arr.length;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[4096];
    size_t pkg_len = build_mbpf_package_with_heap(package, sizeof(package),
                                                   bytecode, bc_len, 16384);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, 1);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program - should fail with OOM */
    int32_t rc = 99;
    err = mbpf_run(rt, 1, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    /* For TRACEPOINT (hook type 1), default is 0 */
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, 1);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Verify OOM is counted in stats
 * ============================================================================ */

TEST(oom_counted_in_stats) {
    /* Program that definitely causes OOM by creating huge strings */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s = 'x';\n"
        "    for (var i = 0; i < 20; i++) {\n"
        "        s = s + s;\n"
        "    }\n"
        "    return s.length;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[4096];
    size_t pkg_len = build_mbpf_package_with_heap(package, sizeof(package),
                                                   bytecode, bc_len, 16384);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, 1);
    ASSERT_EQ(err, MBPF_OK);

    /* Get initial stats */
    mbpf_stats_t stats_before;
    err = mbpf_program_stats(prog, &stats_before);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats_before.oom_errors, 0);

    /* Run the program - should fail with OOM */
    int32_t rc = -1;
    err = mbpf_run(rt, 1, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);

    /* Check stats - should have OOM error counted */
    mbpf_stats_t stats_after;
    err = mbpf_program_stats(prog, &stats_after);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_GT(stats_after.oom_errors, stats_before.oom_errors);

    mbpf_program_detach(rt, prog, 1);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Verify safe default returned on OOM for NET_RX hook
 * ============================================================================ */

/* Helper to build manifest with specific heap_size and hook type */
static size_t build_manifest_with_heap_and_hook(uint8_t *buf, size_t cap,
                                                  uint32_t heap_size, uint32_t hook_type) {
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"heap_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%u,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":%u,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        hook_type, heap_size);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

static size_t build_mbpf_package_with_heap_and_hook(uint8_t *buf, size_t cap,
                                                     const uint8_t *bytecode, size_t bc_len,
                                                     uint32_t heap_size, uint32_t hook_type) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_heap_and_hook(manifest, sizeof(manifest),
                                                             heap_size, hook_type);
    if (manifest_len == 0) return 0;

    uint32_t header_size = 20 + 2 * 16;
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

TEST(oom_returns_safe_default_net_rx) {
    /* Program that causes OOM */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s = 'x';\n"
        "    for (var i = 0; i < 20; i++) {\n"
        "        s = s + s;\n"
        "    }\n"
        "    return 1;\n"  /* Would return DROP if it completed */
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Use NET_RX hook type (3) */
    uint8_t package[4096];
    size_t pkg_len = build_mbpf_package_with_heap_and_hook(package, sizeof(package),
                                                           bytecode, bc_len, 16384, 3);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, 3);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program - should fail with OOM and return PASS (0) for NET_RX */
    int32_t rc = 99;
    err = mbpf_run(rt, 3, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);  /* MBPF_NET_PASS = 0 */

    mbpf_program_detach(rt, prog, 3);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Verify safe default returned on OOM for SECURITY hook
 * ============================================================================ */

TEST(oom_returns_safe_default_security) {
    /* Program that causes OOM */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s = 'x';\n"
        "    for (var i = 0; i < 20; i++) {\n"
        "        s = s + s;\n"
        "    }\n"
        "    return 0;\n"  /* Would return ALLOW if it completed */
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Use SECURITY hook type (5) */
    uint8_t package[4096];
    size_t pkg_len = build_mbpf_package_with_heap_and_hook(package, sizeof(package),
                                                           bytecode, bc_len, 16384, 5);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, 5);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program - should fail with OOM and return DENY (1) for SECURITY */
    int32_t rc = 99;
    err = mbpf_run(rt, 5, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* MBPF_SEC_DENY = 1 */

    mbpf_program_detach(rt, prog, 5);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Multiple OOM errors are counted correctly
 * ============================================================================ */

TEST(multiple_oom_counted) {
    /* Program that causes OOM */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var s = 'x';\n"
        "    for (var i = 0; i < 20; i++) {\n"
        "        s = s + s;\n"
        "    }\n"
        "    return s.length;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[4096];
    size_t pkg_len = build_mbpf_package_with_heap(package, sizeof(package),
                                                   bytecode, bc_len, 16384);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, 1);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times */
    int32_t rc;
    for (int i = 0; i < 3; i++) {
        err = mbpf_run(rt, 1, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Check stats - should have 3 OOM errors */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 3);
    ASSERT_EQ(stats.oom_errors, 3);
    ASSERT_EQ(stats.successes, 0);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_program_detach(rt, prog, 1);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: OOM does not affect subsequent runs within limit
 * ============================================================================ */

TEST(oom_does_not_affect_subsequent_runs) {
    /* First program causes OOM */
    const char *oom_js =
        "function mbpf_prog(ctx) {\n"
        "    var s = 'x';\n"
        "    for (var i = 0; i < 20; i++) {\n"
        "        s = s + s;\n"
        "    }\n"
        "    return s.length;\n"
        "}\n";

    /* Second program is small and should work */
    const char *small_js =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    size_t oom_bc_len = 0;
    uint8_t *oom_bytecode = compile_js_to_bytecode(oom_js, &oom_bc_len);
    ASSERT_NOT_NULL(oom_bytecode);

    size_t small_bc_len = 0;
    uint8_t *small_bytecode = compile_js_to_bytecode(small_js, &small_bc_len);
    ASSERT_NOT_NULL(small_bytecode);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    /* Load and run OOM program */
    uint8_t oom_package[4096];
    size_t oom_pkg_len = build_mbpf_package_with_heap(oom_package, sizeof(oom_package),
                                                       oom_bytecode, oom_bc_len, 16384);
    ASSERT_GT(oom_pkg_len, 0);

    mbpf_program_t *oom_prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, oom_package, oom_pkg_len, &opts, &oom_prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, oom_prog, 1);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -1;
    err = mbpf_run(rt, 1, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Default for TRACEPOINT is 0 */
    ASSERT_EQ(rc, 0);

    /* Verify OOM was counted */
    mbpf_stats_t stats;
    err = mbpf_program_stats(oom_prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_GT(stats.oom_errors, 0);

    mbpf_program_detach(rt, oom_prog, 1);
    mbpf_program_unload(rt, oom_prog);

    /* Now load and run small program - should work */
    uint8_t small_package[4096];
    size_t small_pkg_len = build_mbpf_package_with_heap(small_package, sizeof(small_package),
                                                         small_bytecode, small_bc_len, 16384);
    ASSERT_GT(small_pkg_len, 0);

    mbpf_program_t *small_prog = NULL;
    err = mbpf_program_load(rt, small_package, small_pkg_len, &opts, &small_prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, small_prog, 1);
    ASSERT_EQ(err, MBPF_OK);

    rc = -1;
    err = mbpf_run(rt, 1, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 42);  /* Should return 42 */

    mbpf_program_detach(rt, small_prog, 1);
    mbpf_program_unload(rt, small_prog);
    mbpf_runtime_shutdown(rt);

    free(oom_bytecode);
    free(small_bytecode);
    return 0;
}

/* ============================================================================
 * Test: throw null is counted as exception, not OOM
 * ============================================================================ */

TEST(throw_null_not_oom) {
    /* Program that throws null explicitly */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw null;\n"
        "}\n";

    size_t bc_len = 0;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t package[4096];
    size_t pkg_len = build_mbpf_package_with_heap(package, sizeof(package),
                                                   bytecode, bc_len, 16384);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, package, pkg_len, &opts, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, 1);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program - should throw null, counted as exception not OOM */
    int32_t rc = 99;
    err = mbpf_run(rt, 1, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);  /* Default for TRACEPOINT */

    /* Check stats - should have exception, NOT OOM */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.oom_errors, 0);  /* NOT OOM */
    ASSERT_EQ(stats.exceptions, 1);  /* Is a regular exception */

    mbpf_program_detach(rt, prog, 1);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0, failed = 0;

    printf("microBPF Heap Size Enforcement Tests\n");
    printf("=====================================\n\n");

    printf("Basic heap size tests:\n");
    RUN_TEST(load_with_16kb_heap);
    RUN_TEST(allocation_within_limit);

    printf("\nOOM detection tests:\n");
    RUN_TEST(allocation_exceeds_limit);
    RUN_TEST(oom_counted_in_stats);

    printf("\nSafe default tests:\n");
    RUN_TEST(oom_returns_safe_default_net_rx);
    RUN_TEST(oom_returns_safe_default_security);

    printf("\nEdge case tests:\n");
    RUN_TEST(multiple_oom_counted);
    RUN_TEST(oom_does_not_affect_subsequent_runs);
    RUN_TEST(throw_null_not_oom);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
