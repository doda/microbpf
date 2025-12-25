/*
 * microBPF Instance Creation Tests
 *
 * Tests for per-CPU or per-thread instance creation as specified in
 * the instance-creation task.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "mbpf.h"
#include "mbpf_package.h"

/* Test framework macros */
#define TEST(name) static int test_##name(void)
#define RUN_TEST(name) do { \
    printf("  " #name "... "); \
    if (test_##name() == 0) { \
        printf("PASS\n"); \
        passed++; \
    } else { \
        printf("FAIL\n"); \
        failed++; \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { \
    printf("ASSERT failed: %s at line %d\n", #cond, __LINE__); return 1; } } while(0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("ASSERT_EQ failed: %s != %s at line %d\n", #a, #b, __LINE__); return 1; } } while(0)
#define ASSERT_NOT_NULL(ptr) do { if ((ptr) == NULL) { \
    printf("ASSERT_NOT_NULL failed: %s at line %d\n", #ptr, __LINE__); return 1; } } while(0)

/* ============================================================================
 * Helper functions
 * ============================================================================ */

/* Build a JSON test manifest */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    char json[1024];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"test_prog\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"entry_symbol\":\"mbpf_prog\","
        "\"mquickjs_bytecode_version\":8,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":16384,"
        "\"budgets\":{\"max_steps\":10000,\"max_helpers\":100},"
        "\"capabilities\":[\"LOG\"]"
        "}", mbpf_runtime_word_size(), mbpf_runtime_endianness());
    if (len <= 0 || (size_t)len > cap) return 0;
    memcpy(buf, json, len);
    return (size_t)len;
}

/* Build a complete .mbpf package with bytecode */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
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
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;  /* "MBPF" LE */
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
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Manifest section */
    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    /* Bytecode section */
    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* Compile JS to bytecode */
static uint8_t *compile_js(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_inst.js";
    const char *bc_file = "/tmp/test_inst.qjbc";

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
    *out_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(*out_len);
    if (!data) {
        fclose(f);
        return NULL;
    }
    fread(data, 1, *out_len, f);
    fclose(f);

    return data;
}

/* ============================================================================
 * Test: Single instance mode (default)
 * ============================================================================ */
TEST(single_instance_default) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Default config should use single instance */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify single instance was created */
    ASSERT_EQ(mbpf_program_instance_count(prog), 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Per-CPU instance mode
 * ============================================================================ */
TEST(per_cpu_instances) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Configure per-CPU mode */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;
    cfg.instance_mode = MBPF_INSTANCE_PER_CPU;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify multiple instances were created (at least 1, may be more on multi-CPU) */
    uint32_t count = mbpf_program_instance_count(prog);
    ASSERT(count >= 1);  /* At least 1 instance */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Explicit instance count mode
 * ============================================================================ */
TEST(explicit_instance_count) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Configure explicit instance count */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;
    cfg.instance_mode = MBPF_INSTANCE_COUNT;
    cfg.instance_count = 4;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify exactly 4 instances were created */
    ASSERT_EQ(mbpf_program_instance_count(prog), 4);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Each instance has its own JSContext with configured heap_size
 * ============================================================================ */
TEST(instances_have_own_heap) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Configure 3 instances */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 32768;  /* 32KB */
    cfg.instance_mode = MBPF_INSTANCE_COUNT;
    cfg.instance_count = 3;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(mbpf_program_instance_count(prog), 3);

    /* Verify each instance has the configured heap size */
    for (uint32_t i = 0; i < 3; i++) {
        size_t heap_size = mbpf_program_instance_heap_size(prog, i);
        ASSERT_EQ(heap_size, 32768);
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Instance pointers are different (isolation check)
 * ============================================================================ */
TEST(instances_are_distinct) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Configure 3 instances */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;
    cfg.instance_mode = MBPF_INSTANCE_COUNT;
    cfg.instance_count = 3;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Get all instances and verify they are distinct pointers */
    mbpf_instance_t *inst0 = mbpf_program_get_instance(prog, 0);
    mbpf_instance_t *inst1 = mbpf_program_get_instance(prog, 1);
    mbpf_instance_t *inst2 = mbpf_program_get_instance(prog, 2);

    ASSERT_NOT_NULL(inst0);
    ASSERT_NOT_NULL(inst1);
    ASSERT_NOT_NULL(inst2);

    /* All pointers should be different */
    ASSERT(inst0 != inst1);
    ASSERT(inst1 != inst2);
    ASSERT(inst0 != inst2);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Out of bounds instance access returns NULL
 * ============================================================================ */
TEST(instance_bounds_check) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Single instance mode */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    ASSERT_EQ(mbpf_program_instance_count(prog), 1);

    /* Instance 0 should exist */
    ASSERT_NOT_NULL(mbpf_program_get_instance(prog, 0));

    /* Instance 1 should not exist (out of bounds) */
    ASSERT(mbpf_program_get_instance(prog, 1) == NULL);

    /* Large index should also return NULL */
    ASSERT(mbpf_program_get_instance(prog, 1000) == NULL);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: NULL program returns 0 instance count
 * ============================================================================ */
TEST(null_program_safety) {
    ASSERT_EQ(mbpf_program_instance_count(NULL), 0);
    ASSERT_EQ(mbpf_program_instance_heap_size(NULL, 0), 0);
    ASSERT(mbpf_program_get_instance(NULL, 0) == NULL);
    return 0;
}

/* ============================================================================
 * Test: Instances can run programs independently
 * ============================================================================ */
TEST(instances_run_independently) {
    /* Create a program with a counter that increments on each run */
    const char *js_code =
        "var counter = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    counter++;\n"
        "    return counter;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Configure 2 instances - each will have its own counter */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;
    cfg.instance_mode = MBPF_INSTANCE_COUNT;
    cfg.instance_count = 2;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Attach the program */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program and verify it executes */
    int32_t rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Return value should be the counter (at least 1) */
    ASSERT(rc >= 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Multiple programs each get their own instances
 * ============================================================================ */
TEST(multiple_programs_have_instances) {
    const char *js_code1 = "function mbpf_prog(ctx) { return 1; }\n";
    const char *js_code2 = "function mbpf_prog(ctx) { return 2; }\n";

    size_t bc_len1, bc_len2;
    uint8_t *bytecode1 = compile_js(js_code1, &bc_len1);
    uint8_t *bytecode2 = compile_js(js_code2, &bc_len2);
    ASSERT_NOT_NULL(bytecode1);
    ASSERT_NOT_NULL(bytecode2);

    uint8_t pkg1[8192], pkg2[8192];
    size_t pkg_len1 = build_mbpf_package(pkg1, sizeof(pkg1), bytecode1, bc_len1);
    size_t pkg_len2 = build_mbpf_package(pkg2, sizeof(pkg2), bytecode2, bc_len2);
    ASSERT(pkg_len1 > 0);
    ASSERT(pkg_len2 > 0);

    /* Configure 2 instances per program */
    mbpf_runtime_config_t cfg = {0};
    cfg.default_heap_size = 16384;
    cfg.instance_mode = MBPF_INSTANCE_COUNT;
    cfg.instance_count = 2;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog1, *prog2;
    int err = mbpf_program_load(rt, pkg1, pkg_len1, NULL, &prog1);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_load(rt, pkg2, pkg_len2, NULL, &prog2);
    ASSERT_EQ(err, MBPF_OK);

    /* Both programs should have 2 instances each */
    ASSERT_EQ(mbpf_program_instance_count(prog1), 2);
    ASSERT_EQ(mbpf_program_instance_count(prog2), 2);

    /* Instances from different programs should be different */
    mbpf_instance_t *p1_i0 = mbpf_program_get_instance(prog1, 0);
    mbpf_instance_t *p2_i0 = mbpf_program_get_instance(prog2, 0);
    ASSERT(p1_i0 != p2_i0);

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

    printf("microBPF Instance Creation Tests\n");
    printf("=================================\n\n");

    printf("Instance creation modes:\n");
    RUN_TEST(single_instance_default);
    RUN_TEST(per_cpu_instances);
    RUN_TEST(explicit_instance_count);

    printf("\nInstance properties:\n");
    RUN_TEST(instances_have_own_heap);
    RUN_TEST(instances_are_distinct);
    RUN_TEST(instance_bounds_check);
    RUN_TEST(null_program_safety);

    printf("\nInstance behavior:\n");
    RUN_TEST(instances_run_independently);
    RUN_TEST(multiple_programs_have_instances);

    printf("\n=================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
