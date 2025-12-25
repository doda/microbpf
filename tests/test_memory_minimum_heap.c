/*
 * microBPF Memory Minimum Heap Tests
 *
 * Tests for the memory-minimum-heap task:
 * 1. Attempt to load program with heap_size=1024 (too small)
 * 2. Verify load fails with appropriate error
 * 3. Document platform minimum heap size (8KB = 8192 bytes)
 *
 * Platform Minimum Heap Size: 8192 bytes (8KB)
 *
 * This minimum is required because MQuickJS needs sufficient space for:
 * - Standard library initialization
 * - Basic JS heap operations
 * - Runtime context objects
 * - Program bytecode loading
 *
 * Programs requesting less than 8KB will fail to load with MBPF_ERR_HEAP_TOO_SMALL.
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
    const char *js_file = "/tmp/test_min_heap.js";
    const char *bc_file = "/tmp/test_min_heap.qjbc";

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
        "\"program_name\":\"min_heap_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":%u,"
        "\"budgets\":{\"max_steps\":10000,\"max_helpers\":100},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
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
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;  /* Magic "MBPF" LE */
    *p++ = 0x01; *p++ = 0x00;  /* Format version 1 */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* Flags */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* Section count = 2 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* File CRC (disabled) */

    /* Section 0: MANIFEST */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* Type = MANIFEST */
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* Section CRC (disabled) */

    /* Section 1: BYTECODE */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* Type = BYTECODE */
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* Section CRC (disabled) */

    memcpy(p, manifest, manifest_len);
    p += manifest_len;

    memcpy(p, bytecode, bc_len);
    p += bc_len;

    return (size_t)(p - buf);
}

/* ============================================================================
 * Test: Verify platform minimum heap size constant is correctly defined
 * ============================================================================ */

TEST(platform_minimum_is_8kb) {
    /* Document: Platform minimum heap size is 8192 bytes (8KB) */
    ASSERT_EQ(MBPF_MIN_HEAP_SIZE, 8192);
    return 0;
}

/* ============================================================================
 * Test: Attempt to load program with heap_size=1024 (too small)
 * Verify load fails with MBPF_ERR_HEAP_TOO_SMALL
 * ============================================================================ */

TEST(heap_1024_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_heap(pkg, sizeof(pkg),
                                                   bytecode, bc_len, 1024);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);

    /* Verify load fails with appropriate error */
    ASSERT_EQ(err, MBPF_ERR_HEAP_TOO_SMALL);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Verify heap_size=0 is also rejected
 * ============================================================================ */

TEST(heap_0_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_heap(pkg, sizeof(pkg),
                                                   bytecode, bc_len, 0);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);

    ASSERT_EQ(err, MBPF_ERR_HEAP_TOO_SMALL);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Verify heap_size=4096 (4KB, still below minimum) is rejected
 * ============================================================================ */

TEST(heap_4096_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_heap(pkg, sizeof(pkg),
                                                   bytecode, bc_len, 4096);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);

    ASSERT_EQ(err, MBPF_ERR_HEAP_TOO_SMALL);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Verify heap_size=8191 (1 byte below minimum) is rejected
 * ============================================================================ */

TEST(heap_8191_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_heap(pkg, sizeof(pkg),
                                                   bytecode, bc_len, 8191);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);

    ASSERT_EQ(err, MBPF_ERR_HEAP_TOO_SMALL);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Verify heap_size=8192 (exactly at minimum) succeeds
 * ============================================================================ */

TEST(heap_8192_accepted) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_heap(pkg, sizeof(pkg),
                                                   bytecode, bc_len, 8192);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);

    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Verify heap_size=16384 (above minimum) succeeds
 * ============================================================================ */

TEST(heap_16384_accepted) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package_with_heap(pkg, sizeof(pkg),
                                                   bytecode, bc_len, 16384);
    ASSERT_GT(pkg_len, 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t opts = {0};
    opts.allow_unsigned = 1;

    int err = mbpf_program_load(rt, pkg, pkg_len, &opts, &prog);

    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test: Verify error message/code is appropriate
 * ============================================================================ */

TEST(error_code_is_heap_too_small) {
    /* MBPF_ERR_HEAP_TOO_SMALL should be -18 */
    ASSERT_EQ(MBPF_ERR_HEAP_TOO_SMALL, -18);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0, failed = 0;

    printf("microBPF Memory Minimum Heap Tests\n");
    printf("===================================\n\n");

    printf("Platform documentation tests:\n");
    RUN_TEST(platform_minimum_is_8kb);
    RUN_TEST(error_code_is_heap_too_small);

    printf("\nHeap rejection tests:\n");
    RUN_TEST(heap_1024_rejected);
    RUN_TEST(heap_0_rejected);
    RUN_TEST(heap_4096_rejected);
    RUN_TEST(heap_8191_rejected);

    printf("\nHeap acceptance tests:\n");
    RUN_TEST(heap_8192_accepted);
    RUN_TEST(heap_16384_accepted);

    printf("\n===================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    printf("\n");
    printf("Platform Minimum Heap Size Documentation:\n");
    printf("------------------------------------------\n");
    printf("MBPF_MIN_HEAP_SIZE = %d bytes (8KB)\n", MBPF_MIN_HEAP_SIZE);
    printf("\n");
    printf("This minimum is required because MQuickJS needs sufficient\n");
    printf("space for standard library initialization and basic JS heap\n");
    printf("operations. Programs with heap_size < 8192 will fail to load\n");
    printf("with error code MBPF_ERR_HEAP_TOO_SMALL (%d).\n", MBPF_ERR_HEAP_TOO_SMALL);
    printf("\n");

    return failed > 0 ? 1 : 0;
}
