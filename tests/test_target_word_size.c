/*
 * microBPF Target Word Size Tests
 *
 * Tests for target word size (32-bit vs 64-bit) handling:
 * - Compile bytecode for 32-bit target
 * - Load on 32-bit runtime - verify works (simulated via manifest)
 * - Compile bytecode for 64-bit target
 * - Load on 64-bit runtime - verify works
 * - Cross-load (32 on 64 or vice versa) - verify rejected
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
 * Helper functions
 * ============================================================================ */

/* Build a JSON manifest with specified word size and endianness */
static size_t build_manifest_with_target(uint8_t *buf, size_t cap, int word_size, int endianness) {
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"test\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%d,\"endianness\":%d},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[]"
        "}", word_size, endianness);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and specified target */
static size_t build_mbpf_with_target(uint8_t *buf, size_t cap,
                                      const uint8_t *bytecode, size_t bc_len,
                                      int word_size, int endianness) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_manifest_with_target(manifest, sizeof(manifest), word_size, endianness);
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
    const char *js_file = "/tmp/test_word_size.js";
    const char *bc_file = "/tmp/test_word_size.qjbc";

    FILE *f = fopen(js_file, "w");
    if (!f) return NULL;
    fputs(js_code, f);
    fclose(f);

    /* Compile using mqjs (native word size) */
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

/* Test: mbpf_runtime_word_size returns 32 or 64 */
TEST(runtime_word_size_valid) {
    uint8_t ws = mbpf_runtime_word_size();
    ASSERT(ws == 32 || ws == 64);
    /* Should match sizeof(void*) */
    ASSERT_EQ(ws, (uint8_t)(sizeof(void*) * 8));
    return 0;
}

/* Test: mbpf_runtime_endianness returns 0 or 1 */
TEST(runtime_endianness_valid) {
    uint8_t end = mbpf_runtime_endianness();
    ASSERT(end == 0 || end == 1);
    return 0;
}

/* Test: Package with matching target loads successfully */
TEST(matching_target_loads) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with runtime's word size and endianness */
    uint8_t pkg[8192];
    uint8_t runtime_ws = mbpf_runtime_word_size();
    uint8_t runtime_end = mbpf_runtime_endianness();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, runtime_ws, runtime_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and load program */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT(prog != NULL);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Package with 64-bit word size on 64-bit runtime loads (if runtime is 64-bit) */
TEST(word_size_64_on_64_runtime) {
    if (mbpf_runtime_word_size() != 64) {
        /* Skip - runtime is not 64-bit */
        printf("(skipped - 32-bit runtime) ");
        return 0;
    }

    const char *js_code = "function mbpf_prog(ctx) { return 42; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with 64-bit word size and correct endianness */
    uint8_t pkg[8192];
    uint8_t runtime_end = mbpf_runtime_endianness();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, 64, runtime_end);
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

/* Test: Package with 32-bit word size rejected on 64-bit runtime */
TEST(word_size_32_on_64_rejected) {
    if (mbpf_runtime_word_size() != 64) {
        /* Skip - runtime is not 64-bit */
        printf("(skipped - 32-bit runtime) ");
        return 0;
    }

    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with 32-bit word size (mismatched) but correct endianness */
    uint8_t pkg[8192];
    uint8_t runtime_end = mbpf_runtime_endianness();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, 32, runtime_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_TARGET_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Package with 64-bit word size rejected on 32-bit runtime */
TEST(word_size_64_on_32_rejected) {
    if (mbpf_runtime_word_size() != 32) {
        /* Skip - runtime is not 32-bit */
        printf("(skipped - 64-bit runtime) ");
        return 0;
    }

    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with 64-bit word size (mismatched) but correct endianness */
    uint8_t pkg[8192];
    uint8_t runtime_end = mbpf_runtime_endianness();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, 64, runtime_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_TARGET_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Cross-load is always rejected (either direction) */
TEST(cross_load_word_size_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 123; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    uint8_t runtime_ws = mbpf_runtime_word_size();
    uint8_t runtime_end = mbpf_runtime_endianness();
    int wrong_ws = (runtime_ws == 64) ? 32 : 64;

    /* Build package with wrong word size but correct endianness */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, wrong_ws, runtime_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_TARGET_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Wrong endianness is rejected */
TEST(cross_load_endianness_rejected) {
    const char *js_code = "function mbpf_prog(ctx) { return 456; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    uint8_t runtime_ws = mbpf_runtime_word_size();
    uint8_t runtime_end = mbpf_runtime_endianness();
    int wrong_end = (runtime_end == 0) ? 1 : 0;

    /* Build package with correct word size but wrong endianness */
    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, runtime_ws, wrong_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_TARGET_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test: Bytecode version also encodes word size (double protection) */
TEST(bytecode_version_encodes_word_size) {
    uint16_t version = mbpf_bytecode_version();

    /* Version 0x8001 = 64-bit, 0x0001 = 32-bit */
    if (mbpf_runtime_word_size() == 64) {
        ASSERT_EQ(version, 0x8001);
    } else {
        ASSERT_EQ(version, 0x0001);
    }

    return 0;
}

/* Test: Load program with correct manifest target but wrong bytecode version */
TEST(manifest_vs_bytecode_consistency) {
    /*
     * This test verifies that both manifest target and bytecode version
     * are checked. Even if manifest claims correct target, wrong bytecode
     * version will be caught.
     *
     * We create a fake bytecode with wrong version header:
     * - Magic 0xACFB (MQuickJS bytecode magic)
     * - Version with opposite word size bit
     */
    uint16_t runtime_version = mbpf_bytecode_version();
    uint16_t wrong_version = (runtime_version == 0x8001) ? 0x0001 : 0x8001;

    /* Build fake bytecode header with wrong version */
    uint8_t fake_bc[32];
    memset(fake_bc, 0, sizeof(fake_bc));
    fake_bc[0] = 0xFB;  /* Magic low byte */
    fake_bc[1] = 0xAC;  /* Magic high byte */
    fake_bc[2] = wrong_version & 0xFF;
    fake_bc[3] = (wrong_version >> 8) & 0xFF;

    /* Build package with correct manifest target but wrong bytecode */
    uint8_t pkg[8192];
    uint8_t runtime_ws = mbpf_runtime_word_size();
    uint8_t runtime_end = mbpf_runtime_endianness();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), fake_bc, sizeof(fake_bc), runtime_ws, runtime_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and attempt to load */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Should fail due to bytecode version mismatch */
    ASSERT_EQ(err, MBPF_ERR_UNSUPPORTED_VER);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test: Verify MBPF_ERR_TARGET_MISMATCH error code exists */
TEST(target_mismatch_error_code) {
    /* Verify the error code constant has expected value */
    ASSERT_EQ(MBPF_ERR_TARGET_MISMATCH, -27);
    return 0;
}

/* Test: Program with matching target can be attached and run */
TEST(matching_target_runs) {
    const char *js_code = "function mbpf_prog(ctx) { return 77; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT(bytecode != NULL);

    /* Build package with runtime's word size and endianness */
    uint8_t pkg[8192];
    uint8_t runtime_ws = mbpf_runtime_word_size();
    uint8_t runtime_end = mbpf_runtime_endianness();
    size_t pkg_len = build_mbpf_with_target(pkg, sizeof(pkg), bytecode, bc_len, runtime_ws, runtime_end);
    ASSERT(pkg_len > 0);

    /* Create runtime and load program */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT(rt != NULL);

    mbpf_program_t *prog;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Attach to hook */
    mbpf_hook_id_t hook = MBPF_HOOK_TRACEPOINT;
    err = mbpf_program_attach(rt, prog, hook);
    ASSERT_EQ(err, MBPF_OK);

    /* Run program */
    int32_t rc;
    err = mbpf_run(rt, hook, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 77);

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

    printf("microBPF Target Word Size Tests\n");
    printf("================================\n");
    printf("Runtime word size: %u-bit\n", mbpf_runtime_word_size());
    printf("Runtime endianness: %s\n", mbpf_runtime_endianness() == 0 ? "little" : "big");
    printf("\n");

    printf("Runtime info tests:\n");
    RUN_TEST(runtime_word_size_valid);
    RUN_TEST(runtime_endianness_valid);
    RUN_TEST(bytecode_version_encodes_word_size);
    RUN_TEST(target_mismatch_error_code);

    printf("\nMatching target tests:\n");
    RUN_TEST(matching_target_loads);
    RUN_TEST(matching_target_runs);
    RUN_TEST(word_size_64_on_64_runtime);

    printf("\nCross-load rejection tests:\n");
    RUN_TEST(cross_load_word_size_rejected);
    RUN_TEST(cross_load_endianness_rejected);
    RUN_TEST(word_size_32_on_64_rejected);
    RUN_TEST(word_size_64_on_32_rejected);
    RUN_TEST(manifest_vs_bytecode_consistency);

    printf("\n================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
