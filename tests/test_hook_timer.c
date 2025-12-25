/*
 * microBPF TIMER Hook Tests
 *
 * Tests for MBPF_HOOK_TIMER hook type:
 * 1. Load program targeting MBPF_HOOK_TIMER
 * 2. Attach with timer configuration (period, etc.)
 * 3. Verify program executes periodically
 * 4. Verify timer context provides expected fields
 * 5. Detach and verify timer stops
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

/* Helper to build a minimal valid JSON manifest with TIMER hook type */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    char json[1024];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"timer_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":2,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
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
    const char *js_file = "/tmp/test_hook_timer.js";
    const char *bc_file = "/tmp/test_hook_timer.qjbc";

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
 * Test Cases - hook-timer
 * ============================================================================ */

/*
 * Test 1: Load program targeting MBPF_HOOK_TIMER
 */
TEST(load_timer_program) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Attach to timer hook
 */
TEST(attach_to_timer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Verify ABI version for TIMER hook
 */
TEST(hook_abi_version) {
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_TIMER), 1);
    return 0;
}

/*
 * Test 4: Trigger hook with timer context
 */
TEST(trigger_with_context) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    if (ctx.timer_id !== 42) return -2;\n"
        "    if (ctx.period_us !== 1000) return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    /* Create timer context */
    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 42,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 0
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Verify timer_id field
 */
TEST(context_timer_id) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.timer_id === 123) return 0;\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 123,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 0
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Verify period_us field
 */
TEST(context_period_us) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.period_us === 5000) return 0;\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 1,
        .period_us = 5000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 0
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Verify invocation_count field
 */
TEST(context_invocation_count) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.invocation_count === 100) return 0;\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 1,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 100,
        .timestamp = 0
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Verify timestamp field
 */
TEST(context_timestamp) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.timestamp === 9876543210) return 0;\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 1,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 9876543210ULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Verify flags field
 */
TEST(context_flags) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.flags === 1) return 0;\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 1,
        .period_us = 1000,
        .flags = MBPF_CTX_F_TRUNCATED,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 0
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Verify return value is captured
 */
TEST(return_value_captured) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 1,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 0
    };

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Simulate periodic execution (multiple invocations with incrementing count)
 */
TEST(periodic_execution) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return ctx.invocation_count;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    /* Simulate 5 periodic timer invocations */
    for (uint64_t i = 0; i < 5; i++) {
        mbpf_ctx_timer_v1_t ctx = {
            .abi_version = 1,
            .timer_id = 1,
            .period_us = 1000,
            .flags = 0,
            .reserved = 0,
            .invocation_count = i,
            .timestamp = i * 1000000ULL  /* Simulate timestamp increment */
        };

        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ((uint64_t)out_rc, i);
    }

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 5);
    ASSERT_EQ(stats.successes, 5);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Detach and verify timer stops (program doesn't execute after detach)
 */
TEST(detach_stops_timer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 7;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 1,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 0
    };

    /* Attach and run */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 7);

    /* Detach */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    /* Run should return default (no attached program) */
    out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    /* Verify stats only counted one invocation */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: Re-attach after detach
 */
TEST(reattach_after_detach) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 99;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 1,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 0
    };

    /* Attach, run, detach */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 99);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    /* Re-attach and run again */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 99);

    /* Verify stats counted two invocations */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 2);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 14: Null context returns null to JS
 */
TEST(null_context) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return 0;\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 15: Context properties are read-only
 */
TEST(context_readonly) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var original = ctx.timer_id;\n"
        "    ctx.timer_id = 999;\n"
        "    if (ctx.timer_id === original) return 0;\n"
        "    return -1;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 42,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 0
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 16: All context fields accessible in one check
 */
TEST(all_fields_accessible) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.timer_id !== 1) return -1;\n"
        "    if (ctx.period_us !== 2000) return -2;\n"
        "    if (ctx.invocation_count !== 50) return -3;\n"
        "    if (ctx.timestamp !== 123456789) return -4;\n"
        "    if (ctx.flags !== 0) return -5;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 1,
        .period_us = 2000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 50,
        .timestamp = 123456789ULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 17: Hook type mismatch rejected
 */
TEST(hook_mismatch_rejected) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Try to attach to wrong hook type (NET_RX instead of TIMER) */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF TIMER Hook Tests\n");
    printf("=========================\n\n");

    printf("Load and attach tests:\n");
    RUN_TEST(load_timer_program);
    RUN_TEST(attach_to_timer);
    RUN_TEST(hook_abi_version);

    printf("\nContext field tests:\n");
    RUN_TEST(trigger_with_context);
    RUN_TEST(context_timer_id);
    RUN_TEST(context_period_us);
    RUN_TEST(context_invocation_count);
    RUN_TEST(context_timestamp);
    RUN_TEST(context_flags);
    RUN_TEST(all_fields_accessible);

    printf("\nExecution tests:\n");
    RUN_TEST(return_value_captured);
    RUN_TEST(periodic_execution);
    RUN_TEST(null_context);
    RUN_TEST(context_readonly);

    printf("\nLifecycle tests:\n");
    RUN_TEST(detach_stops_timer);
    RUN_TEST(reattach_after_detach);
    RUN_TEST(hook_mismatch_rejected);

    printf("\n=========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
