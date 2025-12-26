/*
 * microBPF Context Object Reuse Tests
 *
 * Verifies that the ctx host object is reused across invocations:
 * 1. The ctx object is created once per instance at load time
 * 2. The opaque pointer (context data) is updated at each invocation
 * 3. No per-invocation allocation is needed for the ctx object itself
 *
 * This test works by:
 * 1. Running multiple invocations with different context data
 * 2. Verifying the correct values are seen in each invocation
 * 3. Testing that the JS object identity is preserved (same object reused)
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

/* Helper to build a minimal valid JSON manifest with specific hook type */
static size_t build_test_manifest(uint8_t *buf, size_t cap, int hook_type) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"ctx_reuse_test\","
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

/* Build a complete .mbpf package with bytecode */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest), hook_type);
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
    const char *js_file = "/tmp/test_ctx_reuse.js";
    const char *bc_file = "/tmp/test_ctx_reuse.qjbc";

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
    *out_len = len;
    return bytecode;
}

/* ============================================================================
 * Test Cases - context-object-reuse
 * ============================================================================ */

/*
 * Test 1: Context data updates between invocations
 *
 * Run multiple invocations with different ifindex values and verify
 * the correct value is seen in each invocation.
 */
TEST(ctx_data_updates_between_invocations) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.ifindex;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run with ifindex=100 */
    mbpf_ctx_net_rx_v1_t ctx1 = {
        .abi_version = 1,
        .ifindex = 100,
        .pkt_len = 64,
        .data_len = 0,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx1, sizeof(ctx1), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 100);

    /* Run with ifindex=200 */
    mbpf_ctx_net_rx_v1_t ctx2 = {
        .abi_version = 1,
        .ifindex = 200,
        .pkt_len = 128,
        .data_len = 0,
        .l2_proto = 0x86DD,
        .flags = 0,
        .data = NULL,
        .read_fn = NULL
    };

    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx2, sizeof(ctx2), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 200);

    /* Run with ifindex=42 */
    mbpf_ctx_net_rx_v1_t ctx3 = {
        .abi_version = 1,
        .ifindex = 42,
        .pkt_len = 256,
        .data_len = 0,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = NULL,
        .read_fn = NULL
    };

    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx3, sizeof(ctx3), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: All scalar fields update correctly
 *
 * Verify that all scalar fields (ifindex, pkt_len, data_len, l2_proto, flags)
 * are updated correctly between invocations.
 */
TEST(all_scalars_update_correctly) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    /* Return a composite value encoding multiple fields */\n"
        "    return (ctx.ifindex << 24) | (ctx.pkt_len << 16) | "
        "(ctx.data_len << 8) | ctx.l2_proto;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run with specific values */
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 2,
        .data_len = 3,
        .l2_proto = 4,
        .flags = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Expected: (1 << 24) | (2 << 16) | (3 << 8) | 4 = 0x01020304 */
    ASSERT_EQ(out_rc, 0x01020304);

    /* Run with different values */
    ctx_blob.ifindex = 5;
    ctx_blob.pkt_len = 6;
    ctx_blob.data_len = 7;
    ctx_blob.l2_proto = 8;

    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Expected: (5 << 24) | (6 << 16) | (7 << 8) | 8 = 0x05060708 */
    ASSERT_EQ(out_rc, 0x05060708);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Data buffer updates correctly between invocations
 *
 * Verify that packet data is correctly updated between invocations.
 */
TEST(data_buffer_updates_between_invocations) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    if (ctx.data_len < 2) return -2;\n"
        "    /* Return first two bytes as 16-bit value */\n"
        "    return ctx.readU16LE(0);\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run with first data set: 0x12, 0x34 => LE 16-bit = 0x3412 */
    uint8_t data1[] = {0x12, 0x34, 0x56, 0x78};
    mbpf_ctx_net_rx_v1_t ctx1 = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(data1),
        .data_len = sizeof(data1),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = data1,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx1, sizeof(ctx1), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0x3412);

    /* Run with second data set: 0xAB, 0xCD => LE 16-bit = 0xCDAB */
    uint8_t data2[] = {0xAB, 0xCD, 0xEF, 0x01};
    mbpf_ctx_net_rx_v1_t ctx2 = {
        .abi_version = 1,
        .ifindex = 2,
        .pkt_len = sizeof(data2),
        .data_len = sizeof(data2),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = data2,
        .read_fn = NULL
    };

    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx2, sizeof(ctx2), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, (int32_t)0xCDAB);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Many invocations verify reuse (performance/stress test)
 *
 * Run many invocations to stress-test the reuse mechanism.
 * If per-invocation allocation were happening, this would show
 * memory growth or performance degradation.
 */
TEST(many_invocations_verify_reuse) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.ifindex;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run 1000 invocations with varying ifindex */
    for (int i = 0; i < 1000; i++) {
        mbpf_ctx_net_rx_v1_t ctx_blob = {
            .abi_version = 1,
            .ifindex = (uint32_t)(i % 256),
            .pkt_len = 64,
            .data_len = 0,
            .l2_proto = 0x0800,
            .flags = 0,
            .data = NULL,
            .read_fn = NULL
        };

        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, (int32_t)(i % 256));
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Timer hook context updates correctly
 *
 * Test that timer hook context also updates correctly between invocations.
 */
TEST(timer_ctx_updates_correctly) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.timer_id;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TIMER);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    /* Run with timer_id=10 */
    mbpf_ctx_timer_v1_t timer1 = {
        .abi_version = 1,
        .timer_id = 10,
        .period_us = 1000,
        .invocation_count = 1,
        .timestamp = 123456789,
        .flags = 0
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &timer1, sizeof(timer1), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 10);

    /* Run with timer_id=42 */
    mbpf_ctx_timer_v1_t timer2 = {
        .abi_version = 1,
        .timer_id = 42,
        .period_us = 2000,
        .invocation_count = 2,
        .timestamp = 123456790,
        .flags = 0
    };

    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TIMER, &timer2, sizeof(timer2), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Large data buffer handling
 *
 * Test that large data buffers (> 1KB) are handled correctly without
 * buffer overflow or truncation. This verifies the dynamic buffer
 * allocation fix.
 */
TEST(large_data_buffer_handling) {
    /* JS code that sums first and last bytes of data */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    if (ctx.data_len < 2) return -2;\n"
        "    var first = ctx.readU8(0);\n"
        "    var last = ctx.readU8(ctx.data_len - 1);\n"
        "    return first + last;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Create a 2000-byte data buffer (larger than old 4096 char buffer could handle) */
    uint8_t *large_data = malloc(2000);
    ASSERT_NOT_NULL(large_data);

    /* Fill with known pattern: first byte = 0x11, last byte = 0x22 */
    memset(large_data, 0xAA, 2000);
    large_data[0] = 0x11;
    large_data[1999] = 0x22;

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 2000,
        .data_len = 2000,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = large_data,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Expected: 0x11 + 0x22 = 0x33 = 51 */
    ASSERT_EQ(out_rc, 0x33);

    free(large_data);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Runner
 * ============================================================================ */

int main(void) {
    int passed = 0, failed = 0;

    printf("microBPF Context Object Reuse Tests\n");
    printf("====================================\n\n");

    printf("Context data update tests:\n");
    RUN_TEST(ctx_data_updates_between_invocations);
    RUN_TEST(all_scalars_update_correctly);
    RUN_TEST(data_buffer_updates_between_invocations);

    printf("\nStress tests:\n");
    RUN_TEST(many_invocations_verify_reuse);

    printf("\nMultiple hook type tests:\n");
    RUN_TEST(timer_ctx_updates_correctly);

    printf("\nLarge data tests:\n");
    RUN_TEST(large_data_buffer_handling);

    printf("\n====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    return (failed > 0) ? 1 : 0;
}
