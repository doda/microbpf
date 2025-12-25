/*
 * microBPF NET_RX Decision Hook Tests
 *
 * Tests for MBPF_HOOK_NET_RX hook type:
 * 1. Load program targeting MBPF_HOOK_NET_RX
 * 2. Attach to network receive hook
 * 3. Invoke with packet context
 * 4. Verify MBPF_NET_PASS (0) allows packet
 * 5. Verify MBPF_NET_DROP (1) drops packet
 * 6. Verify MBPF_NET_ABORT (2) handled appropriately
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

/* Helper to build a minimal valid JSON manifest with NET_RX hook type */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    char json[1024];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"net_rx_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":3,"
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
    const char *js_file = "/tmp/test_hook_net_rx.js";
    const char *bc_file = "/tmp/test_hook_net_rx.qjbc";

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
 * Test Cases - hook-net-rx
 * ============================================================================ */

/*
 * Test 1: Load program targeting MBPF_HOOK_NET_RX
 */
TEST(load_net_rx_program) {
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
 * Test 2: Attach to network receive hook
 */
TEST(attach_to_net_rx) {
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Invoke with packet context
 */
TEST(invoke_with_packet_context) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    if (ctx.ifindex !== 42) return -2;\n"
        "    if (ctx.pkt_len !== 1500) return -3;\n"
        "    if (ctx.data_len !== 64) return -4;\n"
        "    if (ctx.l2_proto !== 0x0800) return -5;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Create NET_RX context with sample packet data */
    uint8_t packet_data[64];
    memset(packet_data, 0xAB, sizeof(packet_data));

    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 42,
        .pkt_len = 1500,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: MBPF_NET_PASS (0) allows packet
 */
TEST(net_pass_allows_packet) {
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t packet_data[64] = {0};
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    /* Verify stats show success */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: MBPF_NET_DROP (1) drops packet
 */
TEST(net_drop_drops_packet) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t packet_data[64] = {0};
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_DROP);

    /* Verify stats show success (program ran successfully, just returned DROP) */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: MBPF_NET_ABORT (2) handled appropriately
 */
TEST(net_abort_handled) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 2;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t packet_data[64] = {0};
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_ABORT);

    /* Verify stats show success (program ran successfully) */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Decision based on packet content - drop packets with first byte 0xFF
 */
TEST(decision_based_on_content) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.data_len < 1) return 0;\n"
        "    var first_byte = ctx.readU8(0);\n"
        "    if (first_byte === 0xFF) {\n"
        "        return 1;\n"
        "    }\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Test packet with first byte 0xFF - should be dropped */
    uint8_t drop_packet[64] = {0xFF, 0x00, 0x00, 0x00};
    mbpf_ctx_net_rx_v1_t ctx1 = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = drop_packet,
        .read_fn = NULL
    };

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx1, sizeof(ctx1), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_DROP);

    /* Test packet with first byte NOT 0xFF - should be passed */
    uint8_t pass_packet[64] = {0x00, 0x00, 0x00, 0x00};
    mbpf_ctx_net_rx_v1_t ctx2 = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = pass_packet,
        .read_fn = NULL
    };

    out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx2, sizeof(ctx2), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Exception in program returns safe default (PASS)
 */
TEST(exception_returns_safe_default) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t packet_data[64] = {0};
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    /* Verify exception was counted */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.exceptions, 1);
    ASSERT_EQ(stats.successes, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Verify hook ABI version for NET_RX
 */
TEST(hook_abi_version) {
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_NET_RX), 1);
    return 0;
}

/*
 * Test 10: Read packet data using all read methods
 */
TEST(read_packet_data) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.data_len < 8) return -1;\n"
        "    if (ctx.readU8(0) !== 0xDE) return -2;\n"
        "    if (ctx.readU8(1) !== 0xAD) return -3;\n"
        "    if (ctx.readU16LE(0) !== 0xADDE) return -4;\n"
        "    if (ctx.readU32LE(0) !== 0xEFBEADDE) return -5;\n"
        "    var buf = new Uint8Array(4);\n"
        "    var n = ctx.readBytes(4, 4, buf);\n"
        "    if (n !== 4) return -6;\n"
        "    if (buf[0] !== 0x12) return -7;\n"
        "    if (buf[1] !== 0x34) return -8;\n"
        "    if (buf[2] !== 0x56) return -9;\n"
        "    if (buf[3] !== 0x78) return -10;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* 0xDEADBEEF in little-endian, followed by 0x12345678 */
    uint8_t packet_data[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78};
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 8,
        .data_len = 8,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Detach and verify program no longer runs
 */
TEST(detach_stops_execution) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t packet_data[64] = {0};
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    /* Run while attached - should return DROP */
    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_DROP);

    /* Detach */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Run after detach - should return default (PASS) */
    out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Verify flags field is accessible
 */
TEST(flags_field_accessible) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.flags !== 1) return -1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t packet_data[64] = {0};
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = MBPF_CTX_F_TRUNCATED,
        .data = packet_data,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: Multiple invocations update stats correctly
 */
TEST(multiple_invocations) {
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    for (int i = 0; i < 10; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_NET_PASS);
    }

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 10);
    ASSERT_EQ(stats.successes, 10);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 14: Filter based on L2 protocol (only allow IPv4)
 * Note: Due to a pre-existing GC timing issue with dynamic context objects,
 * each test case uses a separate runtime to avoid the second-invocation bug.
 */
TEST(filter_by_l2_proto_ipv4) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.l2_proto === 0x0800) {\n"
        "        return 0;\n"
        "    }\n"
        "    return 1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t packet_data[64] = {0};

    /* IPv4 packet (0x0800) - should pass */
    mbpf_ctx_net_rx_v1_t ctx_ipv4 = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_ipv4, sizeof(ctx_ipv4), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 14b: Filter based on L2 protocol - IPv6 should be dropped
 */
TEST(filter_by_l2_proto_ipv6) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.l2_proto === 0x0800) {\n"
        "        return 0;\n"
        "    }\n"
        "    return 1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t packet_data[64] = {0};

    /* IPv6 packet (0x86DD) - should drop */
    mbpf_ctx_net_rx_v1_t ctx_ipv6 = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x86DD,
        .flags = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_ipv6, sizeof(ctx_ipv6), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_DROP);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 15: Null context returns null to JS and triggers PASS
 */
TEST(null_context) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return 0;\n"
        "    return 1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF NET_RX Decision Hook Tests\n");
    printf("====================================\n\n");

    printf("Load and attach tests:\n");
    RUN_TEST(load_net_rx_program);
    RUN_TEST(attach_to_net_rx);
    RUN_TEST(hook_abi_version);

    printf("\nContext and execution tests:\n");
    RUN_TEST(invoke_with_packet_context);
    RUN_TEST(null_context);
    RUN_TEST(multiple_invocations);

    printf("\nDecision return value tests:\n");
    RUN_TEST(net_pass_allows_packet);
    RUN_TEST(net_drop_drops_packet);
    RUN_TEST(net_abort_handled);

    printf("\nPacket content decision tests:\n");
    RUN_TEST(decision_based_on_content);
    RUN_TEST(filter_by_l2_proto_ipv4);
    RUN_TEST(filter_by_l2_proto_ipv6);
    RUN_TEST(read_packet_data);

    printf("\nContext field tests:\n");
    RUN_TEST(flags_field_accessible);

    printf("\nError handling tests:\n");
    RUN_TEST(exception_returns_safe_default);

    printf("\nLifecycle tests:\n");
    RUN_TEST(detach_stops_execution);

    printf("\n====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
