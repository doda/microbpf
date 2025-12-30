/*
 * microBPF Context Read Methods Tests
 *
 * Tests for ctx.readU8, ctx.readU16LE, ctx.readU32LE, ctx.readBytes:
 * 1. Create NET_RX context with known packet data
 * 2. Run program calling ctx.readU8(0) - verify correct byte returned
 * 3. Run program calling ctx.readU16LE(0) - verify correct little-endian 16-bit value
 * 4. Run program calling ctx.readU32LE(0) - verify correct little-endian 32-bit value
 * 5. Run program calling ctx.readBytes(0, 10, outBuffer) - verify bytes copied
 * 6. Verify readBytes returns number of bytes copied
 * 7. Verify out-of-bounds reads throw exceptions
 * 8. Verify type errors thrown for invalid arguments
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
        "\"program_name\":\"ctx_read_test\","
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
    const char *js_file = "/tmp/test_ctx_read.js";
    const char *bc_file = "/tmp/test_ctx_read.qjbc";

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

/* Known packet data for testing */
static const uint8_t test_packet[] = {
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,  /* bytes 0-7 */
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,  /* bytes 8-15 */
    0xAA, 0xBB, 0xCC, 0xDD                           /* bytes 16-19 */
};

/* ============================================================================
 * Test Cases - context-read-methods
 * ============================================================================ */

/*
 * Test 1: ctx.readU8(0) - verify correct byte returned
 */
TEST(readU8_at_offset_0) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.readU8(0);\n"
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

    /* Create NET_RX context with known packet data */
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0x12);  /* First byte */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: ctx.readU8 at different offsets
 */
TEST(readU8_various_offsets) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.readU8(5);\n"  /* Should return 0xBC */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0xBC);  /* Byte at offset 5 */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: ctx.readU16LE(0) - verify correct little-endian 16-bit value
 */
TEST(readU16LE_at_offset_0) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.readU16LE(0);\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Little-endian: bytes 0x12, 0x34 -> 0x3412 */
    ASSERT_EQ(out_rc, 0x3412);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: ctx.readU16LE at different offset
 */
TEST(readU16LE_at_offset_2) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.readU16LE(2);\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Little-endian: bytes 0x56, 0x78 -> 0x7856 */
    ASSERT_EQ(out_rc, 0x7856);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: ctx.readU32LE(0) - verify correct little-endian 32-bit value
 */
TEST(readU32LE_at_offset_0) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.readU32LE(0);\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Little-endian: bytes 0x12, 0x34, 0x56, 0x78 -> 0x78563412 */
    ASSERT_EQ((uint32_t)out_rc, 0x78563412u);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: ctx.readU32LE at offset 4
 */
TEST(readU32LE_at_offset_4) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.readU32LE(4);\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Little-endian: bytes 0x9A, 0xBC, 0xDE, 0xF0 -> 0xF0DEBC9A */
    ASSERT_EQ((uint32_t)out_rc, 0xF0DEBC9Au);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: ctx.readBytes - verify bytes copied and count returned
 */
TEST(readBytes_basic) {
    /* Read 5 bytes and sum them to verify they were copied correctly */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    var buf = new Uint8Array(5);\n"
        "    var n = ctx.readBytes(0, 5, buf);\n"
        "    if (n !== 5) return -2;\n"
        "    var sum = 0;\n"
        "    for (var i = 0; i < 5; i++) sum += buf[i];\n"
        "    return sum;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Sum of first 5 bytes: 0x12 + 0x34 + 0x56 + 0x78 + 0x9A = 0x1AE = 430 */
    ASSERT_EQ(out_rc, 430);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: ctx.readBytes at non-zero offset
 */
TEST(readBytes_at_offset) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    var buf = new Uint8Array(4);\n"
        "    var n = ctx.readBytes(8, 4, buf);\n"
        "    if (n !== 4) return -2;\n"
        "    return buf[0] + buf[1] + buf[2] + buf[3];\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Bytes at offset 8-11: 0x11, 0x22, 0x33, 0x44 = 0xAA = 170 */
    ASSERT_EQ(out_rc, 0x11 + 0x22 + 0x33 + 0x44);  /* 170 */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: ctx.readBytes returns actual bytes copied when truncated
 */
TEST(readBytes_truncated) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    var buf = new Uint8Array(100);\n"
        "    var n = ctx.readBytes(15, 100, buf);\n"  /* Request 100 but only 5 available */
        "    return n;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),  /* 20 bytes total */
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* From offset 15, only 5 bytes available (20 - 15 = 5) */
    ASSERT_EQ(out_rc, 5);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Out-of-bounds readU8 throws exception
 */
TEST(readU8_out_of_bounds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    try {\n"
        "        ctx.readU8(100);\n"  /* Out of bounds */
        "        return 0;\n"  /* Should not reach here */
        "    } catch (e) {\n"
        "        return 42;\n"  /* Exception caught */
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);  /* Exception was caught */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Out-of-bounds readU16LE throws exception
 */
TEST(readU16LE_out_of_bounds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    try {\n"
        "        ctx.readU16LE(19);\n"  /* Only 1 byte available, need 2 */
        "        return 0;\n"
        "    } catch (e) {\n"
        "        return 42;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),  /* 20 bytes */
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Out-of-bounds readU32LE throws exception
 */
TEST(readU32LE_out_of_bounds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    try {\n"
        "        ctx.readU32LE(17);\n"  /* Only 3 bytes available, need 4 */
        "        return 0;\n"
        "    } catch (e) {\n"
        "        return 42;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),  /* 20 bytes */
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: Out-of-bounds readBytes throws exception
 */
TEST(readBytes_out_of_bounds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    try {\n"
        "        var buf = new Uint8Array(10);\n"
        "        ctx.readBytes(100, 10, buf);\n"  /* Offset beyond data */
        "        return 0;\n"
        "    } catch (e) {\n"
        "        return 42;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 14: TypeError for non-number offset
 */
TEST(readU8_type_error_non_number) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    try {\n"
        "        ctx.readU8('hello');\n"  /* String instead of number */
        "        return 0;\n"
        "    } catch (e) {\n"
        "        return 42;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);  /* Exception caught */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 15: TypeError for non-Uint8Array buffer in readBytes
 */
TEST(readBytes_type_error_non_uint8array) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    try {\n"
        "        ctx.readBytes(0, 5, [1,2,3,4,5]);\n"  /* Array instead of Uint8Array */
        "        return 0;\n"
        "    } catch (e) {\n"
        "        return 42;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 16: Negative offset throws RangeError
 */
TEST(readU8_negative_offset) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    try {\n"
        "        ctx.readU8(-1);\n"
        "        return 0;\n"
        "    } catch (e) {\n"
        "        return 42;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 17: No data available throws RangeError
 */
TEST(readU8_no_data) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    try {\n"
        "        ctx.readU8(0);\n"
        "        return 0;\n"
        "    } catch (e) {\n"
        "        return 42;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_NET_RX);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    /* Context with no data pointer */
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 100,
        .data_len = 0,  /* No data */
        .l2_proto = 0x0800,
        .flags = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Context Read Methods Tests\n");
    printf("====================================\n\n");

    printf("ctx.readU8 tests:\n");
    RUN_TEST(readU8_at_offset_0);
    RUN_TEST(readU8_various_offsets);

    printf("\nctx.readU16LE tests:\n");
    RUN_TEST(readU16LE_at_offset_0);
    RUN_TEST(readU16LE_at_offset_2);

    printf("\nctx.readU32LE tests:\n");
    RUN_TEST(readU32LE_at_offset_0);
    RUN_TEST(readU32LE_at_offset_4);

    printf("\nctx.readBytes tests:\n");
    RUN_TEST(readBytes_basic);
    RUN_TEST(readBytes_at_offset);
    RUN_TEST(readBytes_truncated);

    printf("\nOut-of-bounds error tests:\n");
    RUN_TEST(readU8_out_of_bounds);
    RUN_TEST(readU16LE_out_of_bounds);
    RUN_TEST(readU32LE_out_of_bounds);
    RUN_TEST(readBytes_out_of_bounds);

    printf("\nType error tests:\n");
    RUN_TEST(readU8_type_error_non_number);
    RUN_TEST(readBytes_type_error_non_uint8array);
    RUN_TEST(readU8_negative_offset);
    RUN_TEST(readU8_no_data);

    printf("\n====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
