/*
 * microBPF NET_RX v1 Context Tests
 *
 * Tests for MBPF_HOOK_NET_RX v1 context structure and binding:
 * 1. Create mbpf_ctx_net_rx_v1 structure with abi_version=1
 * 2. Populate ifindex, pkt_len, data_len, l2_proto, flags, data pointer
 * 3. Run program and verify all fields accessible via ctx object
 * 4. Verify ctx.read* methods work with data pointer
 * 5. Test with read_fn instead of data pointer
 * 6. Verify MBPF_CTX_F_TRUNCATED flag is accessible
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
        "\"program_name\":\"net_rx_v1_test\","
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
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        hook_type);
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
    const char *js_file = "/tmp/test_net_rx_v1.js";
    const char *bc_file = "/tmp/test_net_rx_v1.qjbc";

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

/* Scatter-gather read function for testing read_fn */
static int test_read_fn(const void *ctx_blob, uint32_t off, uint32_t len, uint8_t *dst) {
    (void)ctx_blob;  /* We don't use the context blob in this test */

    if (off >= sizeof(test_packet)) {
        return 0;
    }

    uint32_t available = sizeof(test_packet) - off;
    uint32_t to_copy = (len < available) ? len : available;

    memcpy(dst, test_packet + off, to_copy);
    return (int)to_copy;
}

/* ============================================================================
 * Test Cases - context-net-rx-v1
 * ============================================================================ */

/*
 * Test 1: Verify mbpf_ctx_net_rx_v1_t structure has abi_version=1
 * This is a compile-time test - if the structure doesn't exist, this won't compile
 */
TEST(ctx_net_rx_v1_structure_exists) {
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 0,
        .pkt_len = 0,
        .data_len = 0,
        .l2_proto = 0,
        .flags = 0,
        .data = NULL,
        .read_fn = NULL
    };

    /* Verify all required fields are present */
    ASSERT_EQ(ctx.abi_version, 1);
    ASSERT_EQ(ctx.ifindex, 0);
    ASSERT_EQ(ctx.pkt_len, 0);
    ASSERT_EQ(ctx.data_len, 0);
    ASSERT_EQ(ctx.l2_proto, 0);
    ASSERT_EQ(ctx.flags, 0);
    ASSERT_NULL(ctx.data);
    ASSERT_NULL(ctx.read_fn);

    return 0;
}

/*
 * Test 2: Populate all fields and run program that reads them
 */
TEST(ctx_net_rx_v1_all_fields_accessible) {
    /* Program reads all fields and returns a computed value */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    var sum = ctx.ifindex + ctx.pkt_len + ctx.data_len + ctx.l2_proto + ctx.flags;\n"
        "    return sum;\n"
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

    /* Create NET_RX context with known values */
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 10,
        .pkt_len = 100,
        .data_len = 50,
        .l2_proto = 20,
        .flags = 5,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 10 + 100 + 50 + 20 + 5);  /* 185 */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Verify ctx.flags field is accessible
 */
TEST(ctx_net_rx_v1_flags_accessible) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.flags;\n"
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
        .pkt_len = 100,
        .data_len = 100,
        .l2_proto = 0x0800,
        .flags = 42,
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

/*
 * Test 4: Verify MBPF_CTX_F_TRUNCATED flag is accessible
 */
TEST(ctx_net_rx_v1_truncated_flag) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.flags;\n"
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

    /* Set the TRUNCATED flag */
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 1000,  /* Original packet length */
        .data_len = 100,  /* Truncated data length */
        .l2_proto = 0x0800,
        .flags = MBPF_CTX_F_TRUNCATED,  /* Flag indicating truncation */
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_CTX_F_TRUNCATED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Verify program can check for TRUNCATED flag using bitwise AND
 */
TEST(ctx_net_rx_v1_check_truncated_flag) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    if (ctx.flags & 1) {\n"  /* MBPF_CTX_F_TRUNCATED = 1 */
        "        return 100;\n"  /* Truncated */
        "    }\n"
        "    return 0;\n"  /* Not truncated */
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

    /* Test with TRUNCATED flag set */
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 1000,
        .data_len = 100,
        .l2_proto = 0x0800,
        .flags = MBPF_CTX_F_TRUNCATED,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 100);  /* Should detect truncation */

    /* Test without TRUNCATED flag */
    ctx_blob.flags = 0;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* Not truncated */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Verify ctx.read* methods work with data pointer
 */
TEST(ctx_net_rx_v1_read_with_data_pointer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.readU8(0) + ctx.readU8(1);\n"
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
    /* First two bytes: 0x12 + 0x34 = 0x46 = 70 */
    ASSERT_EQ(out_rc, 0x12 + 0x34);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Verify ctx.read* methods work with read_fn instead of data pointer
 */
TEST(ctx_net_rx_v1_read_with_read_fn) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.readU8(0) + ctx.readU8(1);\n"
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

    /* Use read_fn instead of data pointer */
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = NULL,  /* No direct data pointer */
        .read_fn = test_read_fn  /* Use read function instead */
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* First two bytes: 0x12 + 0x34 = 0x46 = 70 */
    ASSERT_EQ(out_rc, 0x12 + 0x34);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Verify readU16LE works with read_fn
 */
TEST(ctx_net_rx_v1_readU16LE_with_read_fn) {
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
        .data = NULL,
        .read_fn = test_read_fn
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Little-endian: 0x12, 0x34 -> 0x3412 */
    ASSERT_EQ(out_rc, 0x3412);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Verify readU32LE works with read_fn
 */
TEST(ctx_net_rx_v1_readU32LE_with_read_fn) {
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
        .data = NULL,
        .read_fn = test_read_fn
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Little-endian: 0x12, 0x34, 0x56, 0x78 -> 0x78563412 */
    ASSERT_EQ((uint32_t)out_rc, 0x78563412u);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Verify readBytes works with read_fn
 */
TEST(ctx_net_rx_v1_readBytes_with_read_fn) {
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
        .data = NULL,
        .read_fn = test_read_fn
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Sum of first 5 bytes: 0x12 + 0x34 + 0x56 + 0x78 + 0x9A = 430 */
    ASSERT_EQ(out_rc, 430);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Verify data pointer takes precedence over read_fn
 */
TEST(ctx_net_rx_v1_data_pointer_precedence) {
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

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);

    /* Both data and read_fn provided - data should take precedence */
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_packet),
        .data_len = sizeof(test_packet),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_packet,  /* Direct data pointer */
        .read_fn = test_read_fn  /* Also provided */
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Should read from data pointer (test_packet[0] = 0x12) */
    ASSERT_EQ(out_rc, 0x12);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Multiple flags combined
 */
TEST(ctx_net_rx_v1_multiple_flags) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    return ctx.flags;\n"
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

    /* Set multiple flags (TRUNCATED + hypothetical future flags) */
    uint16_t combined_flags = MBPF_CTX_F_TRUNCATED | (1 << 1) | (1 << 2);
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 1000,
        .data_len = 100,
        .l2_proto = 0x0800,
        .flags = combined_flags,
        .data = test_packet,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, combined_flags);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: Verify MBPF_CTX_F_TRUNCATED constant value
 */
TEST(ctx_flag_truncated_value) {
    /* MBPF_CTX_F_TRUNCATED should be (1 << 0) = 1 */
    ASSERT_EQ(MBPF_CTX_F_TRUNCATED, 1);
    return 0;
}

/*
 * Test 14: Large data via read_fn
 */
TEST(ctx_net_rx_v1_large_read_fn_data) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    var buf = new Uint8Array(20);\n"
        "    var n = ctx.readBytes(0, 20, buf);\n"
        "    return n;\n"  /* Return how many bytes were read */
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
        .data = NULL,
        .read_fn = test_read_fn
    };

    int32_t out_rc = -999;
    int err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 20);  /* Should read all 20 bytes */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF NET_RX v1 Context Tests\n");
    printf("=================================\n\n");

    printf("Structure and field tests:\n");
    RUN_TEST(ctx_net_rx_v1_structure_exists);
    RUN_TEST(ctx_net_rx_v1_all_fields_accessible);
    RUN_TEST(ctx_net_rx_v1_flags_accessible);

    printf("\nTRUNCATED flag tests:\n");
    RUN_TEST(ctx_net_rx_v1_truncated_flag);
    RUN_TEST(ctx_net_rx_v1_check_truncated_flag);
    RUN_TEST(ctx_flag_truncated_value);
    RUN_TEST(ctx_net_rx_v1_multiple_flags);

    printf("\nRead with data pointer tests:\n");
    RUN_TEST(ctx_net_rx_v1_read_with_data_pointer);

    printf("\nRead with read_fn tests:\n");
    RUN_TEST(ctx_net_rx_v1_read_with_read_fn);
    RUN_TEST(ctx_net_rx_v1_readU16LE_with_read_fn);
    RUN_TEST(ctx_net_rx_v1_readU32LE_with_read_fn);
    RUN_TEST(ctx_net_rx_v1_readBytes_with_read_fn);
    RUN_TEST(ctx_net_rx_v1_large_read_fn_data);

    printf("\nPrecedence tests:\n");
    RUN_TEST(ctx_net_rx_v1_data_pointer_precedence);

    printf("\n=================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
