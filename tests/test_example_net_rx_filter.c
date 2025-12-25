/*
 * microBPF Example NET_RX Filter Test
 *
 * End-to-end test for the example NET_RX filter program from spec.
 * Tests:
 * 1. Create JS program that drops packets with first byte 0xFF
 * 2. Compile to bytecode and package as .mbpf
 * 3. Load and attach to NET_RX hook
 * 4. Send packet with first byte 0xFF - verify dropped
 * 5. Send packet with different first byte - verify passed
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
        "\"program_name\":\"net_rx_filter_example\","
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

/* Compile JavaScript file to bytecode using mqjs */
static uint8_t *compile_js_file_to_bytecode(const char *js_file, size_t *out_len) {
    const char *bc_file = "/tmp/test_example_net_rx_filter.qjbc";

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "./deps/mquickjs/mqjs --no-column -o %s %s 2>/dev/null",
             bc_file, js_file);
    int ret = system(cmd);
    if (ret != 0) return NULL;

    FILE *f = fopen(bc_file, "rb");
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
 * Test Cases - example-net-rx-filter
 * ============================================================================ */

/*
 * Test 1: Compile the example JS program to bytecode
 */
TEST(compile_example_js_to_bytecode) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_file_to_bytecode("examples/net_rx_filter.js", &bc_len);
    ASSERT_NOT_NULL(bytecode);
    ASSERT(bc_len > 0);

    /* Verify bytecode has MQuickJS magic header (0xfbac01) */
    ASSERT(bc_len >= 3);
    ASSERT(bytecode[0] == 0xfb || bytecode[0] == 0x01);  /* Version-dependent magic */

    free(bytecode);
    return 0;
}

/*
 * Test 2: Package bytecode as .mbpf
 */
TEST(package_as_mbpf) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_file_to_bytecode("examples/net_rx_filter.js", &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Verify .mbpf magic header "MBPF" in little endian */
    ASSERT(pkg[0] == 0x46 && pkg[1] == 0x50 && pkg[2] == 0x42 && pkg[3] == 0x4D);

    free(bytecode);
    return 0;
}

/*
 * Test 3: Load and attach to NET_RX hook
 */
TEST(load_and_attach) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_file_to_bytecode("examples/net_rx_filter.js", &bc_len);
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Packet with first byte 0xFF is dropped
 */
TEST(packet_0xff_dropped) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_file_to_bytecode("examples/net_rx_filter.js", &bc_len);
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

    /* Create packet with first byte 0xFF - should be dropped */
    uint8_t packet_data[64];
    memset(packet_data, 0x00, sizeof(packet_data));
    packet_data[0] = 0xFF;  /* This triggers the drop */

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
    ASSERT_EQ(out_rc, MBPF_NET_DROP);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Packet with different first byte is passed
 */
TEST(packet_other_byte_passed) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_file_to_bytecode("examples/net_rx_filter.js", &bc_len);
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

    /* Create packet with first byte NOT 0xFF - should pass */
    uint8_t packet_data[64];
    memset(packet_data, 0xAB, sizeof(packet_data));  /* Any value except 0xFF */

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

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Multiple packets - verify consistent filtering
 */
TEST(multiple_packets_filtering) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_file_to_bytecode("examples/net_rx_filter.js", &bc_len);
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

    int32_t out_rc;
    uint8_t packet_data[64];
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

    /* Test various first bytes */
    struct {
        uint8_t first_byte;
        int32_t expected_result;
    } test_cases[] = {
        { 0xFF, MBPF_NET_DROP },  /* Drop - first byte is 0xFF */
        { 0x00, MBPF_NET_PASS },  /* Pass - first byte is 0x00 */
        { 0x45, MBPF_NET_PASS },  /* Pass - IPv4 header */
        { 0x60, MBPF_NET_PASS },  /* Pass - IPv6 header */
        { 0xFE, MBPF_NET_PASS },  /* Pass - close to 0xFF but not */
        { 0xFF, MBPF_NET_DROP },  /* Drop again - verify consistent */
        { 0x01, MBPF_NET_PASS },  /* Pass - another value */
    };

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        memset(packet_data, 0, sizeof(packet_data));
        packet_data[0] = test_cases[i].first_byte;

        out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, test_cases[i].expected_result);
    }

    /* Verify stats */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 7);
    ASSERT_EQ(stats.successes, 7);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Empty packet (zero length) is passed
 */
TEST(empty_packet_passed) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_file_to_bytecode("examples/net_rx_filter.js", &bc_len);
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

    /* Create empty packet - program checks pkt_len < 1 and returns PASS */
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 0,
        .data_len = 0,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Verify the example code matches the spec
 * The example should implement this logic:
 *   if (ctx.pkt_len < 1) return 0; // PASS
 *   var b0 = ctx.readU8(0);
 *   if (b0 === 0xFF) return 1; // DROP
 *   return 0; // PASS
 */
TEST(verify_spec_behavior) {
    /* Read the example file and verify it contains expected code */
    FILE *f = fopen("examples/net_rx_filter.js", "r");
    ASSERT_NOT_NULL(f);

    char content[4096];
    size_t len = fread(content, 1, sizeof(content) - 1, f);
    content[len] = '\0';
    fclose(f);

    /* Verify key elements of the spec */
    ASSERT(strstr(content, "mbpf_prog") != NULL);
    ASSERT(strstr(content, "ctx.pkt_len") != NULL || strstr(content, "pkt_len") != NULL);
    ASSERT(strstr(content, "ctx.readU8") != NULL || strstr(content, "readU8") != NULL);
    ASSERT(strstr(content, "0xFF") != NULL);
    ASSERT(strstr(content, "return 0") != NULL || strstr(content, "return 1") != NULL);

    return 0;
}

/*
 * Test 9: Packet with 0xFF at non-first position is passed
 */
TEST(0xff_not_at_first_position_passed) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_file_to_bytecode("examples/net_rx_filter.js", &bc_len);
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

    /* Create packet with 0xFF at second position - should pass */
    uint8_t packet_data[64];
    memset(packet_data, 0x00, sizeof(packet_data));
    packet_data[0] = 0x00;  /* First byte is NOT 0xFF */
    packet_data[1] = 0xFF;  /* Second byte is 0xFF but doesn't matter */

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

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: End-to-end with toolchain integration
 * Uses the mbpf-compile and mbpf-assemble tools to create a real package
 */
TEST(toolchain_integration) {
    const char *js_file = "examples/net_rx_filter.js";
    const char *bc_file = "/tmp/test_net_rx_example.qjbc";
    const char *manifest_file = "/tmp/test_net_rx_example_manifest.json";
    const char *mbpf_file = "/tmp/test_net_rx_example.mbpf";

    /* Step 1: Compile JS to bytecode using mbpf-compile */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "./tools/mbpf-compile %s -o %s 2>/dev/null", js_file, bc_file);
    int ret = system(cmd);
    ASSERT_EQ(ret, 0);

    /* Step 2: Create manifest file */
    FILE *f = fopen(manifest_file, "w");
    ASSERT_NOT_NULL(f);
    fprintf(f,
        "{\n"
        "    \"program_name\": \"net_rx_filter_example\",\n"
        "    \"program_version\": \"1.0.0\",\n"
        "    \"hook_type\": 3,\n"
        "    \"hook_ctx_abi_version\": 1,\n"
        "    \"mquickjs_bytecode_version\": 1,\n"
        "    \"target\": {\"word_size\": %u, \"endianness\": %u},\n"
        "    \"mbpf_api_version\": 1,\n"
        "    \"heap_size\": 65536,\n"
        "    \"budgets\": {\"max_steps\": 100000, \"max_helpers\": 1000},\n"
        "    \"capabilities\": [\"CAP_LOG\"]\n"
        "}\n",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
    fclose(f);

    /* Step 3: Assemble .mbpf package */
    snprintf(cmd, sizeof(cmd),
             "./tools/mbpf-assemble -m %s -b %s -o %s 2>/dev/null",
             manifest_file, bc_file, mbpf_file);
    ret = system(cmd);
    ASSERT_EQ(ret, 0);

    /* Step 4: Read the package */
    f = fopen(mbpf_file, "rb");
    ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long pkg_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    ASSERT(pkg_len > 0);

    uint8_t *pkg = malloc(pkg_len);
    ASSERT_NOT_NULL(pkg);
    ASSERT_EQ(fread(pkg, 1, pkg_len, f), (size_t)pkg_len);
    fclose(f);

    /* Step 5: Load and test */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_OK);

    /* Test 0xFF packet - should drop */
    uint8_t drop_packet[64] = {0xFF};
    mbpf_ctx_net_rx_v1_t ctx_drop = {
        .abi_version = 1, .ifindex = 1, .pkt_len = 64, .data_len = 64,
        .l2_proto = 0x0800, .flags = 0, .data = drop_packet, .read_fn = NULL
    };
    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_drop, sizeof(ctx_drop), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_DROP);

    /* Test non-0xFF packet - should pass */
    uint8_t pass_packet[64] = {0x45};  /* IPv4 header */
    mbpf_ctx_net_rx_v1_t ctx_pass = {
        .abi_version = 1, .ifindex = 1, .pkt_len = 64, .data_len = 64,
        .l2_proto = 0x0800, .flags = 0, .data = pass_packet, .read_fn = NULL
    };
    out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_pass, sizeof(ctx_pass), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    mbpf_runtime_shutdown(rt);
    free(pkg);

    /* Cleanup temp files */
    remove(bc_file);
    remove(manifest_file);
    remove(mbpf_file);

    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Example NET_RX Filter Tests\n");
    printf("=====================================\n\n");

    printf("Step 1: Compile JS program to bytecode\n");
    RUN_TEST(compile_example_js_to_bytecode);

    printf("\nStep 2: Package as .mbpf\n");
    RUN_TEST(package_as_mbpf);

    printf("\nStep 3: Load and attach to NET_RX hook\n");
    RUN_TEST(load_and_attach);

    printf("\nStep 4: Verify packet with first byte 0xFF is dropped\n");
    RUN_TEST(packet_0xff_dropped);

    printf("\nStep 5: Verify packet with different first byte is passed\n");
    RUN_TEST(packet_other_byte_passed);

    printf("\nAdditional tests:\n");
    RUN_TEST(multiple_packets_filtering);
    RUN_TEST(empty_packet_passed);
    RUN_TEST(verify_spec_behavior);
    RUN_TEST(0xff_not_at_first_position_passed);

    printf("\nToolchain integration test:\n");
    RUN_TEST(toolchain_integration);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
