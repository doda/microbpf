/*
 * microBPF Integration Tests - Full Load-Run Cycle
 *
 * Tests the complete lifecycle of a microBPF program:
 * 1. Create complete .mbpf package
 * 2. Load, attach, run, detach, unload
 * 3. Verify expected behavior at each step
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include "test_utils.h"
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
#define ASSERT_OK(err) ASSERT((err) == MBPF_OK)

/* Helper to build a .mbpf package from bytecode and manifest */
static size_t build_test_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  const char *manifest, size_t manifest_len) {
    if (cap < 256) return 0;

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
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 1: BYTECODE (type=2) */
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

/* Compile JS source to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_source, size_t *out_len) {
    const char *src_file = "/tmp/test_integration_src.js";
    const char *bc_file = "/tmp/test_integration.qjbc";

    FILE *f = fopen(src_file, "w");
    if (!f) return NULL;
    fprintf(f, "%s", js_source);
    fclose(f);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "./deps/mquickjs/mqjs --no-column -o %s %s 2>/dev/null",
             bc_file, src_file);
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

/* Build a manifest for TRACEPOINT hook */
static size_t build_tracepoint_manifest(char *buf, size_t cap) {
    int len = snprintf(buf, cap,
        "{"
        "\"program_name\":\"integration_test\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}", mbpf_runtime_word_size(), mbpf_runtime_endianness());
    if (len < 0 || (size_t)len >= cap) return 0;
    return (size_t)len;
}

/* Build a manifest for NET_RX hook */
static size_t build_net_rx_manifest(char *buf, size_t cap, const char *name) {
    int len = snprintf(buf, cap,
        "{"
        "\"program_name\":\"%s\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":3,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}", name, mbpf_runtime_word_size(), mbpf_runtime_endianness());
    if (len < 0 || (size_t)len >= cap) return 0;
    return (size_t)len;
}

/* ============================================================================
 * Test Cases - Step 1: Create complete .mbpf package
 * ============================================================================ */

/*
 * Create a minimal valid .mbpf package from JS source
 */
TEST(create_package_from_js) {
    const char *js_source = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);
    ASSERT(bc_len > 0);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    /* Verify .mbpf magic header */
    ASSERT(pkg[0] == 0x46 && pkg[1] == 0x50 && pkg[2] == 0x42 && pkg[3] == 0x4D);

    free(bytecode);
    return 0;
}

/*
 * Create .mbpf package with program returning non-zero
 */
TEST(create_package_returning_value) {
    const char *js_source = "function mbpf_prog(ctx) { return 42; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - Step 2: Load, attach, run, detach, unload
 * ============================================================================ */

/*
 * Full lifecycle: load -> verify state
 */
TEST(load_verifies_program_state) {
    const char *js_source = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);
    ASSERT_NOT_NULL(prog);

    /* Verify program has instances */
    uint32_t inst_count = mbpf_program_instance_count(prog);
    ASSERT(inst_count > 0);

    /* Verify stats are initialized */
    mbpf_stats_t stats;
    err = mbpf_program_stats(prog, &stats);
    ASSERT_OK(err);
    ASSERT_EQ(stats.invocations, 0);
    ASSERT_EQ(stats.successes, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Full lifecycle: load -> attach -> verify attached
 */
TEST(attach_verifies_hook_binding) {
    const char *js_source = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    /* Attach to tracepoint hook */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Double attach should fail */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_ALREADY_ATTACHED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Full lifecycle: load -> attach -> run -> verify execution
 */
TEST(run_executes_program) {
    const char *js_source = "function mbpf_prog(ctx) { return 42; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Create tracepoint context */
    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 123,
        .timestamp = 1000000,
        .cpu = 0,
        .pid = 0,
        .data_len = 0,
        .flags = 0,
        .reserved = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 42);

    /* Verify stats updated */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Full lifecycle: load -> attach -> run -> detach -> verify no more execution
 */
TEST(detach_stops_execution) {
    const char *js_source = "function mbpf_prog(ctx) { return 42; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Run once to verify attached */
    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 123,
        .timestamp = 1000000,
        .cpu = 0,
        .pid = 0,
        .data_len = 0,
        .flags = 0,
        .reserved = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 42);

    /* Detach */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Run again - should have no effect since detached */
    out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    /* When no program attached, run returns success but no programs execute */
    ASSERT_OK(err);
    /* out_rc may be 0 or unchanged when no programs run */

    /* Verify stats: only 1 invocation (from before detach) */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Full lifecycle: load -> attach -> run -> detach -> unload -> verify cleanup
 */
TEST(unload_cleans_up) {
    const char *js_source = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 123,
        .timestamp = 1000000,
        .cpu = 0,
        .pid = 0,
        .data_len = 0,
        .flags = 0,
        .reserved = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_program_unload(rt, prog);
    ASSERT_OK(err);

    /* Double unload should fail or be handled gracefully */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_ERR_ALREADY_UNLOADED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - Step 3: Verify expected behavior at each step
 * ============================================================================ */

/*
 * Verify return value semantics through full cycle
 */
TEST(return_value_through_cycle) {
    /* Test different return values */
    struct {
        const char *js_source;
        int32_t expected_rc;
    } test_cases[] = {
        { "function mbpf_prog(ctx) { return 0; }", 0 },
        { "function mbpf_prog(ctx) { return 1; }", 1 },
        { "function mbpf_prog(ctx) { return -1; }", -1 },
        { "function mbpf_prog(ctx) { return 255; }", 255 },
        { "function mbpf_prog(ctx) { return 12345; }", 12345 },
    };

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        size_t bc_len;
        uint8_t *bytecode = compile_js_to_bytecode(test_cases[i].js_source, &bc_len);
        ASSERT_NOT_NULL(bytecode);

        char manifest[512];
        size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
        ASSERT(manifest_len > 0);

        uint8_t pkg[8192];
        size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                             manifest, manifest_len);
        ASSERT(pkg_len > 0);

        mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
        ASSERT_NOT_NULL(rt);

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
        ASSERT_OK(err);

        err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
        ASSERT_OK(err);

        mbpf_ctx_tracepoint_v1_t ctx = {
            .abi_version = 1,
            .tracepoint_id = 123,
            .timestamp = 1000000,
            .cpu = 0,
            .pid = 0,
            .data_len = 0,
            .flags = 0,
            .reserved = 0,
            .data = NULL,
            .read_fn = NULL
        };

        int32_t out_rc = -999;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_OK(err);
        ASSERT_EQ(out_rc, test_cases[i].expected_rc);

        mbpf_runtime_shutdown(rt);
        free(bytecode);
    }

    return 0;
}

/*
 * NET_RX hook full lifecycle with decision making
 */
TEST(net_rx_full_lifecycle) {
    const char *js_source =
        "function mbpf_prog(ctx) {\n"
        "  if (ctx.pkt_len < 1) return 0;\n"  /* PASS */
        "  var b0 = ctx.readU8(0);\n"
        "  if (b0 === 0xFF) return 1;\n"      /* DROP */
        "  return 0;\n"                       /* PASS */
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_net_rx_manifest(manifest, sizeof(manifest), "net_rx_test");
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_OK(err);

    /* Test packet with first byte 0xFF - should DROP */
    uint8_t drop_pkt[64] = {0xFF};
    mbpf_ctx_net_rx_v1_t ctx_drop = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = drop_pkt,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_drop, sizeof(ctx_drop), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, MBPF_NET_DROP);

    /* Test packet with first byte 0x45 - should PASS */
    uint8_t pass_pkt[64] = {0x45};
    mbpf_ctx_net_rx_v1_t ctx_pass = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = pass_pkt,
        .read_fn = NULL
    };

    out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_pass, sizeof(ctx_pass), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    /* Detach and verify */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_OK(err);

    /* Verify stats after complete cycle */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 2);
    ASSERT_EQ(stats.successes, 2);
    ASSERT_EQ(stats.exceptions, 0);

    err = mbpf_program_unload(rt, prog);
    ASSERT_OK(err);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Multiple programs on different hooks
 */
TEST(multiple_programs_lifecycle) {
    /* Program 1: TRACEPOINT hook returns 111 */
    const char *js1 = "function mbpf_prog(ctx) { return 111; }";

    /* Program 2: TRACEPOINT hook returns 222 */
    const char *js2 = "function mbpf_prog(ctx) { return 222; }";

    size_t bc1_len, bc2_len;
    uint8_t *bc1 = compile_js_to_bytecode(js1, &bc1_len);
    uint8_t *bc2 = compile_js_to_bytecode(js2, &bc2_len);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);

    char manifest1[512], manifest2[512];
    size_t m1_len = build_tracepoint_manifest(manifest1, sizeof(manifest1));
    size_t m2_len = build_tracepoint_manifest(manifest2, sizeof(manifest2));
    ASSERT(m1_len > 0);
    ASSERT(m2_len > 0);

    uint8_t pkg1[8192], pkg2[8192];
    size_t pkg1_len = build_test_package(pkg1, sizeof(pkg1), bc1, bc1_len,
                                          manifest1, m1_len);
    size_t pkg2_len = build_test_package(pkg2, sizeof(pkg2), bc2, bc2_len,
                                          manifest2, m2_len);
    ASSERT(pkg1_len > 0);
    ASSERT(pkg2_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Load both programs */
    mbpf_program_t *prog1 = NULL, *prog2 = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg1_len, NULL, &prog1);
    ASSERT_OK(err);
    err = mbpf_program_load(rt, pkg2, pkg2_len, NULL, &prog2);
    ASSERT_OK(err);

    /* Attach both to the same hook */
    err = mbpf_program_attach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);
    err = mbpf_program_attach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Run hook - both programs should execute */
    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 123,
        .timestamp = 1000000,
        .cpu = 0,
        .pid = 0,
        .data_len = 0,
        .flags = 0,
        .reserved = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    /* Return code may be from either program or combined */

    /* Verify both programs ran */
    mbpf_stats_t stats1, stats2;
    mbpf_program_stats(prog1, &stats1);
    mbpf_program_stats(prog2, &stats2);
    ASSERT_EQ(stats1.invocations, 1);
    ASSERT_EQ(stats2.invocations, 1);

    /* Detach and unload in order */
    err = mbpf_program_detach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);
    err = mbpf_program_detach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    err = mbpf_program_unload(rt, prog1);
    ASSERT_OK(err);
    err = mbpf_program_unload(rt, prog2);
    ASSERT_OK(err);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/*
 * Exception handling through full cycle
 */
TEST(exception_handling_lifecycle) {
    const char *js_source = "function mbpf_prog(ctx) { throw new Error('test'); }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 123,
        .timestamp = 1000000,
        .cpu = 0,
        .pid = 0,
        .data_len = 0,
        .flags = 0,
        .reserved = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    /* Run should still succeed but exception counted */
    ASSERT_OK(err);

    /* Verify exception was counted */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.exceptions, 1);
    ASSERT_EQ(stats.successes, 0);

    /* Cleanup should still work */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);
    err = mbpf_program_unload(rt, prog);
    ASSERT_OK(err);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Repeated load/unload cycles
 */
TEST(repeated_load_unload_cycles) {
    const char *js_source = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    for (int cycle = 0; cycle < 5; cycle++) {
        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
        ASSERT_OK(err);

        err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
        ASSERT_OK(err);

        mbpf_ctx_tracepoint_v1_t ctx = {
            .abi_version = 1,
            .tracepoint_id = 123,
            .timestamp = 1000000,
            .cpu = 0,
            .pid = 0,
            .data_len = 0,
            .flags = 0,
            .reserved = 0,
            .data = NULL,
            .read_fn = NULL
        };

        int32_t out_rc;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
        ASSERT_OK(err);

        err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
        ASSERT_OK(err);

        err = mbpf_program_unload(rt, prog);
        ASSERT_OK(err);
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Context data access through full cycle
 */
TEST(context_data_access_lifecycle) {
    const char *js_source =
        "function mbpf_prog(ctx) {\n"
        "  var sum = 0;\n"
        "  for (var i = 0; i < ctx.data_len && i < 4; i++) {\n"
        "    sum += ctx.readU8(i);\n"
        "  }\n"
        "  return sum;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_net_rx_manifest(manifest, sizeof(manifest), "ctx_access_test");
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_OK(err);

    /* Test with packet containing 1, 2, 3, 4 - sum should be 10 */
    uint8_t pkt[64] = {1, 2, 3, 4};
    mbpf_ctx_net_rx_v1_t ctx = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = 64,
        .data_len = 64,
        .l2_proto = 0x0800,
        .flags = 0,
        .data = pkt,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);
    ASSERT_EQ(out_rc, 10);

    err = mbpf_program_detach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_OK(err);
    err = mbpf_program_unload(rt, prog);
    ASSERT_OK(err);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Full cycle with runtime shutdown (implicit cleanup)
 */
TEST(runtime_shutdown_cleanup) {
    const char *js_source = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    /* Run once */
    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 123,
        .timestamp = 1000000,
        .cpu = 0,
        .pid = 0,
        .data_len = 0,
        .flags = 0,
        .reserved = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_OK(err);

    /* Shutdown without explicit detach/unload - should cleanup automatically */
    mbpf_runtime_shutdown(rt);

    free(bytecode);
    return 0;
}

/*
 * Error handling - mismatched hook type
 */
TEST(error_hook_mismatch) {
    const char *js_source = "function mbpf_prog(ctx) { return 0; }";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_source, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Manifest specifies TRACEPOINT hook */
    char manifest[512];
    size_t manifest_len = build_tracepoint_manifest(manifest, sizeof(manifest));
    ASSERT(manifest_len > 0);

    uint8_t pkg[8192];
    size_t pkg_len = build_test_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         manifest, manifest_len);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_OK(err);

    /* Try to attach to NET_RX hook - should fail with hook mismatch */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    /* Attaching to correct hook should still work */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_OK(err);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF Integration Tests - Full Load-Run Cycle\n");
    printf("=================================================\n\n");

    printf("Step 1: Create complete .mbpf package\n");
    RUN_TEST(create_package_from_js);
    RUN_TEST(create_package_returning_value);

    printf("\nStep 2: Load, attach, run, detach, unload\n");
    RUN_TEST(load_verifies_program_state);
    RUN_TEST(attach_verifies_hook_binding);
    RUN_TEST(run_executes_program);
    RUN_TEST(detach_stops_execution);
    RUN_TEST(unload_cleans_up);

    printf("\nStep 3: Verify expected behavior at each step\n");
    RUN_TEST(return_value_through_cycle);
    RUN_TEST(net_rx_full_lifecycle);
    RUN_TEST(multiple_programs_lifecycle);
    RUN_TEST(exception_handling_lifecycle);
    RUN_TEST(repeated_load_unload_cycles);
    RUN_TEST(context_data_access_lifecycle);
    RUN_TEST(runtime_shutdown_cleanup);
    RUN_TEST(error_hook_mismatch);

    printf("\n=================================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
