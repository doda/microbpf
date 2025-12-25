/*
 * microBPF Deferred Context Snapshot Tests
 *
 * Tests for deferred execution context snapshotting:
 * 1. Queue invocation with context containing packet data
 * 2. Free original context before worker runs
 * 3. Verify worker sees correct snapshotted scalar fields
 * 4. Verify worker sees correct snapshotted buffer data
 * 5. Verify TRUNCATED flag set if data was truncated
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
#define ASSERT_TRUE(x) ASSERT(x)
#define ASSERT_FALSE(x) ASSERT(!(x))

/* Helper to build a minimal valid JSON manifest with TRACEPOINT hook type */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    char json[512];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"context_snapshot_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
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
    const char *js_file = "/tmp/test_ctx_snapshot.js";
    const char *bc_file = "/tmp/test_ctx_snapshot.qjbc";

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
 * Test Cases - deferred-context-snapshot
 * ============================================================================ */

/*
 * Test 1: Queue invocation with context containing packet data
 * This tests that we can queue a context with buffer data attached.
 */
TEST(queue_with_packet_data) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 4096
    };

    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Create tracepoint context with packet data */
    uint8_t packet_data[64];
    for (int i = 0; i < 64; i++) {
        packet_data[i] = (uint8_t)(i * 3);
    }

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 42,
        .timestamp = 1234567890ULL,
        .cpu = 3,
        .pid = 1234,
        .data_len = 64,
        .flags = 0,
        .reserved = 0,
        .data = packet_data,
        .read_fn = NULL
    };

    /* Queue the invocation */
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(mbpf_deferred_pending(queue), 1);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 2: Free original context before worker runs
 * The snapshot should be independent of the original context memory.
 */
TEST(free_original_before_drain) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 4096
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Allocate context and data on heap */
    mbpf_ctx_tracepoint_v1_t *ctx = malloc(sizeof(mbpf_ctx_tracepoint_v1_t));
    ASSERT_NOT_NULL(ctx);

    uint8_t *data = malloc(32);
    ASSERT_NOT_NULL(data);
    for (int i = 0; i < 32; i++) {
        data[i] = (uint8_t)(0xAA + i);
    }

    ctx->abi_version = 1;
    ctx->tracepoint_id = 100;
    ctx->timestamp = 9999999999ULL;
    ctx->cpu = 7;
    ctx->pid = 5678;
    ctx->data_len = 32;
    ctx->flags = 0;
    ctx->reserved = 0;
    ctx->data = data;
    ctx->read_fn = NULL;

    /* Queue the invocation */
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    ctx, sizeof(*ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Free the original context and data - snapshot should remain valid */
    memset(data, 0xFF, 32);  /* Corrupt the data first */
    free(data);
    memset(ctx, 0xFF, sizeof(*ctx));  /* Corrupt the context */
    free(ctx);

    /* Queue should still be valid */
    ASSERT_EQ(mbpf_deferred_pending(queue), 1);

    /* Drain should work (even without programs attached, it clears the queue).
     * The return value is the number of entries drained, not the number of
     * programs that actually executed (which would be 0 since no programs
     * are attached to this hook). */
    int drained = mbpf_drain_deferred(queue);
    ASSERT_EQ(drained, 1);  /* 1 entry drained (mbpf_run was called once) */
    ASSERT_EQ(mbpf_deferred_pending(queue), 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 3: Verify worker sees correct snapshotted scalar fields
 * The program should see the exact values that were in the original context.
 */
TEST(verify_scalar_fields_snapshot) {
    /* JS code that checks all scalar fields */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.tracepoint_id !== 12345) return -1;\n"
        "    if (ctx.cpu !== 11) return -2;\n"
        "    if (ctx.pid !== 99999) return -3;\n"
        "    if (ctx.data_len !== 8) return -4;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Allocate context on heap with specific values */
    mbpf_ctx_tracepoint_v1_t *ctx = malloc(sizeof(mbpf_ctx_tracepoint_v1_t));
    ASSERT_NOT_NULL(ctx);

    uint8_t *data = malloc(8);
    ASSERT_NOT_NULL(data);
    memset(data, 0xAB, 8);

    ctx->abi_version = 1;
    ctx->tracepoint_id = 12345;
    ctx->timestamp = 0;
    ctx->cpu = 11;
    ctx->pid = 99999;
    ctx->data_len = 8;
    ctx->flags = 0;
    ctx->reserved = 0;
    ctx->data = data;
    ctx->read_fn = NULL;

    /* Queue the invocation */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                ctx, sizeof(*ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt and free the original context */
    memset(data, 0xFF, 8);
    free(data);
    memset(ctx, 0xFF, sizeof(*ctx));
    free(ctx);

    /* Drain and verify execution */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 1);

    /* Verify program executed successfully (saw correct scalar fields) */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Verify worker sees correct snapshotted buffer data
 * The program should see the exact bytes that were in the original buffer.
 */
TEST(verify_buffer_data_snapshot) {
    /* JS code that reads buffer data and verifies specific bytes */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(16);\n"
        "    var len = ctx.readBytes(0, 16, buf);\n"
        "    if (len !== 16) return -1;\n"
        "    if (buf[0] !== 0xDE) return -2;\n"
        "    if (buf[1] !== 0xAD) return -3;\n"
        "    if (buf[2] !== 0xBE) return -4;\n"
        "    if (buf[3] !== 0xEF) return -5;\n"
        "    if (buf[4] !== 0xCA) return -6;\n"
        "    if (buf[5] !== 0xFE) return -7;\n"
        "    if (buf[6] !== 0xBA) return -8;\n"
        "    if (buf[7] !== 0xBE) return -9;\n"
        "    /* Verify pattern continues */\n"
        "    for (var i = 8; i < 16; i++) {\n"
        "        if (buf[i] !== (0x10 + i)) return -(10 + i);\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Allocate data on heap with specific pattern */
    uint8_t *data = malloc(16);
    ASSERT_NOT_NULL(data);
    data[0] = 0xDE;
    data[1] = 0xAD;
    data[2] = 0xBE;
    data[3] = 0xEF;
    data[4] = 0xCA;
    data[5] = 0xFE;
    data[6] = 0xBA;
    data[7] = 0xBE;
    for (int i = 8; i < 16; i++) {
        data[i] = (uint8_t)(0x10 + i);
    }

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 1,
        .timestamp = 0,
        .cpu = 0,
        .pid = 0,
        .data_len = 16,
        .flags = 0,
        .reserved = 0,
        .data = data,
        .read_fn = NULL
    };

    /* Queue the invocation */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt and free the original data */
    memset(data, 0x00, 16);
    free(data);

    /* Drain and verify execution */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 1);

    /* Verify program executed successfully (saw correct buffer data) */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Verify TRUNCATED flag set if data was truncated
 * When data exceeds max_snapshot_bytes, flag should be set.
 */
TEST(truncated_flag_set) {
    /* JS code that checks the TRUNCATED flag */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* MBPF_CTX_F_TRUNCATED = 1 */\n"
        "    if ((ctx.flags & 1) === 0) return -1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Create queue with very small max_snapshot_bytes */
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 16  /* Only 16 bytes allowed */
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Create context with large data that will be truncated */
    uint8_t data[128];
    memset(data, 0xAB, sizeof(data));

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 1,
        .timestamp = 0,
        .cpu = 0,
        .pid = 0,
        .data_len = 128,  /* Much larger than max_snapshot_bytes */
        .flags = 0,       /* Start with no flags */
        .reserved = 0,
        .data = data,
        .read_fn = NULL
    };

    /* Queue the invocation - should succeed but truncate */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Drain and verify TRUNCATED flag is set */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 1);

    /* Verify program saw TRUNCATED flag set */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Verify no TRUNCATED flag when data fits
 * When data fits within max_snapshot_bytes, flag should NOT be set.
 */
TEST(no_truncated_flag_when_fits) {
    /* JS code that checks the TRUNCATED flag is NOT set */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* MBPF_CTX_F_TRUNCATED = 1 */\n"
        "    if ((ctx.flags & 1) !== 0) return -1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024  /* Large enough for data */
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Create context with small data that fits */
    uint8_t data[32];
    memset(data, 0xCD, sizeof(data));

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 1,
        .timestamp = 0,
        .cpu = 0,
        .pid = 0,
        .data_len = 32,   /* Fits in max_snapshot_bytes */
        .flags = 0,
        .reserved = 0,
        .data = data,
        .read_fn = NULL
    };

    /* Queue the invocation */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Drain and verify TRUNCATED flag is NOT set */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 1);

    /* Verify program saw TRUNCATED flag NOT set */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Truncated data is partially readable
 * When data is truncated, the first max_snapshot_bytes should be valid.
 */
TEST(truncated_data_partially_readable) {
    /* JS code that reads the truncated data */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(16);\n"
        "    var len = ctx.readBytes(0, 16, buf);\n"
        "    if (len !== 16) return -1;\n"
        "    /* Verify first 16 bytes have expected pattern */\n"
        "    for (var i = 0; i < 16; i++) {\n"
        "        if (buf[i] !== i) return -(10 + i);\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 16  /* Truncate to 16 bytes */
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Create context with pattern data larger than snapshot limit */
    uint8_t data[64];
    for (int i = 0; i < 64; i++) {
        data[i] = (uint8_t)i;  /* 0, 1, 2, ... 63 */
    }

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 1,
        .timestamp = 0,
        .cpu = 0,
        .pid = 0,
        .data_len = 64,
        .flags = 0,
        .reserved = 0,
        .data = data,
        .read_fn = NULL
    };

    /* Queue the invocation */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Drain and verify execution */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 1);

    /* Verify program could read the truncated data */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Snapshot via read_fn works correctly
 * Data accessed via read_fn should be snapshotted just like direct pointer.
 */
static int test_read_fn(const void *ctx_blob, uint32_t off, uint32_t len, uint8_t *dst) {
    (void)ctx_blob;  /* Unused */
    /* Simple read function that provides patterned data */
    for (uint32_t i = 0; i < len; i++) {
        dst[i] = (uint8_t)(0xF0 + ((off + i) & 0x0F));
    }
    return (int)len;
}

TEST(snapshot_via_read_fn) {
    /* JS code that verifies read_fn data was snapshotted */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(8);\n"
        "    var len = ctx.readBytes(0, 8, buf);\n"
        "    if (len !== 8) return -1;\n"
        "    /* Verify pattern from read_fn: 0xF0, 0xF1, ... */\n"
        "    for (var i = 0; i < 8; i++) {\n"
        "        if (buf[i] !== (0xF0 + i)) return -(10 + i);\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Create context with read_fn instead of data pointer */
    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 1,
        .timestamp = 0,
        .cpu = 0,
        .pid = 0,
        .data_len = 8,
        .flags = 0,
        .reserved = 0,
        .data = NULL,  /* No direct data */
        .read_fn = test_read_fn  /* Use read function */
    };

    /* Queue the invocation */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Drain and verify execution */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 1);

    /* Verify program saw data from read_fn */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Timer context snapshot preserves all fields
 * TIMER contexts have no data buffer but should preserve scalar fields.
 */
TEST(timer_context_snapshot) {
    /* Build TIMER package */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.timer_id !== 777) return -1;\n"
        "    if (ctx.period_us !== 5000) return -2;\n"
        "    if (ctx.invocation_count !== 42) return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Create TIMER package */
    char timer_manifest[512];
    snprintf(timer_manifest, sizeof(timer_manifest),
        "{"
        "\"program_name\":\"timer_snapshot_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":2,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
    size_t manifest_len = strlen(timer_manifest);

    uint8_t pkg[8192];
    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;

    uint8_t *p = pkg;
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    memcpy(p, timer_manifest, manifest_len);
    p += manifest_len;
    memcpy(p, bytecode, bc_len);
    p += bc_len;
    size_t pkg_len = (size_t)(p - pkg);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Allocate timer context on heap */
    mbpf_ctx_timer_v1_t *ctx = malloc(sizeof(mbpf_ctx_timer_v1_t));
    ASSERT_NOT_NULL(ctx);

    ctx->abi_version = 1;
    ctx->timer_id = 777;
    ctx->period_us = 5000;
    ctx->flags = 0;
    ctx->reserved = 0;
    ctx->invocation_count = 42;
    ctx->timestamp = 1234567890ULL;

    /* Queue the invocation */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TIMER,
                                MBPF_HOOK_TIMER,
                                ctx, sizeof(*ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Corrupt and free original context */
    memset(ctx, 0xFF, sizeof(*ctx));
    free(ctx);

    /* Drain and verify execution */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 1);

    /* Verify program saw correct timer fields */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Multiple queued invocations with different data
 * Each snapshot should be independent with its own data.
 */
TEST(multiple_invocations_independent_data) {
    /* JS code that returns the first byte of data as result */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(1);\n"
        "    var len = ctx.readBytes(0, 1, buf);\n"
        "    if (len !== 1) return -1;\n"
        "    return buf[0];\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Queue 5 invocations with different first bytes */
    for (int i = 0; i < 5; i++) {
        uint8_t *data = malloc(4);
        ASSERT_NOT_NULL(data);
        data[0] = (uint8_t)(0x10 + i);  /* 0x10, 0x11, 0x12, 0x13, 0x14 */
        data[1] = 0;
        data[2] = 0;
        data[3] = 0;

        mbpf_ctx_tracepoint_v1_t ctx = {
            .abi_version = 1,
            .tracepoint_id = i,
            .timestamp = 0,
            .cpu = 0,
            .pid = 0,
            .data_len = 4,
            .flags = 0,
            .reserved = 0,
            .data = data,
            .read_fn = NULL
        };

        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);

        /* Free immediately after queuing */
        free(data);
    }

    ASSERT_EQ(mbpf_deferred_pending(queue), 5);

    /* Drain all */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 5);

    /* All invocations should have succeeded */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 5);
    ASSERT_EQ(stats.successes, 5);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Main entry point
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Deferred Context Snapshot Tests\n");
    printf("=========================================\n\n");

    printf("Context queueing:\n");
    RUN_TEST(queue_with_packet_data);
    RUN_TEST(free_original_before_drain);

    printf("\nScalar field snapshots:\n");
    RUN_TEST(verify_scalar_fields_snapshot);
    RUN_TEST(timer_context_snapshot);

    printf("\nBuffer data snapshots:\n");
    RUN_TEST(verify_buffer_data_snapshot);
    RUN_TEST(snapshot_via_read_fn);
    RUN_TEST(multiple_invocations_independent_data);

    printf("\nTruncation handling:\n");
    RUN_TEST(truncated_flag_set);
    RUN_TEST(no_truncated_flag_when_fits);
    RUN_TEST(truncated_data_partially_readable);

    printf("\n=========================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
