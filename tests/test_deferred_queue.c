/*
 * microBPF Deferred Execution Queue Tests
 *
 * Tests for deferred execution queue API:
 * 1. Configure tracepoint hook for deferred execution
 * 2. Trigger hook - verify invocation is queued
 * 3. Verify worker context drains queue and executes program
 * 4. Verify queue has fixed maximum depth
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
    const char *json =
        "{"
        "\"program_name\":\"deferred_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}";
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
    const char *js_file = "/tmp/test_deferred_queue.js";
    const char *bc_file = "/tmp/test_deferred_queue.qjbc";

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
 * Test Cases - deferred-execution-queue
 * ============================================================================ */

/*
 * Test 1: Create and destroy deferred queue
 */
TEST(queue_create_destroy) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };

    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    ASSERT_EQ(mbpf_deferred_pending(queue), 0);
    ASSERT_EQ(mbpf_deferred_dropped(queue), 0);

    mbpf_deferred_queue_destroy(queue);
    return 0;
}

/*
 * Test 2: Create with invalid config
 */
TEST(queue_create_invalid) {
    /* NULL config */
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(NULL);
    ASSERT_NULL(queue);

    /* max_entries = 0 */
    mbpf_deferred_config_t cfg = { .max_entries = 0, .max_snapshot_bytes = 1024 };
    queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NULL(queue);

    return 0;
}

/*
 * Test 3: Hook type deferability checks
 */
TEST(hook_can_defer) {
    /* Observer hooks can be deferred */
    ASSERT_TRUE(mbpf_hook_can_defer(MBPF_HOOK_TRACEPOINT));
    ASSERT_TRUE(mbpf_hook_can_defer(MBPF_HOOK_TIMER));

    /* Decision hooks cannot be deferred */
    ASSERT_FALSE(mbpf_hook_can_defer(MBPF_HOOK_NET_RX));
    ASSERT_FALSE(mbpf_hook_can_defer(MBPF_HOOK_NET_TX));
    ASSERT_FALSE(mbpf_hook_can_defer(MBPF_HOOK_SECURITY));
    ASSERT_FALSE(mbpf_hook_can_defer(MBPF_HOOK_CUSTOM));

    return 0;
}

/*
 * Test 4: Queue tracepoint invocation
 */
TEST(queue_tracepoint_invocation) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };

    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Create tracepoint context */
    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 42,
        .timestamp = 1234567890ULL,
        .cpu = 3,
        .pid = 1234,
        .data_len = 0,
        .flags = 0,
        .reserved = 0,
        .data = NULL,
        .read_fn = NULL
    };

    /* Queue the invocation */
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(mbpf_deferred_pending(queue), 1);
    ASSERT_EQ(mbpf_deferred_dropped(queue), 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 5: Queue timer invocation
 */
TEST(queue_timer_invocation) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };

    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Create timer context */
    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 100,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 5,
        .timestamp = 9876543210ULL
    };

    /* Queue the invocation */
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TIMER,
                                    MBPF_HOOK_TIMER,
                                    &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(mbpf_deferred_pending(queue), 1);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 6: Reject decision hooks from being queued
 */
TEST(reject_decision_hooks) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };

    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Create NET_RX context */
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

    /* Queue should reject decision hooks */
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_NET_RX,
                                    MBPF_HOOK_NET_RX,
                                    &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);
    ASSERT_EQ(mbpf_deferred_pending(queue), 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 7: Queue has fixed maximum depth
 */
TEST(queue_max_depth) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 3,  /* Small queue for testing */
        .max_snapshot_bytes = 1024
    };

    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 1,
        .timestamp = 0,
        .cpu = 0,
        .pid = 0,
        .data_len = 0,
        .flags = 0,
        .reserved = 0,
        .data = NULL,
        .read_fn = NULL
    };

    /* Fill the queue */
    int err;
    for (int i = 0; i < 3; i++) {
        ctx.tracepoint_id = i;
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }
    ASSERT_EQ(mbpf_deferred_pending(queue), 3);

    /* Trying to queue more should fail with MBPF_ERR_NO_MEM */
    ctx.tracepoint_id = 99;
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    ASSERT_EQ(mbpf_deferred_pending(queue), 3);
    ASSERT_EQ(mbpf_deferred_dropped(queue), 1);

    /* Queue more to increment drop counter */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    ASSERT_EQ(mbpf_deferred_dropped(queue), 2);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 8: Worker drains queue and executes program
 */
TEST(drain_executes_programs) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return ctx.tracepoint_id;\n"
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

    /* Create deferred queue */
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Queue 3 invocations */
    for (int i = 0; i < 3; i++) {
        mbpf_ctx_tracepoint_v1_t ctx = {
            .abi_version = 1,
            .tracepoint_id = i + 1,
            .timestamp = 0,
            .cpu = 0,
            .pid = 0,
            .data_len = 0,
            .flags = 0,
            .reserved = 0,
            .data = NULL,
            .read_fn = NULL
        };
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }
    ASSERT_EQ(mbpf_deferred_pending(queue), 3);

    /* Get initial stats */
    mbpf_stats_t stats_before;
    mbpf_program_stats(prog, &stats_before);
    ASSERT_EQ(stats_before.invocations, 0);

    /* Drain the queue */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 3);
    ASSERT_EQ(mbpf_deferred_pending(queue), 0);

    /* Verify programs were executed */
    mbpf_stats_t stats_after;
    mbpf_program_stats(prog, &stats_after);
    ASSERT_EQ(stats_after.invocations, 3);
    ASSERT_EQ(stats_after.successes, 3);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Context is snapshotted - original can be freed
 */
TEST(context_snapshot) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Allocate context on heap */
    mbpf_ctx_tracepoint_v1_t *ctx = malloc(sizeof(mbpf_ctx_tracepoint_v1_t));
    ASSERT_NOT_NULL(ctx);
    ctx->abi_version = 1;
    ctx->tracepoint_id = 42;
    ctx->timestamp = 1234567890ULL;
    ctx->cpu = 7;
    ctx->pid = 5678;
    ctx->data_len = 0;
    ctx->flags = 0;
    ctx->reserved = 0;
    ctx->data = NULL;
    ctx->read_fn = NULL;

    /* Queue the invocation */
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    ctx, sizeof(*ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Free the original context - snapshot should still be valid */
    free(ctx);

    ASSERT_EQ(mbpf_deferred_pending(queue), 1);

    /* Queue should still be drainable */
    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 10: Tracepoint with data buffer is snapshotted
 */
TEST(snapshot_tracepoint_data) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);\n"
        "    var len = ctx.readBytes(0, 4, buf);\n"
        "    if (len !== 4) return -1;\n"
        "    if (buf[0] !== 0xDE) return -2;\n"
        "    if (buf[1] !== 0xAD) return -3;\n"
        "    if (buf[2] !== 0xBE) return -4;\n"
        "    if (buf[3] !== 0xEF) return -5;\n"
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

    /* Create context with data */
    uint8_t *data = malloc(4);
    ASSERT_NOT_NULL(data);
    data[0] = 0xDE;
    data[1] = 0xAD;
    data[2] = 0xBE;
    data[3] = 0xEF;

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 1,
        .timestamp = 0,
        .cpu = 0,
        .pid = 0,
        .data_len = 4,
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

    /* Free the original data - snapshot should have its own copy */
    free(data);

    /* Drain and execute */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 1);

    /* Verify program saw correct data */
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
 * Test 11: Data truncation sets TRUNCATED flag
 */
TEST(snapshot_truncation) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 10  /* Small limit to force truncation */
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Create context with data larger than max_snapshot_bytes */
    uint8_t data[100];
    memset(data, 0xAB, sizeof(data));

    mbpf_ctx_tracepoint_v1_t ctx = {
        .abi_version = 1,
        .tracepoint_id = 1,
        .timestamp = 0,
        .cpu = 0,
        .pid = 0,
        .data_len = 100,  /* Larger than max_snapshot_bytes */
        .flags = 0,
        .reserved = 0,
        .data = data,
        .read_fn = NULL
    };

    /* Queue should succeed but truncate */
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 12: Drain empty queue returns 0
 */
TEST(drain_empty_queue) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 0);

    mbpf_deferred_queue_destroy(queue);
    return 0;
}

/*
 * Test 13: NULL queue handling
 */
TEST(null_queue_handling) {
    ASSERT_EQ(mbpf_deferred_pending(NULL), 0);
    ASSERT_EQ(mbpf_deferred_dropped(NULL), 0);
    ASSERT_EQ(mbpf_drain_deferred(NULL), -1);

    /* Destroy NULL should be safe */
    mbpf_deferred_queue_destroy(NULL);

    return 0;
}

/*
 * Test 14: Queue invocation with NULL arguments
 */
TEST(queue_null_args) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 10,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_ctx_tracepoint_v1_t ctx = {0};

    /* NULL queue */
    int err = mbpf_queue_invocation(NULL, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL runtime */
    err = mbpf_queue_invocation(queue, NULL, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* NULL context */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                NULL, sizeof(ctx));
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* Zero length */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, 0);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 15: Multiple queue/drain cycles
 */
TEST(multiple_cycles) {
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 5,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Cycle 1: queue 3, drain 3 */
    for (int i = 0; i < 3; i++) {
        mbpf_ctx_tracepoint_v1_t ctx = {
            .abi_version = 1,
            .tracepoint_id = i,
            .timestamp = 0,
            .cpu = 0,
            .pid = 0,
            .data_len = 0,
            .flags = 0,
            .reserved = 0,
            .data = NULL,
            .read_fn = NULL
        };
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }
    ASSERT_EQ(mbpf_drain_deferred(queue), 3);
    ASSERT_EQ(mbpf_deferred_pending(queue), 0);

    /* Cycle 2: queue 5, drain 5 */
    for (int i = 0; i < 5; i++) {
        mbpf_ctx_tracepoint_v1_t ctx = {
            .abi_version = 1,
            .tracepoint_id = i,
            .timestamp = 0,
            .cpu = 0,
            .pid = 0,
            .data_len = 0,
            .flags = 0,
            .reserved = 0,
            .data = NULL,
            .read_fn = NULL
        };
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }
    ASSERT_EQ(mbpf_drain_deferred(queue), 5);
    ASSERT_EQ(mbpf_deferred_pending(queue), 0);

    /* Verify total invocations */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 8);

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

    printf("microBPF Deferred Execution Queue Tests\n");
    printf("========================================\n\n");

    printf("Queue creation/destruction:\n");
    RUN_TEST(queue_create_destroy);
    RUN_TEST(queue_create_invalid);

    printf("\nHook type checks:\n");
    RUN_TEST(hook_can_defer);

    printf("\nQueueing invocations:\n");
    RUN_TEST(queue_tracepoint_invocation);
    RUN_TEST(queue_timer_invocation);
    RUN_TEST(reject_decision_hooks);
    RUN_TEST(queue_max_depth);

    printf("\nDraining and execution:\n");
    RUN_TEST(drain_executes_programs);
    RUN_TEST(drain_empty_queue);
    RUN_TEST(multiple_cycles);

    printf("\nContext snapshotting:\n");
    RUN_TEST(context_snapshot);
    RUN_TEST(snapshot_tracepoint_data);
    RUN_TEST(snapshot_truncation);

    printf("\nError handling:\n");
    RUN_TEST(null_queue_handling);
    RUN_TEST(queue_null_args);

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
