/*
 * microBPF Deferred Execution Backpressure Tests
 *
 * Tests for deferred execution queue backpressure:
 * 1. Fill deferred queue to capacity
 * 2. Trigger additional hooks
 * 3. Verify invocations are dropped (not blocking)
 * 4. Verify per-program/per-hook drop counter is incremented
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
        "\"program_name\":\"backpressure_test\","
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
    const char *js_file = "/tmp/test_backpressure.js";
    const char *bc_file = "/tmp/test_backpressure.qjbc";

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
 * Test Cases - deferred-execution-backpressure
 * ============================================================================ */

/*
 * Test 1: Fill queue to capacity, verify drops are counted
 */
TEST(queue_full_drops_counted) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 5,  /* Small queue for testing */
        .max_snapshot_bytes = 1024
    };

    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Create tracepoint context */
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

    /* Fill the queue to capacity */
    for (int i = 0; i < 5; i++) {
        int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                        MBPF_HOOK_TRACEPOINT,
                                        &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }
    ASSERT_EQ(mbpf_deferred_pending(queue), 5);
    ASSERT_EQ(mbpf_deferred_dropped(queue), 0);

    /* Try to queue more - should be dropped */
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    ASSERT_EQ(mbpf_deferred_pending(queue), 5);  /* Still 5 */
    ASSERT_EQ(mbpf_deferred_dropped(queue), 1);  /* 1 dropped */

    /* Queue more drops */
    for (int i = 0; i < 10; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    }
    ASSERT_EQ(mbpf_deferred_dropped(queue), 11);  /* 1 + 10 = 11 dropped */

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 2: Verify dropping is non-blocking (immediate return)
 */
TEST(drops_are_non_blocking) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 1,  /* Minimal queue */
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
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Dropping should be immediate - just verify it returns quickly.
     * We queue many drops and they should all return quickly. */
    for (int i = 0; i < 1000; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    }
    ASSERT_EQ(mbpf_deferred_dropped(queue), 1000);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 3: Per-program drop counter is incremented for attached programs
 */
TEST(per_program_drop_counter) {
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

    /* Check initial stats */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.deferred_dropped, 0);

    /* Create a small deferred queue */
    mbpf_deferred_config_t cfg = {
        .max_entries = 3,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

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
    for (int i = 0; i < 3; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Now queue more to trigger drops */
    for (int i = 0; i < 5; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    }

    /* Verify per-program counter was incremented */
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.deferred_dropped, 5);

    /* Verify global counter also incremented */
    ASSERT_EQ(mbpf_deferred_dropped(queue), 5);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Multiple programs attached to same hook, all get drop counters
 */
TEST(multiple_programs_drop_counter) {
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

    /* Load and attach two programs */
    mbpf_program_t *prog1 = NULL;
    mbpf_program_t *prog2 = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog1);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog2);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 2,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

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
    for (int i = 0; i < 2; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Trigger 3 drops */
    for (int i = 0; i < 3; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    }

    /* Both programs should have their deferred_dropped counters incremented */
    mbpf_stats_t stats1, stats2;
    mbpf_program_stats(prog1, &stats1);
    mbpf_program_stats(prog2, &stats2);
    ASSERT_EQ(stats1.deferred_dropped, 3);
    ASSERT_EQ(stats2.deferred_dropped, 3);

    /* Global counter shows total drops (3, not 6) */
    ASSERT_EQ(mbpf_deferred_dropped(queue), 3);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Unattached program doesn't get drop counter incremented
 */
TEST(unattached_program_no_drops) {
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

    /* Load two programs, only attach one */
    mbpf_program_t *attached = NULL;
    mbpf_program_t *unattached = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &attached);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, pkg, pkg_len, NULL, &unattached);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, attached, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);
    /* unattached is NOT attached */

    mbpf_deferred_config_t cfg = {
        .max_entries = 1,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

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

    /* Fill queue */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_OK);

    /* Trigger drops */
    for (int i = 0; i < 5; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    }

    /* Only attached program should have drops */
    mbpf_stats_t attached_stats, unattached_stats;
    mbpf_program_stats(attached, &attached_stats);
    mbpf_program_stats(unattached, &unattached_stats);
    ASSERT_EQ(attached_stats.deferred_dropped, 5);
    ASSERT_EQ(unattached_stats.deferred_dropped, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Different hooks - drops only affect matching hook's programs
 */
TEST(per_hook_drop_isolation) {
    const char *js_code_tracepoint =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode_tp = compile_js_to_bytecode(js_code_tracepoint, &bc_len);
    ASSERT_NOT_NULL(bytecode_tp);

    /* Build TRACEPOINT package */
    uint8_t pkg_tp[8192];
    size_t pkg_tp_len = build_mbpf_package(pkg_tp, sizeof(pkg_tp), bytecode_tp, bc_len);
    ASSERT(pkg_tp_len > 0);

    /* Build TIMER package with modified manifest */
    uint8_t pkg_timer[8192];
    /* Create a simple TIMER package - we need to modify the manifest */
    char timer_manifest[512];
    snprintf(timer_manifest, sizeof(timer_manifest),
        "{"
        "\"program_name\":\"timer_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":2,"  /* TIMER */
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
    size_t timer_manifest_len = strlen(timer_manifest);

    /* Calculate offsets for timer package */
    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)timer_manifest_len;
    (void)(bytecode_offset + (uint32_t)bc_len);  /* Suppress unused total_size warning */

    uint8_t *p = pkg_timer;
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = timer_manifest_len & 0xFF; *p++ = (timer_manifest_len >> 8) & 0xFF;
    *p++ = (timer_manifest_len >> 16) & 0xFF; *p++ = (timer_manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    memcpy(p, timer_manifest, timer_manifest_len);
    p += timer_manifest_len;
    memcpy(p, bytecode_tp, bc_len);
    p += bc_len;
    size_t pkg_timer_len = (size_t)(p - pkg_timer);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Load both programs */
    mbpf_program_t *prog_tp = NULL;
    mbpf_program_t *prog_timer = NULL;
    int err = mbpf_program_load(rt, pkg_tp, pkg_tp_len, NULL, &prog_tp);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, pkg_timer, pkg_timer_len, NULL, &prog_timer);
    ASSERT_EQ(err, MBPF_OK);

    /* Attach both */
    err = mbpf_program_attach(rt, prog_tp, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog_timer, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_deferred_config_t cfg = {
        .max_entries = 1,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    /* Queue and drop TRACEPOINT invocations */
    mbpf_ctx_tracepoint_v1_t tp_ctx = {
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

    /* Fill and drop for TRACEPOINT */
    err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                MBPF_HOOK_TRACEPOINT,
                                &tp_ctx, sizeof(tp_ctx));
    ASSERT_EQ(err, MBPF_OK);

    for (int i = 0; i < 3; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &tp_ctx, sizeof(tp_ctx));
        ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    }

    /* Only TRACEPOINT program should have drops */
    mbpf_stats_t tp_stats, timer_stats;
    mbpf_program_stats(prog_tp, &tp_stats);
    mbpf_program_stats(prog_timer, &timer_stats);
    ASSERT_EQ(tp_stats.deferred_dropped, 3);
    ASSERT_EQ(timer_stats.deferred_dropped, 0);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    free(bytecode_tp);
    return 0;
}

/*
 * Test 7: Drain clears queue, allowing more queuing
 */
TEST(drain_and_requeue) {
    mbpf_deferred_config_t cfg = {
        .max_entries = 3,
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
    for (int i = 0; i < 3; i++) {
        int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                        MBPF_HOOK_TRACEPOINT,
                                        &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Drops */
    int err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
    ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    ASSERT_EQ(mbpf_deferred_dropped(queue), 1);

    /* Drain */
    int executed = mbpf_drain_deferred(queue);
    ASSERT_EQ(executed, 3);
    ASSERT_EQ(mbpf_deferred_pending(queue), 0);

    /* Now we can queue again */
    for (int i = 0; i < 3; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TRACEPOINT,
                                    MBPF_HOOK_TRACEPOINT,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }
    ASSERT_EQ(mbpf_deferred_pending(queue), 3);

    /* Drop counter persists */
    ASSERT_EQ(mbpf_deferred_dropped(queue), 1);

    mbpf_deferred_queue_destroy(queue);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test 8: Timer hook drops also tracked
 */
TEST(timer_hook_drops) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Build TIMER package */
    char timer_manifest[512];
    snprintf(timer_manifest, sizeof(timer_manifest),
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
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
    size_t timer_manifest_len = strlen(timer_manifest);

    uint8_t pkg[8192];
    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)timer_manifest_len;

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
    *p++ = timer_manifest_len & 0xFF; *p++ = (timer_manifest_len >> 8) & 0xFF;
    *p++ = (timer_manifest_len >> 16) & 0xFF; *p++ = (timer_manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    memcpy(p, timer_manifest, timer_manifest_len);
    p += timer_manifest_len;
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
        .max_entries = 2,
        .max_snapshot_bytes = 1024
    };
    mbpf_deferred_queue_t *queue = mbpf_deferred_queue_create(&cfg);
    ASSERT_NOT_NULL(queue);

    mbpf_ctx_timer_v1_t ctx = {
        .abi_version = 1,
        .timer_id = 1,
        .period_us = 1000,
        .flags = 0,
        .reserved = 0,
        .invocation_count = 0,
        .timestamp = 0
    };

    /* Fill and drop */
    for (int i = 0; i < 2; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TIMER,
                                    MBPF_HOOK_TIMER,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_OK);
    }

    for (int i = 0; i < 4; i++) {
        err = mbpf_queue_invocation(queue, rt, MBPF_HOOK_TIMER,
                                    MBPF_HOOK_TIMER,
                                    &ctx, sizeof(ctx));
        ASSERT_EQ(err, MBPF_ERR_NO_MEM);
    }

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.deferred_dropped, 4);
    ASSERT_EQ(mbpf_deferred_dropped(queue), 4);

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

    printf("microBPF Deferred Execution Backpressure Tests\n");
    printf("===============================================\n\n");

    printf("Queue full handling:\n");
    RUN_TEST(queue_full_drops_counted);
    RUN_TEST(drops_are_non_blocking);
    RUN_TEST(drain_and_requeue);

    printf("\nPer-program drop counters:\n");
    RUN_TEST(per_program_drop_counter);
    RUN_TEST(multiple_programs_drop_counter);
    RUN_TEST(unattached_program_no_drops);

    printf("\nPer-hook drop isolation:\n");
    RUN_TEST(per_hook_drop_isolation);
    RUN_TEST(timer_hook_drops);

    printf("\n===============================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
