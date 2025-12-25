/*
 * microBPF Ring Buffer Map Tests
 *
 * Tests for ring buffer map type for event output:
 * 1. Define ring buffer map in manifest
 * 2. Write events to ring buffer from program
 * 3. Read events from ring buffer (host side)
 * 4. Verify overflow behavior (oldest events dropped)
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
        printf("FAIL (code %d)\n", result); \
        failed++; \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("ASSERT FAILED: " #cond " at line %d\n", __LINE__); return -1; } } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Helper to build a manifest with ring buffer map definition */
static size_t build_manifest_with_ring_map(uint8_t *buf, size_t cap, int hook_type,
                                            const char *map_name, uint32_t max_entries,
                                            uint32_t value_size) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"ring_map_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":5,\"key_size\":0,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        hook_type, map_name, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with bytecode and ring buffer map */
static size_t build_mbpf_package_with_ring_map(uint8_t *buf, size_t cap,
                                                const uint8_t *bytecode, size_t bc_len,
                                                int hook_type,
                                                const char *map_name, uint32_t max_entries,
                                                uint32_t value_size) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_ring_map(manifest, sizeof(manifest),
                                                        hook_type, map_name,
                                                        max_entries, value_size);
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
    const char *js_file = "/tmp/test_ring_map.js";
    const char *bc_file = "/tmp/test_ring_map.qjbc";

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
 * Test Cases - map-ring-buffer
 * ============================================================================ */

/*
 * Test 1: Define ring buffer map in manifest and load
 *
 * Verification: Map is created and can be accessed with proper methods
 */
TEST(ring_map_created) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Verify map exists */\n"
        "    if (!maps.events) return -1;\n"
        "    if (typeof maps.events.submit !== 'function') return -2;\n"
        "    if (typeof maps.events.count !== 'function') return -3;\n"
        "    if (typeof maps.events.dropped !== 'function') return -4;\n"
        "    if (typeof maps.events.peek !== 'function') return -5;\n"
        "    if (typeof maps.events.consume !== 'function') return -6;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);  /* 16*8=128 bytes buffer */
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Write events to ring buffer from program
 *
 * Verification: Events are submitted successfully
 */
TEST(submit_events) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Submit a simple event */\n"
        "    var event1 = new Uint8Array([1, 2, 3, 4]);\n"
        "    if (!maps.events.submit(event1)) return -1;\n"
        "    \n"
        "    /* Submit another event */\n"
        "    var event2 = new Uint8Array([5, 6, 7, 8]);\n"
        "    if (!maps.events.submit(event2)) return -2;\n"
        "    \n"
        "    /* Check count */\n"
        "    if (maps.events.count() !== 2) return -3;\n"
        "    \n"
        "    return 2;  /* 2 events submitted */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Read events from ring buffer (host side)
 *
 * Verification: Host can read events submitted by program
 */
TEST(host_read_events) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Submit two events */\n"
        "    var event1 = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD]);\n"
        "    if (!maps.events.submit(event1)) return -1;\n"
        "    \n"
        "    var event2 = new Uint8Array([0x11, 0x22, 0x33]);\n"
        "    if (!maps.events.submit(event2)) return -2;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    /* Find the ring buffer map */
    int map_idx = mbpf_program_find_ring_map(prog, "events");
    ASSERT(map_idx >= 0);

    /* Check event count */
    int count = mbpf_ring_count(prog, map_idx);
    ASSERT_EQ(count, 2);

    /* Read first event */
    uint8_t buf[32];
    int len = mbpf_ring_read(prog, map_idx, buf, sizeof(buf));
    ASSERT_EQ(len, 4);
    ASSERT_EQ(buf[0], 0xAA);
    ASSERT_EQ(buf[1], 0xBB);
    ASSERT_EQ(buf[2], 0xCC);
    ASSERT_EQ(buf[3], 0xDD);

    /* Check count after read */
    count = mbpf_ring_count(prog, map_idx);
    ASSERT_EQ(count, 1);

    /* Read second event */
    len = mbpf_ring_read(prog, map_idx, buf, sizeof(buf));
    ASSERT_EQ(len, 3);
    ASSERT_EQ(buf[0], 0x11);
    ASSERT_EQ(buf[1], 0x22);
    ASSERT_EQ(buf[2], 0x33);

    /* Check count after read */
    count = mbpf_ring_count(prog, map_idx);
    ASSERT_EQ(count, 0);

    /* Read from empty buffer should return 0 */
    len = mbpf_ring_read(prog, map_idx, buf, sizeof(buf));
    ASSERT_EQ(len, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Verify overflow behavior (oldest events dropped)
 *
 * Verification: When buffer is full, oldest events are dropped
 */
TEST(overflow_drops_oldest) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Submit events until buffer overflows */\n"
        "    /* Buffer is 64 bytes. Each event is 4+8=12 bytes (header + data) */\n"
        "    /* We can fit about 5 events before overflow */\n"
        "    for (var i = 0; i < 10; i++) {\n"
        "        var event = new Uint8Array([i, i+1, i+2, i+3, i+4, i+5, i+6, i+7]);\n"
        "        if (!maps.events.submit(event)) return -(i+1);\n"
        "    }\n"
        "    \n"
        "    /* Check that some events were dropped */\n"
        "    if (maps.events.dropped() === 0) return -100;\n"
        "    \n"
        "    /* Return the number of dropped events */\n"
        "    return maps.events.dropped();\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    /* 8*8=64 bytes buffer - small to force overflow */
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 8, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* Return value should be positive (number of dropped events) */
    ASSERT(out_rc > 0);

    /* Verify from host side */
    int map_idx = mbpf_program_find_ring_map(prog, "events");
    ASSERT(map_idx >= 0);

    int dropped = mbpf_ring_dropped(prog, map_idx);
    ASSERT_EQ(dropped, out_rc);

    /* Read remaining events - they should be the newer ones */
    uint8_t buf[32];
    int len;
    while ((len = mbpf_ring_read(prog, map_idx, buf, sizeof(buf))) > 0) {
        /* The first byte should be >= dropped count (older events were dropped) */
        ASSERT(buf[0] >= (uint8_t)dropped);
    }

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: Peek without consuming
 *
 * Verification: peek() reads event data without removing it
 */
TEST(peek_without_consume) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Submit an event */\n"
        "    var event = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);\n"
        "    if (!maps.events.submit(event)) return -1;\n"
        "    \n"
        "    /* Peek at the event */\n"
        "    var peekBuf = new Uint8Array(4);\n"
        "    var len = maps.events.peek(peekBuf);\n"
        "    if (len !== 4) return -2;\n"
        "    if (peekBuf[0] !== 0xDE) return -3;\n"
        "    if (peekBuf[3] !== 0xEF) return -4;\n"
        "    \n"
        "    /* Count should still be 1 (not consumed) */\n"
        "    if (maps.events.count() !== 1) return -5;\n"
        "    \n"
        "    /* Peek again - same data */\n"
        "    var peekBuf2 = new Uint8Array(4);\n"
        "    len = maps.events.peek(peekBuf2);\n"
        "    if (len !== 4) return -6;\n"
        "    if (peekBuf2[0] !== 0xDE) return -7;\n"
        "    \n"
        "    /* Consume the event */\n"
        "    if (!maps.events.consume()) return -8;\n"
        "    if (maps.events.count() !== 0) return -9;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Host peek without consuming
 *
 * Verification: mbpf_ring_peek() reads without consuming
 */
TEST(host_peek) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var event = new Uint8Array([0x12, 0x34, 0x56, 0x78]);\n"
        "    if (!maps.events.submit(event)) return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    int map_idx = mbpf_program_find_ring_map(prog, "events");
    ASSERT(map_idx >= 0);

    /* Peek at event */
    uint8_t buf[32];
    int len = mbpf_ring_peek(prog, map_idx, buf, sizeof(buf));
    ASSERT_EQ(len, 4);
    ASSERT_EQ(buf[0], 0x12);
    ASSERT_EQ(buf[1], 0x34);
    ASSERT_EQ(buf[2], 0x56);
    ASSERT_EQ(buf[3], 0x78);

    /* Count should still be 1 */
    ASSERT_EQ(mbpf_ring_count(prog, map_idx), 1);

    /* Peek again - same data */
    len = mbpf_ring_peek(prog, map_idx, buf, sizeof(buf));
    ASSERT_EQ(len, 4);
    ASSERT_EQ(buf[0], 0x12);

    /* Now read (consumes) */
    len = mbpf_ring_read(prog, map_idx, buf, sizeof(buf));
    ASSERT_EQ(len, 4);
    ASSERT_EQ(mbpf_ring_count(prog, map_idx), 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Event too large for buffer
 *
 * Verification: submit() returns false for oversized events
 */
TEST(event_too_large) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Buffer is only 64 bytes. Event with 60+ bytes + 4 byte header won't fit */\n"
        "    var largeEvent = new Uint8Array(100);\n"
        "    for (var i = 0; i < 100; i++) largeEvent[i] = i;\n"
        "    \n"
        "    /* This should fail */\n"
        "    if (maps.events.submit(largeEvent)) return -1;\n"
        "    \n"
        "    /* Count should be 0 */\n"
        "    if (maps.events.count() !== 0) return -2;\n"
        "    \n"
        "    /* Small event should still work */\n"
        "    var smallEvent = new Uint8Array([1, 2, 3]);\n"
        "    if (!maps.events.submit(smallEvent)) return -3;\n"
        "    if (maps.events.count() !== 1) return -4;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    /* 8*8=64 bytes buffer */
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 8, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7b: Value size enforcement
 *
 * Verification: Ring buffer enforces manifest value_size as max event size.
 * Even when buffer has enough space, events larger than value_size are rejected.
 */
TEST(value_size_enforcement) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Buffer is 16*8=128 bytes, plenty of space.\n"
        "     * But value_size=8, so events larger than 8 bytes should be rejected. */\n"
        "    \n"
        "    /* Event with exactly 8 bytes should succeed (equals value_size) */\n"
        "    var event8 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);\n"
        "    if (!maps.events.submit(event8)) return -1;\n"
        "    if (maps.events.count() !== 1) return -2;\n"
        "    \n"
        "    /* Event with 9 bytes should fail (exceeds value_size) */\n"
        "    var event9 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);\n"
        "    if (maps.events.submit(event9)) return -3;  /* Should fail */\n"
        "    if (maps.events.count() !== 1) return -4;  /* Count unchanged */\n"
        "    \n"
        "    /* Larger event should also fail */\n"
        "    var event20 = new Uint8Array(20);\n"
        "    for (var i = 0; i < 20; i++) event20[i] = i;\n"
        "    if (maps.events.submit(event20)) return -5;  /* Should fail */\n"
        "    if (maps.events.count() !== 1) return -6;  /* Count unchanged */\n"
        "    \n"
        "    /* Smaller events should still work */\n"
        "    var event4 = new Uint8Array([10, 20, 30, 40]);\n"
        "    if (!maps.events.submit(event4)) return -7;\n"
        "    if (maps.events.count() !== 2) return -8;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    /* 16*8=128 bytes buffer, value_size=8 (max event size) */
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7c: Record too large for buffer
 *
 * Verification: Ring buffer rejects records that won't fit in the buffer.
 * With max_entries=1 and value_size=64, buffer is exactly 64 bytes.
 * A 64-byte event needs 4+64=68 bytes (header + data), which won't fit.
 * Even smaller events may not fit due to the +1 byte requirement.
 */
TEST(record_too_large_for_buffer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Buffer is max_entries=1, value_size=64, so buffer=64 bytes.\n"
        "     * Record format is [4-byte header][data], so max data that fits\n"
        "     * is 64-4-1=59 bytes (need recordSize+1 <= bufSize). */\n"
        "    \n"
        "    /* 59 bytes should succeed (4+59+1=64 fits exactly) */\n"
        "    var event59 = new Uint8Array(59);\n"
        "    for (var i = 0; i < 59; i++) event59[i] = i;\n"
        "    if (!maps.events.submit(event59)) return -1;\n"
        "    if (maps.events.count() !== 1) return -2;\n"
        "    \n"
        "    /* Consume it to make room */\n"
        "    maps.events.consume();\n"
        "    if (maps.events.count() !== 0) return -3;\n"
        "    \n"
        "    /* 60 bytes should fail (4+60+1=65 > 64) */\n"
        "    var event60 = new Uint8Array(60);\n"
        "    for (var i = 0; i < 60; i++) event60[i] = i;\n"
        "    if (maps.events.submit(event60)) return -4;  /* Should fail */\n"
        "    if (maps.events.count() !== 0) return -5;  /* Count unchanged */\n"
        "    \n"
        "    /* 64 bytes (value_size) should also fail because record won't fit */\n"
        "    var event64 = new Uint8Array(64);\n"
        "    for (var i = 0; i < 64; i++) event64[i] = i;\n"
        "    if (maps.events.submit(event64)) return -6;  /* Should fail */\n"
        "    if (maps.events.count() !== 0) return -7;  /* Count unchanged */\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    /* max_entries=1, value_size=64, buffer=64 bytes exactly */
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 1, 64);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Type validation
 *
 * Verification: Ring buffer validates input types correctly
 */
TEST(type_validation) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Test wrong type for submit */\n"
        "    try {\n"
        "        maps.events.submit('string');\n"
        "        return -1;  /* Should have thrown */\n"
        "    } catch (e1) {\n"
        "        if (!(e1 instanceof TypeError)) return -2;\n"
        "    }\n"
        "    \n"
        "    try {\n"
        "        maps.events.submit(12345);\n"
        "        return -3;  /* Should have thrown */\n"
        "    } catch (e2) {\n"
        "        if (!(e2 instanceof TypeError)) return -4;\n"
        "    }\n"
        "    \n"
        "    /* Test wrong type for peek */\n"
        "    var event = new Uint8Array([1, 2, 3]);\n"
        "    maps.events.submit(event);\n"
        "    \n"
        "    try {\n"
        "        maps.events.peek('notarray');\n"
        "        return -5;  /* Should have thrown */\n"
        "    } catch (e3) {\n"
        "        if (!(e3 instanceof TypeError)) return -6;\n"
        "    }\n"
        "    \n"
        "    /* Valid operations should work */\n"
        "    var outBuf = new Uint8Array(10);\n"
        "    if (maps.events.peek(outBuf) !== 3) return -7;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Empty buffer operations
 *
 * Verification: peek/consume on empty buffer behave correctly
 */
TEST(empty_buffer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Buffer should start empty */\n"
        "    if (maps.events.count() !== 0) return -1;\n"
        "    if (maps.events.dropped() !== 0) return -2;\n"
        "    \n"
        "    /* Peek on empty should return 0 */\n"
        "    var buf = new Uint8Array(10);\n"
        "    if (maps.events.peek(buf) !== 0) return -3;\n"
        "    \n"
        "    /* Consume on empty should return false */\n"
        "    if (maps.events.consume()) return -4;\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Multiple runs with ring buffer
 *
 * Verification: Ring buffer persists across program invocations
 */
TEST(persistence_across_runs) {
    const char *js_code =
        "var runCount = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    runCount++;\n"
        "    \n"
        "    if (runCount === 1) {\n"
        "        /* First run: submit an event */\n"
        "        var event = new Uint8Array([0xCA, 0xFE]);\n"
        "        if (!maps.events.submit(event)) return -1;\n"
        "        return 1;\n"
        "    } else {\n"
        "        /* Second run: verify event is still there */\n"
        "        if (maps.events.count() !== 1) return -2;\n"
        "        var buf = new Uint8Array(10);\n"
        "        var len = maps.events.peek(buf);\n"
        "        if (len !== 2) return -3;\n"
        "        if (buf[0] !== 0xCA || buf[1] !== 0xFE) return -4;\n"
        "        return 2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* First run */
    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);

    /* Second run */
    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 2);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Two-way sync - host reads don't reappear after program runs
 *
 * Verification: Host-side mbpf_ring_read consumes events permanently
 */
TEST(twoway_sync) {
    const char *js_code =
        "var runCount = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    runCount++;\n"
        "    if (runCount === 1) {\n"
        "        /* First run: submit 3 events */\n"
        "        for (var i = 0; i < 3; i++) {\n"
        "            var event = new Uint8Array([i, i+1, i+2, i+3]);\n"
        "            maps.events.submit(event);\n"
        "        }\n"
        "        return 3;\n"
        "    } else {\n"
        "        /* Second run: return current count */\n"
        "        return maps.events.count();\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package_with_ring_map(pkg, sizeof(pkg),
                                                       bytecode, bc_len,
                                                       MBPF_HOOK_TRACEPOINT,
                                                       "events", 16, 8);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* First run: submit 3 events */
    mbpf_ctx_tracepoint_v1_t ctx = { .abi_version = 1 };
    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 3);

    int map_idx = mbpf_program_find_ring_map(prog, "events");
    ASSERT(map_idx >= 0);

    /* Host reads 2 events */
    uint8_t buf[32];
    int len = mbpf_ring_read(prog, map_idx, buf, sizeof(buf));
    ASSERT_EQ(len, 4);
    ASSERT_EQ(buf[0], 0);

    len = mbpf_ring_read(prog, map_idx, buf, sizeof(buf));
    ASSERT_EQ(len, 4);
    ASSERT_EQ(buf[0], 1);

    /* Verify host sees 1 remaining */
    ASSERT_EQ(mbpf_ring_count(prog, map_idx), 1);

    /* Second run: program should also see only 1 event (C-to-JS sync worked) */
    out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);  /* Should see 1 event, not 3 */

    /* Verify host still sees 1 */
    ASSERT_EQ(mbpf_ring_count(prog, map_idx), 1);

    /* Read the last event */
    len = mbpf_ring_read(prog, map_idx, buf, sizeof(buf));
    ASSERT_EQ(len, 4);
    ASSERT_EQ(buf[0], 2);

    /* Should be empty now */
    ASSERT_EQ(mbpf_ring_count(prog, map_idx), 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Ring Buffer Map Tests\n");
    printf("==============================\n");

    printf("\nMap creation tests:\n");
    RUN_TEST(ring_map_created);

    printf("\nWrite events tests:\n");
    RUN_TEST(submit_events);

    printf("\nHost-side read tests:\n");
    RUN_TEST(host_read_events);
    RUN_TEST(host_peek);

    printf("\nOverflow behavior tests:\n");
    RUN_TEST(overflow_drops_oldest);

    printf("\nPeek/consume tests:\n");
    RUN_TEST(peek_without_consume);

    printf("\nEdge cases:\n");
    RUN_TEST(event_too_large);
    RUN_TEST(value_size_enforcement);
    RUN_TEST(record_too_large_for_buffer);
    RUN_TEST(type_validation);
    RUN_TEST(empty_buffer);
    RUN_TEST(persistence_across_runs);

    printf("\nTwo-way sync tests:\n");
    RUN_TEST(twoway_sync);

    printf("\n==============================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
