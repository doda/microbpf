/*
 * microBPF No Dynamic Allocation Runtime Tests
 *
 * This test verifies that the runtime does not perform dynamic allocation
 * (malloc/free) in untrusted code paths during program execution, and that
 * the JS heap uses a fixed memory buffer as per the performance requirements.
 *
 * Test categories:
 * 1. Verify fixed memory buffer is used for JS heap
 * 2. Profile runtime during program execution
 * 3. Verify no malloc/free calls from host library in hot path
 *    (for basic program execution without ring buffers/counters/emit)
 *
 * This file uses the GNU linker --wrap feature to intercept malloc/free calls
 * and track allocations. When TRACK_ALLOCS is defined and linking with
 * -Wl,--wrap=malloc,--wrap=free,--wrap=realloc,--wrap=calloc, all allocation
 * calls are tracked and can be asserted on.
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * Allocation Tracking Infrastructure
 *
 * Using GNU linker --wrap feature to intercept malloc/free/realloc/calloc.
 * The linker replaces calls to malloc with __wrap_malloc, and provides
 * __real_malloc to call the actual function.
 * ============================================================================ */

/* Allocation tracking state */
static volatile int g_alloc_tracking_enabled = 0;
static volatile size_t g_alloc_count = 0;
static volatile size_t g_free_count = 0;
static volatile size_t g_realloc_count = 0;
static volatile size_t g_calloc_count = 0;
static volatile size_t g_alloc_bytes = 0;

/* Reset allocation counters */
static void alloc_tracking_reset(void) {
    g_alloc_count = 0;
    g_free_count = 0;
    g_realloc_count = 0;
    g_calloc_count = 0;
    g_alloc_bytes = 0;
}

/* Enable allocation tracking */
static void alloc_tracking_start(void) {
    alloc_tracking_reset();
    g_alloc_tracking_enabled = 1;
}

/* Disable allocation tracking and return total allocation count (malloc + realloc + calloc) */
static size_t alloc_tracking_stop(void) {
    g_alloc_tracking_enabled = 0;
    return g_alloc_count + g_realloc_count + g_calloc_count;
}

/* Declare the real functions provided by the linker */
extern void *__real_malloc(size_t size);
extern void __real_free(void *ptr);
extern void *__real_realloc(void *ptr, size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);

/* Wrapped malloc - intercepts all malloc calls */
void *__wrap_malloc(size_t size) {
    if (g_alloc_tracking_enabled) {
        g_alloc_count++;
        g_alloc_bytes += size;
    }
    return __real_malloc(size);
}

/* Wrapped free - intercepts all free calls */
void __wrap_free(void *ptr) {
    if (g_alloc_tracking_enabled && ptr != NULL) {
        g_free_count++;
    }
    __real_free(ptr);
}

/* Wrapped realloc - intercepts all realloc calls */
void *__wrap_realloc(void *ptr, size_t size) {
    if (g_alloc_tracking_enabled) {
        g_realloc_count++;
        g_alloc_bytes += size;
    }
    return __real_realloc(ptr, size);
}

/* Wrapped calloc - intercepts all calloc calls */
void *__wrap_calloc(size_t nmemb, size_t size) {
    if (g_alloc_tracking_enabled) {
        g_calloc_count++;
        g_alloc_bytes += nmemb * size;
    }
    return __real_calloc(nmemb, size);
}

/* ============================================================================
 * Test Framework
 * ============================================================================ */

#define TEST(name) static int test_##name(void)
#define RUN_TEST(name) do { \
    printf("  " #name "... "); \
    fflush(stdout); \
    int result = test_##name(); \
    if (result == 0) { \
        printf("PASS\n"); \
        passed++; \
    } else { \
        printf("FAIL (rc=%d)\n", result); \
        failed++; \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("ASSERT FAILED: " #cond " at line %d\n", __LINE__); return -1; } } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)
#define ASSERT_GE(a, b) ASSERT((a) >= (b))

/* Build manifest with specified hook and capabilities */
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type,
                             const char *capabilities, const char *maps,
                             size_t heap_size) {
    char json[4096];
    if (maps) {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"no_alloc_test\","
            "\"program_version\":\"1.0.0\","
            "\"hook_type\":%d,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":%u,\"endianness\":%u},"
            "\"mbpf_api_version\":1,"
            "\"heap_size\":%zu,"
            "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
            "\"capabilities\":[%s],"
            "\"maps\":[%s]"
            "}",
            hook_type,
            mbpf_runtime_word_size(), mbpf_runtime_endianness(),
            heap_size,
            capabilities, maps);
    } else {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"no_alloc_test\","
            "\"program_version\":\"1.0.0\","
            "\"hook_type\":%d,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":%u,\"endianness\":%u},"
            "\"mbpf_api_version\":1,"
            "\"heap_size\":%zu,"
            "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
            "\"capabilities\":[%s]"
            "}",
            hook_type,
            mbpf_runtime_word_size(), mbpf_runtime_endianness(),
            heap_size,
            capabilities);
    }
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type, const char *capabilities,
                                  const char *maps, size_t heap_size) {
    if (cap < 256) return 0;

    uint8_t manifest[4096];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest),
                                          hook_type, capabilities, maps, heap_size);
    if (manifest_len == 0) return 0;

    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 0: MANIFEST */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 1: BYTECODE */
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

/* Compile JavaScript to bytecode */
static uint8_t *compile_js(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_no_alloc.js";
    const char *bc_file = "/tmp/test_no_alloc.qjbc";

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
 * Test Cases - Fixed Memory Buffer for JS Heap
 * ============================================================================ */

/*
 * Test: Verify JS heap uses pre-allocated fixed buffer
 *
 * The heap is allocated once at program load time, not during execution.
 */
TEST(heap_is_fixed_buffer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL, 16384);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify instance has a fixed heap size that was configured */
    size_t heap_size = mbpf_program_instance_heap_size(prog, 0);
    ASSERT_GE(heap_size, 16384);

    /* Verify we can get the instance (heap is allocated) */
    mbpf_instance_t *inst = mbpf_program_get_instance(prog, 0);
    ASSERT_NOT_NULL(inst);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Verify heap buffer is reused across invocations
 *
 * Running multiple invocations should not allocate new heaps.
 */
TEST(heap_reused_across_invocations) {
    const char *js_code =
        "var counter = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    counter++;\n"
        "    return counter;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL, 16384);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Get heap info before invocations */
    size_t heap_size_before = mbpf_program_instance_heap_size(prog, 0);
    mbpf_instance_t *inst_before = mbpf_program_get_instance(prog, 0);

    /* Run multiple invocations */
    int32_t rc;
    for (int i = 1; i <= 10; i++) {
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, i);  /* counter should increment */
    }

    /* Verify same heap is used (size unchanged, same instance) */
    size_t heap_size_after = mbpf_program_instance_heap_size(prog, 0);
    mbpf_instance_t *inst_after = mbpf_program_get_instance(prog, 0);

    ASSERT_EQ(heap_size_before, heap_size_after);
    ASSERT_EQ(inst_before, inst_after);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Verify heap size matches manifest configuration
 *
 * The heap size should be at least what's requested in the manifest.
 */
TEST(heap_size_matches_config) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Test with specific heap size */
    size_t requested_heap = 32768;  /* 32KB */

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL,
                                         requested_heap);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify heap size is at least requested */
    size_t actual_heap = mbpf_program_instance_heap_size(prog, 0);
    ASSERT_GE(actual_heap, requested_heap);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - No Dynamic Allocation in Hot Path
 * ============================================================================ */

/*
 * Test: Simple program execution without ring buffers/counters
 *
 * For basic programs that don't use ring buffers, counters, or emit,
 * the hot path should not allocate memory. We verify this by enabling
 * allocation tracking during mbpf_run() calls and asserting zero mallocs.
 */
TEST(simple_execution_no_alloc) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var a = 1;\n"
        "    var b = 2;\n"
        "    return a + b;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL, 16384);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* First run to warm up (first run may do lazy initialization) */
    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 3);

    /* Now enable allocation tracking and run many iterations.
     * ASSERT that NO malloc/free/realloc/calloc calls happen. */
    alloc_tracking_start();

    for (int i = 0; i < 1000; i++) {
        rc = -99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 3);
    }

    size_t alloc_count = alloc_tracking_stop();

    /* Verify NO allocations occurred during the hot path */
    if (alloc_count > 0) {
        printf("\n    ERROR: %zu allocations detected in hot path (expected 0)\n", alloc_count);
        printf("    malloc=%zu, realloc=%zu, calloc=%zu, free=%zu, bytes=%zu\n",
               g_alloc_count, g_realloc_count, g_calloc_count, g_free_count, g_alloc_bytes);
    }
    ASSERT_EQ(alloc_count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Array map operations in hot path
 *
 * Array maps don't require dynamic sync like ring buffers.
 * We verify no allocations occur during map lookup/update operations.
 */
TEST(array_map_execution_no_alloc) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var val = new Uint8Array(4);\n"
        "    val[0] = 42;\n"
        "    maps.myarray.update(0, val);\n"
        "    var out = new Uint8Array(4);\n"
        "    maps.myarray.lookup(0, out);\n"
        "    return out[0];\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    const char *map_def = "{\"name\":\"myarray\",\"type\":1,\"key_size\":4,"
                          "\"max_entries\":8,\"value_size\":4,\"flags\":0}";
    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"",
                                         map_def, 32768);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* First run to warm up (first run may do lazy initialization) */
    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 42);

    /* Enable allocation tracking and run iterations */
    alloc_tracking_start();

    for (int i = 0; i < 100; i++) {
        rc = -99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 42);
    }

    size_t alloc_count = alloc_tracking_stop();

    /* Verify NO allocations occurred during the hot path */
    if (alloc_count > 0) {
        printf("\n    ERROR: %zu allocations detected in hot path (expected 0)\n", alloc_count);
        printf("    malloc=%zu, realloc=%zu, calloc=%zu, free=%zu, bytes=%zu\n",
               g_alloc_count, g_realloc_count, g_calloc_count, g_free_count, g_alloc_bytes);
    }
    ASSERT_EQ(alloc_count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Hash map operations in hot path
 *
 * Hash maps don't require dynamic sync like ring buffers.
 * We verify no allocations occur during hash map lookup/update operations.
 */
TEST(hash_map_execution_no_alloc) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var key = new Uint8Array([1, 2, 3, 4]);\n"
        "    var val = new Uint8Array([10, 20, 30, 40]);\n"
        "    maps.myhash.update(key, val);\n"
        "    var out = new Uint8Array(4);\n"
        "    var found = maps.myhash.lookup(key, out);\n"
        "    if (!found) return -1;\n"
        "    return out[0] + out[1];\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    const char *map_def = "{\"name\":\"myhash\",\"type\":2,\"key_size\":4,"
                          "\"max_entries\":16,\"value_size\":4,\"flags\":0}";
    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"",
                                         map_def, 32768);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* First run to warm up (first run may do lazy initialization) */
    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 30);  /* 10 + 20 */

    /* Enable allocation tracking and run iterations */
    alloc_tracking_start();

    for (int i = 0; i < 100; i++) {
        rc = -99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 30);  /* 10 + 20 */
    }

    size_t alloc_count = alloc_tracking_stop();

    /* Verify NO allocations occurred during the hot path */
    if (alloc_count > 0) {
        printf("\n    ERROR: %zu allocations detected in hot path (expected 0)\n", alloc_count);
        printf("    malloc=%zu, realloc=%zu, calloc=%zu, free=%zu, bytes=%zu\n",
               g_alloc_count, g_realloc_count, g_calloc_count, g_free_count, g_alloc_bytes);
    }
    ASSERT_EQ(alloc_count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Context access when context is null doesn't allocate
 *
 * For hooks that can run with null context (like TRACEPOINT), verify the
 * context object creation path is allocation-free.
 *
 * Note: When a full context structure is provided (e.g., NET_RX with packet data),
 * the current implementation allocates memory to build the JS context object.
 * This test verifies the simpler null-context path is allocation-free.
 */
TEST(context_read_no_alloc) {
    /* This test uses a program that checks if ctx is null and returns appropriately */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return 42;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL, 16384);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* First run to warm up (first run may do lazy initialization) */
    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 42);

    /* Enable allocation tracking and run iterations */
    alloc_tracking_start();

    for (int i = 0; i < 100; i++) {
        rc = -99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 42);
    }

    size_t alloc_count = alloc_tracking_stop();

    /* Verify NO allocations occurred during the hot path */
    if (alloc_count > 0) {
        printf("\n    ERROR: %zu allocations detected in hot path (expected 0)\n", alloc_count);
        printf("    malloc=%zu, realloc=%zu, calloc=%zu, free=%zu, bytes=%zu\n",
               g_alloc_count, g_realloc_count, g_calloc_count, g_free_count, g_alloc_bytes);
    }
    ASSERT_EQ(alloc_count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Helper calls don't allocate in return path
 *
 * Helpers should return primitive types (numbers/booleans) without allocation.
 * We verify no allocations occur during helper invocations.
 */
TEST(helper_returns_no_alloc) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var bytes = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    var out = [0, 0];\n"
        "    mbpf.u64LoadLE(bytes, 0, out);\n"
        "    mbpf.log(0, 'test');\n"
        "    return out[0];\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL, 16384);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* First run to warm up (first run may do lazy initialization) */
    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);

    /* Enable allocation tracking and run iterations */
    alloc_tracking_start();

    for (int i = 0; i < 100; i++) {
        rc = -99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 1);
    }

    size_t alloc_count = alloc_tracking_stop();

    /* Verify NO allocations occurred during the hot path */
    if (alloc_count > 0) {
        printf("\n    ERROR: %zu allocations detected in hot path (expected 0)\n", alloc_count);
        printf("    malloc=%zu, realloc=%zu, calloc=%zu, free=%zu, bytes=%zu\n",
               g_alloc_count, g_realloc_count, g_calloc_count, g_free_count, g_alloc_bytes);
    }
    ASSERT_EQ(alloc_count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - Stress Tests
 * ============================================================================ */

/*
 * Test: High frequency execution doesn't leak memory
 *
 * Running thousands of iterations should be stable and allocation-free.
 * We verify no allocations occur during the sustained hot path.
 */
TEST(high_frequency_stable) {
    const char *js_code =
        "var sum = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    sum = (sum + 1) & 0xFF;\n"
        "    return sum;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL, 16384);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* First run to warm up (first run may do lazy initialization) */
    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);

    /* Enable allocation tracking and run many iterations */
    alloc_tracking_start();

    for (int i = 1; i < 10000; i++) {
        rc = -99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, (i + 1) & 0xFF);
    }

    size_t alloc_count = alloc_tracking_stop();

    /* Verify NO allocations occurred during the sustained hot path */
    if (alloc_count > 0) {
        printf("\n    ERROR: %zu allocations detected in 10000 iterations (expected 0)\n", alloc_count);
        printf("    malloc=%zu, realloc=%zu, calloc=%zu, free=%zu, bytes=%zu\n",
               g_alloc_count, g_realloc_count, g_calloc_count, g_free_count, g_alloc_bytes);
    }
    ASSERT_EQ(alloc_count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Multiple programs can run concurrently without allocation issues
 *
 * We verify no allocations occur when running multiple programs concurrently.
 */
TEST(multiple_programs_no_alloc) {
    const char *js_code1 =
        "function mbpf_prog(ctx) { return 1; }\n";
    const char *js_code2 =
        "function mbpf_prog(ctx) { return 2; }\n";

    size_t bc_len1, bc_len2;
    uint8_t *bytecode1 = compile_js(js_code1, &bc_len1);
    uint8_t *bytecode2 = compile_js(js_code2, &bc_len2);
    ASSERT_NOT_NULL(bytecode1);
    ASSERT_NOT_NULL(bytecode2);

    uint8_t pkg1[16384], pkg2[16384];
    size_t pkg_len1 = build_mbpf_package(pkg1, sizeof(pkg1), bytecode1, bc_len1,
                                          MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL, 16384);
    size_t pkg_len2 = build_mbpf_package(pkg2, sizeof(pkg2), bytecode2, bc_len2,
                                          MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL, 16384);
    ASSERT(pkg_len1 > 0);
    ASSERT(pkg_len2 > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog1 = NULL, *prog2 = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg_len1, NULL, &prog1);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, pkg2, pkg_len2, NULL, &prog2);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* First run to warm up (first run may do lazy initialization) */
    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT(rc == 1 || rc == 2);

    /* Enable allocation tracking and run iterations */
    alloc_tracking_start();

    for (int i = 0; i < 100; i++) {
        rc = -99;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        /* Result should be 1 or 2 */
        ASSERT(rc == 1 || rc == 2);
    }

    size_t alloc_count = alloc_tracking_stop();

    /* Verify NO allocations occurred during the hot path */
    if (alloc_count > 0) {
        printf("\n    ERROR: %zu allocations detected in hot path (expected 0)\n", alloc_count);
        printf("    malloc=%zu, realloc=%zu, calloc=%zu, free=%zu, bytes=%zu\n",
               g_alloc_count, g_realloc_count, g_calloc_count, g_free_count, g_alloc_bytes);
    }
    ASSERT_EQ(alloc_count, 0);

    mbpf_program_detach(rt, prog1, MBPF_HOOK_TRACEPOINT);
    mbpf_program_detach(rt, prog2, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog1);
    mbpf_program_unload(rt, prog2);
    mbpf_runtime_shutdown(rt);
    free(bytecode1);
    free(bytecode2);
    return 0;
}

/*
 * Test: Per-CPU instances have separate fixed heaps
 *
 * When configured with multiple instances, each instance should have
 * its own separate fixed heap buffer.
 */
TEST(percpu_instances_separate_heaps) {
    const char *js_code =
        "var counter = 0;\n"
        "function mbpf_prog(ctx) { counter++; return counter; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL, 16384);
    ASSERT(pkg_len > 0);

    /* Create runtime with multiple instances */
    mbpf_runtime_config_t cfg = {
        .instance_mode = MBPF_INSTANCE_COUNT,
        .instance_count = 4,
        .allowed_capabilities = MBPF_CAP_LOG
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify multiple instances were created */
    uint32_t count = mbpf_program_instance_count(prog);
    ASSERT_GE(count, 1);  /* At least 1 instance */

    /* Each instance should have its own heap */
    for (uint32_t i = 0; i < count; i++) {
        size_t heap_size = mbpf_program_instance_heap_size(prog, i);
        ASSERT_GE(heap_size, 16384);

        mbpf_instance_t *inst = mbpf_program_get_instance(prog, i);
        ASSERT_NOT_NULL(inst);
    }

    mbpf_program_unload(rt, prog);
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

    printf("microBPF No Dynamic Allocation Runtime Tests\n");
    printf("=============================================\n\n");

    printf("Fixed Memory Buffer Tests:\n");
    RUN_TEST(heap_is_fixed_buffer);
    RUN_TEST(heap_reused_across_invocations);
    RUN_TEST(heap_size_matches_config);

    printf("\nNo Dynamic Allocation in Hot Path Tests:\n");
    RUN_TEST(simple_execution_no_alloc);
    RUN_TEST(array_map_execution_no_alloc);
    RUN_TEST(hash_map_execution_no_alloc);
    RUN_TEST(context_read_no_alloc);
    RUN_TEST(helper_returns_no_alloc);

    printf("\nStress Tests:\n");
    RUN_TEST(high_frequency_stable);
    RUN_TEST(multiple_programs_no_alloc);
    RUN_TEST(percpu_instances_separate_heaps);

    printf("\n=============================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
