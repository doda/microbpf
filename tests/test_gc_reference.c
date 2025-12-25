/*
 * microBPF GC Reference Handling Tests
 *
 * Tests for proper GC reference handling with JSGCRef:
 * 1. Use JS_AddGCRef for persistent references (entry func, maps object)
 * 2. Verify references remain valid after GC/compaction
 * 3. Verify references are released on cleanup
 * 4. Stress test with allocations to trigger GC
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

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_gc_ref.js";
    const char *bc_file = "/tmp/test_gc_ref.qjbc";

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
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *bytecode = malloc(size);
    if (!bytecode) {
        fclose(f);
        return NULL;
    }

    size_t nread = fread(bytecode, 1, size, f);
    fclose(f);

    if ((long)nread != size) {
        free(bytecode);
        return NULL;
    }

    *out_len = size;
    return bytecode;
}

/* Build a simple manifest */
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"gc_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":1000000,\"max_helpers\":10000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        hook_type,
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a manifest with a map */
static size_t build_manifest_with_map(uint8_t *buf, size_t cap, int hook_type) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"gc_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":1000000,\"max_helpers\":10000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"testmap\",\"type\":1,\"key_size\":4,\"value_size\":4,\"max_entries\":10,\"flags\":0}]"
        "}",
        hook_type,
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type, int with_map) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len;
    if (with_map) {
        manifest_len = build_manifest_with_map(manifest, sizeof(manifest), hook_type);
    } else {
        manifest_len = build_manifest(manifest, sizeof(manifest), hook_type);
    }
    if (manifest_len == 0) return 0;

    /* Calculate offsets */
    uint32_t header_size = 20 + 2 * 16;  /* header + 2 section descriptors */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t file_size = bytecode_offset + (uint32_t)bc_len;

    if (file_size > cap) return 0;

    uint8_t *p = buf;

    /* Write file header */
    uint32_t magic = 0x4D425046;  /* "MBPF" */
    memcpy(p, &magic, 4); p += 4;
    uint16_t version = 1;
    memcpy(p, &version, 2); p += 2;
    uint16_t header_sz = (uint16_t)header_size;
    memcpy(p, &header_sz, 2); p += 2;
    uint32_t flags = 0;
    memcpy(p, &flags, 4); p += 4;
    uint32_t section_count = 2;
    memcpy(p, &section_count, 4); p += 4;
    uint32_t file_crc32 = 0;
    memcpy(p, &file_crc32, 4); p += 4;

    /* Section 1: MANIFEST */
    uint32_t sec_type = 1;  /* MBPF_SEC_MANIFEST */
    memcpy(p, &sec_type, 4); p += 4;
    memcpy(p, &manifest_offset, 4); p += 4;
    uint32_t sec_len = (uint32_t)manifest_len;
    memcpy(p, &sec_len, 4); p += 4;
    uint32_t sec_crc = 0;
    memcpy(p, &sec_crc, 4); p += 4;

    /* Section 2: BYTECODE */
    sec_type = 2;  /* MBPF_SEC_BYTECODE */
    memcpy(p, &sec_type, 4); p += 4;
    memcpy(p, &bytecode_offset, 4); p += 4;
    sec_len = (uint32_t)bc_len;
    memcpy(p, &sec_len, 4); p += 4;
    memcpy(p, &sec_crc, 4); p += 4;

    /* Copy manifest */
    memcpy(buf + manifest_offset, manifest, manifest_len);

    /* Copy bytecode */
    memcpy(buf + bytecode_offset, bytecode, bc_len);

    return file_size;
}

/*
 * Test 1: Verify GC references are registered (entry function valid after load)
 * Load a program and run it multiple times to verify the cached entry function
 * remains valid across runs.
 */
TEST(entry_function_cached) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run the program 100 times to verify the cached entry function works */
    for (int i = 0; i < 100; i++) {
        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 42);
    }

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);

    return 0;
}

/*
 * Test 2: Stress test with allocations that trigger GC.
 * This program allocates many arrays to trigger GC, then verifies
 * the entry function (which is GC-protected) remains callable.
 */
TEST(gc_stress_allocations) {
    /* This JavaScript allocates many objects to trigger GC */
    const char *js_code =
        "var counter = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    /* Allocate some arrays to trigger GC */\n"
        "    var arr = [];\n"
        "    for (var i = 0; i < 100; i++) {\n"
        "        arr.push([1, 2, 3, 4, 5]);\n"
        "    }\n"
        "    counter++;\n"
        "    return counter;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run many times to stress GC with allocations */
    for (int i = 0; i < 50; i++) {
        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, i + 1);  /* counter should increment each time */
    }

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);

    return 0;
}

/*
 * Test 3: Verify maps object remains valid after GC.
 * This test verifies that the maps object (also GC-protected) remains
 * accessible across runs that trigger GC.
 * Note: Array maps use integer index, not key buffer.
 */
TEST(maps_object_valid_after_gc) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Create some allocations */\n"
        "    var temp = [];\n"
        "    for (var i = 0; i < 50; i++) {\n"
        "        temp.push({x: i, y: i * 2});\n"
        "    }\n"
        "    /* Access maps object - it should remain valid */\n"
        "    /* Array maps use integer index, not key buffer */\n"
        "    var val = new Uint8Array([42, 0, 0, 0]);\n"
        "    maps.testmap.update(0, val);\n"
        "    var out = new Uint8Array(4);\n"
        "    var found = maps.testmap.lookup(0, out);\n"
        "    if (!found) return -1;\n"
        "    return out[0];\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run multiple times with GC-triggering allocations */
    for (int i = 0; i < 30; i++) {
        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 42);
    }

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);

    return 0;
}

/*
 * Test 4: Verify cleanup releases GC references properly.
 * This test loads and unloads many programs to verify GC references
 * are properly released on cleanup without memory leaks or crashes.
 */
TEST(cleanup_releases_refs) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 0);
    ASSERT(pkg_len > 0);

    /* Load and unload many programs to stress cleanup path */
    for (int i = 0; i < 50; i++) {
        mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
        ASSERT_NOT_NULL(rt);

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
        ASSERT_EQ(err, MBPF_OK);

        err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
        ASSERT_EQ(err, MBPF_OK);

        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);

        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
    }

    free(bytecode);
    return 0;
}

/*
 * Test 5: Heavy allocation stress test.
 * This test runs a program that does very heavy allocations, designed
 * to definitively trigger compacting GC and verify references survive.
 */
TEST(heavy_allocation_stress) {
    const char *js_code =
        "var invocations = 0;\n"
        "function mbpf_prog(ctx) {\n"
        "    /* Heavy allocations to stress GC */\n"
        "    var outer = [];\n"
        "    for (var i = 0; i < 20; i++) {\n"
        "        var inner = [];\n"
        "        for (var j = 0; j < 10; j++) {\n"
        "            inner.push({a: i, b: j, c: [i, j, i+j]});\n"
        "        }\n"
        "        outer.push(inner);\n"
        "    }\n"
        "    /* Force some string operations too */\n"
        "    var s = '';\n"
        "    for (var k = 0; k < 10; k++) {\n"
        "        s = s + 'abc';\n"
        "    }\n"
        "    invocations++;\n"
        "    return invocations;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 0);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Run many times with heavy allocations */
    for (int i = 0; i < 100; i++) {
        int32_t rc = 0;
        err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, i + 1);
    }

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);

    return 0;
}

/*
 * Test 6: Multiple programs with maps.
 * Load multiple programs, each with maps, and verify all remain
 * functional across runs that trigger GC.
 * Note: Array maps use integer index, not key buffer.
 */
TEST(multiple_programs_with_maps) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var temp = [];\n"
        "    for (var i = 0; i < 20; i++) temp.push([i]);\n"
        "    /* Array maps use integer index, not key buffer */\n"
        "    var v = new Uint8Array([99, 0, 0, 0]);\n"
        "    maps.testmap.update(5, v);\n"
        "    var out = new Uint8Array(4);\n"
        "    maps.testmap.lookup(5, out);\n"
        "    return out[0];\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, 1);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Load 3 programs */
    mbpf_program_t *progs[3];
    for (int i = 0; i < 3; i++) {
        progs[i] = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &progs[i]);
        ASSERT_EQ(err, MBPF_OK);

        err = mbpf_program_attach(rt, progs[i], MBPF_HOOK_TRACEPOINT);
        ASSERT_EQ(err, MBPF_OK);
    }

    /* Run all programs multiple times */
    for (int run = 0; run < 20; run++) {
        int32_t rc = 0;
        int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(rc, 99);
    }

    /* Cleanup */
    for (int i = 0; i < 3; i++) {
        mbpf_program_unload(rt, progs[i]);
    }
    mbpf_runtime_shutdown(rt);
    free(bytecode);

    return 0;
}

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF GC Reference Handling Tests\n");
    printf("=====================================\n\n");

    printf("GC reference registration tests:\n");
    RUN_TEST(entry_function_cached);

    printf("\nGC stress tests:\n");
    RUN_TEST(gc_stress_allocations);
    RUN_TEST(maps_object_valid_after_gc);
    RUN_TEST(heavy_allocation_stress);

    printf("\nCleanup tests:\n");
    RUN_TEST(cleanup_releases_refs);

    printf("\nMulti-program tests:\n");
    RUN_TEST(multiple_programs_with_maps);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
