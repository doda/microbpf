/*
 * microBPF Allocation-Free Helper Tests
 *
 * This test verifies that all microBPF helpers follow the allocation-free
 * contract specified in SPEC.md §7.5.3:
 *
 * "In the core profile, all microBPF-provided C functions callable from
 *  programs (helpers and ctx.* methods) MUST NOT allocate JS objects/strings/
 *  arrays on the success path. They MUST:
 *  - Take inputs as numbers/booleans and preallocated buffers (Uint8Array).
 *  - Return numbers/booleans (or undefined) and write outputs into
 *    caller-provided buffers."
 *
 * Test categories:
 * 1. mbpf.* helpers return correct types (numbers/booleans/undefined)
 * 2. Helpers use preallocated output buffers
 * 3. ctx.read* methods return numbers only
 * 4. Map methods return booleans and use preallocated buffers
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
        printf("FAIL (rc=%d)\n", result); \
        failed++; \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("ASSERT FAILED: " #cond " at line %d\n", __LINE__); return -1; } } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Build manifest with specified hook and capabilities */
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type,
                             const char *capabilities, const char *maps) {
    char json[4096];
    if (maps) {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"alloc_test\","
            "\"program_version\":\"1.0.0\","
            "\"hook_type\":%d,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":%u,\"endianness\":%u},"
            "\"mbpf_api_version\":1,"
            "\"heap_size\":65536,"
            "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
            "\"capabilities\":[%s],"
            "\"maps\":[%s]"
            "}",
            hook_type,
            mbpf_runtime_word_size(), mbpf_runtime_endianness(),
            capabilities, maps);
    } else {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"alloc_test\","
            "\"program_version\":\"1.0.0\","
            "\"hook_type\":%d,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":1,"
            "\"target\":{\"word_size\":%u,\"endianness\":%u},"
            "\"mbpf_api_version\":1,"
            "\"heap_size\":65536,"
            "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
            "\"capabilities\":[%s]"
            "}",
            hook_type,
            mbpf_runtime_word_size(), mbpf_runtime_endianness(),
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
                                  const char *maps) {
    if (cap < 256) return 0;

    uint8_t manifest[4096];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest),
                                          hook_type, capabilities, maps);
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
    const char *js_file = "/tmp/test_alloc.js";
    const char *bc_file = "/tmp/test_alloc.qjbc";

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
 * Test Cases - mbpf.* helper return types
 * ============================================================================ */

/*
 * Test: mbpf.apiVersion returns a number
 */
TEST(api_version_returns_number) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var v = mbpf.apiVersion;\n"
        "    if (typeof v !== 'number') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: mbpf.log returns undefined (no allocation)
 */
TEST(log_returns_undefined) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var result = mbpf.log(1, 'test');\n"
        "    if (typeof result !== 'undefined') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: mbpf.u64LoadLE writes to preallocated output, returns undefined
 */
TEST(u64_load_le_uses_preallocated_output) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var bytes = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);\n"
        "    var out = [0, 0];  /* preallocated output */\n"
        "    var result = mbpf.u64LoadLE(bytes, 0, out);\n"
        "    if (typeof result !== 'undefined') return -1;\n"
        "    if (out[0] !== 1) return -2;  /* check value was written */\n"
        "    if (out[1] !== 0) return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: mbpf.u64StoreLE writes to preallocated buffer, returns undefined
 */
TEST(u64_store_le_uses_preallocated_buffer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var bytes = new Uint8Array(8);  /* preallocated buffer */\n"
        "    var value = [0x12345678, 0];  /* value to store */\n"
        "    var result = mbpf.u64StoreLE(bytes, 0, value);\n"
        "    if (typeof result !== 'undefined') return -1;\n"
        "    /* check bytes were written correctly */\n"
        "    if (bytes[0] !== 0x78) return -2;\n"
        "    if (bytes[1] !== 0x56) return -3;\n"
        "    if (bytes[2] !== 0x34) return -4;\n"
        "    if (bytes[3] !== 0x12) return -5;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: mbpf.nowNs writes to preallocated output, returns undefined
 */
TEST(now_ns_uses_preallocated_output) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var out = [0, 0];  /* preallocated output */\n"
        "    var result = mbpf.nowNs(out);\n"
        "    if (typeof result !== 'undefined') return -1;\n"
        "    /* check that some value was written (time > 0) */\n"
        "    if (out[0] === 0 && out[1] === 0) return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_TIME\"", NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = { .allowed_capabilities = MBPF_CAP_TIME };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: mbpf.emit returns boolean
 */
TEST(emit_returns_boolean) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var data = new Uint8Array([1, 2, 3]);\n"
        "    var result = mbpf.emit(1, data);\n"
        "    if (typeof result !== 'boolean') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_EMIT\"", NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = { .allowed_capabilities = MBPF_CAP_EMIT };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: mbpf.stats(out) writes to preallocated object, returns undefined
 */
TEST(stats_uses_preallocated_output) {
    const char *js_code =
        "var _statsOut = {\n"
        "    invocations: [0, 0], successes: [0, 0], exceptions: [0, 0],\n"
        "    oom_errors: [0, 0], budget_exceeded: [0, 0], nested_dropped: [0, 0],\n"
        "    deferred_dropped: [0, 0]\n"
        "};\n"
        "function mbpf_prog(ctx) {\n"
        "    var result = mbpf.stats(_statsOut);\n"
        "    if (typeof result !== 'undefined') return -1;\n"
        "    /* Verify data was written to the preallocated object */\n"
        "    if (typeof _statsOut.invocations[0] !== 'number') return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_STATS\"", NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = { .allowed_capabilities = MBPF_CAP_STATS };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - ctx.read* methods
 * ============================================================================ */

/*
 * Test: ctx.readU8 returns number
 */
TEST(ctx_read_u8_returns_number) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var val = ctx.readU8(0);\n"
        "    if (typeof val !== 'number') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Provide some context data */
    uint8_t ctx_data[] = { 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, ctx_data, sizeof(ctx_data), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: ctx.readBytes writes to preallocated buffer, returns number (count)
 */
TEST(ctx_read_bytes_uses_preallocated_buffer) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(4);  /* preallocated buffer */\n"
        "    var count = ctx.readBytes(0, 4, buf);\n"
        "    if (typeof count !== 'number') return -1;\n"
        "    if (count !== 4) return -2;\n"
        "    /* verify bytes were written */\n"
        "    if (buf[0] !== 0x01) return -3;\n"
        "    if (buf[1] !== 0x02) return -4;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT, "\"CAP_LOG\"", NULL);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Context data */
    uint8_t ctx_data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, ctx_data, sizeof(ctx_data), &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - Map methods
 * ============================================================================ */

/*
 * Test: map.lookup returns boolean and writes to preallocated buffer
 */
TEST(map_lookup_returns_boolean) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var out = new Uint8Array(4);  /* preallocated buffer */\n"
        "    var result = maps.counter.lookup(0, out);\n"
        "    if (typeof result !== 'boolean') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    const char *map_def = "{\"name\":\"counter\",\"type\":1,\"key_size\":4,"
                          "\"max_entries\":8,\"value_size\":4,\"flags\":0}";
    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"",
                                         map_def);
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

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: map.update returns boolean
 */
TEST(map_update_returns_boolean) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var val = new Uint8Array([1, 2, 3, 4]);\n"
        "    var result = maps.counter.update(0, val);\n"
        "    if (typeof result !== 'boolean') return -1;\n"
        "    if (result !== true) return -2;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    const char *map_def = "{\"name\":\"counter\",\"type\":1,\"key_size\":4,"
                          "\"max_entries\":8,\"value_size\":4,\"flags\":0}";
    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"",
                                         map_def);
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

    int32_t rc = -99;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
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

    printf("microBPF Allocation-Free Helper Tests\n");
    printf("=====================================\n\n");

    printf("mbpf.* helper return type tests:\n");
    RUN_TEST(api_version_returns_number);
    RUN_TEST(log_returns_undefined);
    RUN_TEST(emit_returns_boolean);

    printf("\nPreallocated output buffer tests:\n");
    RUN_TEST(u64_load_le_uses_preallocated_output);
    RUN_TEST(u64_store_le_uses_preallocated_buffer);
    RUN_TEST(now_ns_uses_preallocated_output);
    RUN_TEST(stats_uses_preallocated_output);

    printf("\nContext read method tests:\n");
    RUN_TEST(ctx_read_u8_returns_number);
    RUN_TEST(ctx_read_bytes_uses_preallocated_buffer);

    printf("\nMap method tests:\n");
    RUN_TEST(map_lookup_returns_boolean);
    RUN_TEST(map_update_returns_boolean);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
