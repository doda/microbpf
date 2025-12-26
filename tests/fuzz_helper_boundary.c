/*
 * Fuzz Test for microBPF Helper Boundaries
 *
 * This is a security fuzz test harness that tests helper functions with
 * malformed inputs including:
 * - Invalid Uint8Array arguments (wrong type, truncated, null)
 * - Invalid offsets (negative, out of bounds, NaN, Infinity)
 * - Invalid array lengths
 * - Type mismatches
 *
 * The goal is to ensure helpers handle all edge cases gracefully without
 * crashing the runtime.
 *
 * Usage as standalone test:
 *   gcc -DFUZZ_STANDALONE -o fuzz_helper_boundary tests/fuzz_helper_boundary.c \
 *       -Iinclude -Ideps/mquickjs -Lbuild -lmbpf -lm
 *   ./fuzz_helper_boundary
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Build a manifest with specified capabilities */
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type, uint32_t caps) {
    char caps_str[512] = "";
    char *p = caps_str;

    p += sprintf(p, "[");
    int first = 1;
    if (caps & MBPF_CAP_LOG) { p += sprintf(p, "%s\"CAP_LOG\"", first ? "" : ","); first = 0; }
    if (caps & MBPF_CAP_TIME) { p += sprintf(p, "%s\"CAP_TIME\"", first ? "" : ","); first = 0; }
    if (caps & MBPF_CAP_EMIT) { p += sprintf(p, "%s\"CAP_EMIT\"", first ? "" : ","); first = 0; }
    if (caps & MBPF_CAP_STATS) { p += sprintf(p, "%s\"CAP_STATS\"", first ? "" : ","); first = 0; }
    if (caps & MBPF_CAP_MAP_READ) { p += sprintf(p, "%s\"CAP_MAP_READ\"", first ? "" : ","); first = 0; }
    if (caps & MBPF_CAP_MAP_WRITE) { p += sprintf(p, "%s\"CAP_MAP_WRITE\"", first ? "" : ","); first = 0; }
    if (caps & MBPF_CAP_MAP_ITERATE) { p += sprintf(p, "%s\"CAP_MAP_ITERATE\"", first ? "" : ","); first = 0; }
    p += sprintf(p, "]");

    char json[4096];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"fuzz_helper\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":1000000,\"max_helpers\":10000},"
        "\"capabilities\":%s,"
        "\"maps\":["
        "{\"name\":\"test_array\",\"type\":1,\"key_size\":4,\"value_size\":8,\"max_entries\":10},"
        "{\"name\":\"test_hash\",\"type\":2,\"key_size\":8,\"value_size\":16,\"max_entries\":10}"
        "]"
        "}",
        hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(), caps_str);

    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type, uint32_t caps) {
    if (cap < 256) return 0;

    uint8_t manifest[4096];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest), hook_type, caps);
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

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/fuzz_helper.js";
    const char *bc_file = "/tmp/fuzz_helper.qjbc";

    FILE *f = fopen(js_file, "w");
    if (!f) return NULL;
    fputs(js_code, f);
    fclose(f);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "./deps/mquickjs/mqjs --no-column -o %s %s 2>/dev/null",
             bc_file, js_file);
    if (system(cmd) != 0) return NULL;

    f = fopen(bc_file, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *bc = malloc(len);
    if (!bc) { fclose(f); return NULL; }
    if (fread(bc, 1, len, f) != (size_t)len) {
        free(bc);
        fclose(f);
        return NULL;
    }
    fclose(f);

    *out_len = (size_t)len;
    return bc;
}

/*
 * Test helper: runs a program that exercises helper functions with
 * various malformed inputs. Returns 0 if all tests pass (helpers
 * threw appropriate exceptions), non-zero if something crashed.
 */
static int run_helper_fuzz_test(const char *js_code, uint32_t caps) {
    size_t bc_len;
    uint8_t *bc = compile_js(js_code, &bc_len);
    if (!bc) {
        return -1;
    }

    uint8_t pkg[32768];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bc, bc_len,
                                         MBPF_HOOK_NET_RX, caps);
    free(bc);
    if (pkg_len == 0) return -2;

    mbpf_runtime_config_t cfg = {
        .require_signatures = false,
        .debug_mode = true,
        .allowed_capabilities = caps
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    if (!rt) return -3;

    mbpf_program_t *prog = NULL;
    mbpf_load_opts_t load_opts = { .allow_unsigned = true };
    int err = mbpf_program_load(rt, pkg, pkg_len, &load_opts, &prog);
    if (err != MBPF_OK) {
        mbpf_runtime_shutdown(rt);
        return -4;
    }

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    if (err != MBPF_OK) {
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return -5;
    }

    /* Create a proper NET_RX context */
    static const uint8_t test_data[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    mbpf_ctx_net_rx_v1_t ctx_blob = {
        .abi_version = 1,
        .ifindex = 1,
        .pkt_len = sizeof(test_data),
        .data_len = sizeof(test_data),
        .l2_proto = 0x0800,
        .flags = 0,
        .data = test_data,
        .read_fn = NULL
    };

    int32_t rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_NET_RX, &ctx_blob, sizeof(ctx_blob), &rc);

    mbpf_program_detach(rt, prog, MBPF_HOOK_NET_RX);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    /* If we get here without crashing, the test passes.
     * rc value indicates whether JS tests passed. */
    return (err == MBPF_OK) ? (int)rc : -6;
}

/* ============================================================================
 * Fuzz Test Categories
 * ============================================================================ */

/*
 * Test 1: u64LoadLE with malformed inputs
 */
static int test_u64LoadLE_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    var out = [0, 0];\n"
        "    \n"
        "    // Test 1: null bytes\n"
        "    try { mbpf.u64LoadLE(null, 0, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: undefined bytes\n"
        "    try { mbpf.u64LoadLE(undefined, 0, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: number instead of Uint8Array\n"
        "    try { mbpf.u64LoadLE(12345, 0, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: string instead of Uint8Array\n"
        "    try { mbpf.u64LoadLE('test', 0, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: empty Uint8Array (offset out of bounds)\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(0), 0, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: Uint8Array too small\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(7), 0, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 7: negative offset\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(8), -1, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 8: offset at boundary (leaves less than 8 bytes)\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(8), 1, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 9: very large offset\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(8), 0x7FFFFFFF, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 10: NaN offset\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(8), NaN, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 11: Infinity offset\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(8), Infinity, out); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 12: null output\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(8), 0, null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 13: output too small\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(8), 0, [0]); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 14: output is not array\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(8), 0, {}); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 15: offset is string\n"
        "    try { mbpf.u64LoadLE(new Uint8Array(8), 'abc', out); errors++; } catch(e) {}\n"
        "    \n"
        "    // If any test didn't throw, return error count\n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG);
}

/*
 * Test 2: u64StoreLE with malformed inputs
 */
static int test_u64StoreLE_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    var val = [0x12345678, 0x9ABCDEF0];\n"
        "    \n"
        "    // Test 1: null bytes\n"
        "    try { mbpf.u64StoreLE(null, 0, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: undefined bytes\n"
        "    try { mbpf.u64StoreLE(undefined, 0, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: number instead of Uint8Array\n"
        "    try { mbpf.u64StoreLE(12345, 0, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: string instead of Uint8Array\n"
        "    try { mbpf.u64StoreLE('test', 0, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: empty Uint8Array\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(0), 0, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: Uint8Array too small\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(7), 0, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 7: negative offset\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(8), -1, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 8: offset at boundary\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(8), 1, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 9: very large offset\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(8), 0x7FFFFFFF, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 10: NaN offset\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(8), NaN, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 11: Infinity offset\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(8), Infinity, val); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 12: null value\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(8), 0, null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 13: value too small\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(8), 0, [0]); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 14: value is not array\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(8), 0, {}); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 15: value is string\n"
        "    try { mbpf.u64StoreLE(new Uint8Array(8), 0, 'abc'); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG);
}

/*
 * Test 3: ctx.readU8 with malformed offsets
 */
static int test_readU8_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    \n"
        "    // Test 1: negative offset\n"
        "    try { ctx.readU8(-1); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: very large offset\n"
        "    try { ctx.readU8(0x7FFFFFFF); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: offset >= data length\n"
        "    try { ctx.readU8(1000); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: NaN offset\n"
        "    try { ctx.readU8(NaN); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: Infinity offset\n"
        "    try { ctx.readU8(Infinity); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: string offset\n"
        "    try { ctx.readU8('abc'); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 7: null offset\n"
        "    try { ctx.readU8(null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 8: undefined offset\n"
        "    try { ctx.readU8(undefined); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 9: object offset\n"
        "    try { ctx.readU8({}); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 10: array offset\n"
        "    try { ctx.readU8([1]); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 11: -Infinity offset\n"
        "    try { ctx.readU8(-Infinity); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG);
}

/*
 * Test 4: ctx.readU16LE with malformed offsets
 */
static int test_readU16LE_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    \n"
        "    // Test 1: negative offset\n"
        "    try { ctx.readU16LE(-1); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: offset too close to end (need 2 bytes)\n"
        "    try { ctx.readU16LE(15); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: very large offset\n"
        "    try { ctx.readU16LE(0x7FFFFFFF); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: NaN offset\n"
        "    try { ctx.readU16LE(NaN); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: Infinity offset\n"
        "    try { ctx.readU16LE(Infinity); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: string offset\n"
        "    try { ctx.readU16LE('abc'); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 7: null offset\n"
        "    try { ctx.readU16LE(null); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG);
}

/*
 * Test 5: ctx.readU32LE with malformed offsets
 */
static int test_readU32LE_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    \n"
        "    // Test 1: negative offset\n"
        "    try { ctx.readU32LE(-1); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: offset too close to end (need 4 bytes)\n"
        "    try { ctx.readU32LE(13); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: very large offset\n"
        "    try { ctx.readU32LE(0x7FFFFFFF); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: NaN offset\n"
        "    try { ctx.readU32LE(NaN); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: Infinity offset\n"
        "    try { ctx.readU32LE(Infinity); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: string offset\n"
        "    try { ctx.readU32LE('abc'); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG);
}

/*
 * Test 6: ctx.readBytes with malformed inputs
 */
static int test_readBytes_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    var buf = new Uint8Array(16);\n"
        "    \n"
        "    // Test 1: negative offset\n"
        "    try { ctx.readBytes(-1, 4, buf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: negative length\n"
        "    try { ctx.readBytes(0, -1, buf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: offset >= data length\n"
        "    try { ctx.readBytes(1000, 4, buf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: null buffer\n"
        "    try { ctx.readBytes(0, 4, null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: undefined buffer\n"
        "    try { ctx.readBytes(0, 4, undefined); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: number instead of buffer\n"
        "    try { ctx.readBytes(0, 4, 12345); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 7: string instead of buffer\n"
        "    try { ctx.readBytes(0, 4, 'test'); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 8: NaN offset\n"
        "    try { ctx.readBytes(NaN, 4, buf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 9: NaN length\n"
        "    try { ctx.readBytes(0, NaN, buf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 10: Infinity offset\n"
        "    try { ctx.readBytes(Infinity, 4, buf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 11: Infinity length\n"
        "    try { ctx.readBytes(0, Infinity, buf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 12: very large offset\n"
        "    try { ctx.readBytes(0x7FFFFFFF, 4, buf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 13: very large length\n"
        "    try { ctx.readBytes(0, 0x7FFFFFFF, buf); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG);
}

/*
 * Test 7: map lookup with malformed inputs
 */
static int test_map_lookup_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    var outBuf = new Uint8Array(16);\n"
        "    var keyBuf = new Uint8Array(8);\n"
        "    \n"
        "    // Array map tests\n"
        "    // Test 1: negative index\n"
        "    try { maps.test_array.lookup(-1, outBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: index >= max_entries\n"
        "    try { maps.test_array.lookup(100, outBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: NaN index\n"
        "    try { maps.test_array.lookup(NaN, outBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: Infinity index\n"
        "    try { maps.test_array.lookup(Infinity, outBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: string index\n"
        "    try { maps.test_array.lookup('abc', outBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: null outBuffer\n"
        "    try { maps.test_array.lookup(0, null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 7: outBuffer too small\n"
        "    try { maps.test_array.lookup(0, new Uint8Array(4)); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 8: number instead of outBuffer\n"
        "    try { maps.test_array.lookup(0, 12345); errors++; } catch(e) {}\n"
        "    \n"
        "    // Hash map tests\n"
        "    // Test 9: null key\n"
        "    try { maps.test_hash.lookup(null, outBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 10: key too small\n"
        "    try { maps.test_hash.lookup(new Uint8Array(4), outBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 11: number instead of key\n"
        "    try { maps.test_hash.lookup(12345, outBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 12: string instead of key\n"
        "    try { maps.test_hash.lookup('testkey', outBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 13: null outBuffer for hash\n"
        "    try { maps.test_hash.lookup(keyBuf, null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 14: outBuffer too small for hash\n"
        "    try { maps.test_hash.lookup(keyBuf, new Uint8Array(8)); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE);
}

/*
 * Test 8: map update with malformed inputs
 */
static int test_map_update_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    var valueBuf = new Uint8Array(16);\n"
        "    var keyBuf = new Uint8Array(8);\n"
        "    \n"
        "    // Array map tests\n"
        "    // Test 1: negative index\n"
        "    try { maps.test_array.update(-1, valueBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: index >= max_entries\n"
        "    try { maps.test_array.update(100, valueBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: NaN index\n"
        "    try { maps.test_array.update(NaN, valueBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: null valueBuffer\n"
        "    try { maps.test_array.update(0, null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: valueBuffer too small\n"
        "    try { maps.test_array.update(0, new Uint8Array(4)); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: number instead of valueBuffer\n"
        "    try { maps.test_array.update(0, 12345); errors++; } catch(e) {}\n"
        "    \n"
        "    // Hash map tests\n"
        "    // Test 7: null key\n"
        "    try { maps.test_hash.update(null, valueBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 8: key too small\n"
        "    try { maps.test_hash.update(new Uint8Array(4), valueBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 9: number instead of key\n"
        "    try { maps.test_hash.update(12345, valueBuf); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 10: null valueBuffer for hash\n"
        "    try { maps.test_hash.update(keyBuf, null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 11: valueBuffer too small for hash\n"
        "    try { maps.test_hash.update(keyBuf, new Uint8Array(8)); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE);
}

/*
 * Test 9: map delete with malformed inputs
 */
static int test_map_delete_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    \n"
        "    // Hash map delete tests\n"
        "    // Test 1: null key\n"
        "    try { maps.test_hash.delete(null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: key too small\n"
        "    try { maps.test_hash.delete(new Uint8Array(4)); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: number instead of key\n"
        "    try { maps.test_hash.delete(12345); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: string instead of key\n"
        "    try { maps.test_hash.delete('testkey'); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: undefined key\n"
        "    try { maps.test_hash.delete(undefined); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: object instead of key\n"
        "    try { maps.test_hash.delete({}); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE);
}

/*
 * Test 10: map nextKey with malformed inputs
 */
static int test_map_nextKey_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    var outKey = new Uint8Array(8);\n"
        "    \n"
        "    // Test 1: outKey too small\n"
        "    try { maps.test_hash.nextKey(null, new Uint8Array(4)); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: outKey is null\n"
        "    try { maps.test_hash.nextKey(null, null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: outKey is number\n"
        "    try { maps.test_hash.nextKey(null, 12345); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: prevKey is wrong type (not null, undefined, or Uint8Array)\n"
        "    try { maps.test_hash.nextKey(12345, outKey); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: prevKey too small\n"
        "    try { maps.test_hash.nextKey(new Uint8Array(4), outKey); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: prevKey is string\n"
        "    try { maps.test_hash.nextKey('testkey', outKey); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 7: outKey is undefined\n"
        "    try { maps.test_hash.nextKey(null, undefined); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE | MBPF_CAP_MAP_ITERATE);
}

/*
 * Test 11: mbpf.log with malformed inputs
 */
static int test_log_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    // These should all be handled gracefully without crashing\n"
        "    // log should accept various inputs and convert to string\n"
        "    mbpf.log(0, null);\n"
        "    mbpf.log(1, undefined);\n"
        "    mbpf.log(2, {});\n"
        "    mbpf.log(3, [1, 2, 3]);\n"
        "    mbpf.log(-1, 'negative level');\n"
        "    mbpf.log(100, 'large level');\n"
        "    mbpf.log(NaN, 'NaN level');\n"
        "    mbpf.log(null, 'null level');\n"
        "    mbpf.log(undefined, 'undefined level');\n"
        "    mbpf.log('abc', 'string level');\n"
        "    return 0;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG);
}

/*
 * Test 12: mbpf.nowNs with malformed inputs
 */
static int test_nowNs_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    \n"
        "    // Test 1: null output\n"
        "    try { mbpf.nowNs(null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: output too small\n"
        "    try { mbpf.nowNs([0]); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: output is number\n"
        "    try { mbpf.nowNs(12345); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: output is string\n"
        "    try { mbpf.nowNs('test'); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: output is undefined\n"
        "    try { mbpf.nowNs(undefined); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: output is object (not array)\n"
        "    try { mbpf.nowNs({}); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG | MBPF_CAP_TIME);
}

/*
 * Test 13: mbpf.emit with malformed inputs
 */
static int test_emit_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    \n"
        "    // Test 1: null bytes\n"
        "    try { mbpf.emit(1, null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: undefined bytes\n"
        "    try { mbpf.emit(1, undefined); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: number instead of bytes\n"
        "    try { mbpf.emit(1, 12345); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: string instead of bytes\n"
        "    try { mbpf.emit(1, 'test'); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: null eventId\n"
        "    try { mbpf.emit(null, new Uint8Array(4)); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: string eventId\n"
        "    try { mbpf.emit('test', new Uint8Array(4)); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 7: object instead of bytes\n"
        "    try { mbpf.emit(1, {}); errors++; } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG | MBPF_CAP_EMIT);
}

/*
 * Test 14: mbpf.stats with malformed inputs
 */
static int test_stats_malformed(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    \n"
        "    // Test 1: null output\n"
        "    try { mbpf.stats(null); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 2: undefined output\n"
        "    try { mbpf.stats(undefined); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 3: number output\n"
        "    try { mbpf.stats(12345); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 4: string output\n"
        "    try { mbpf.stats('test'); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 5: empty object (missing required arrays)\n"
        "    try { mbpf.stats({}); errors++; } catch(e) {}\n"
        "    \n"
        "    // Test 6: object with wrong types for fields\n"
        "    try {\n"
        "        mbpf.stats({\n"
        "            invocations: 123,\n"
        "            successes: [0, 0],\n"
        "            exceptions: [0, 0],\n"
        "            oom_errors: [0, 0],\n"
        "            budget_exceeded: [0, 0],\n"
        "            nested_dropped: [0, 0],\n"
        "            deferred_dropped: [0, 0]\n"
        "        });\n"
        "        errors++;\n"
        "    } catch(e) {}\n"
        "    \n"
        "    // Test 7: object with arrays too small\n"
        "    try {\n"
        "        mbpf.stats({\n"
        "            invocations: [0],\n"
        "            successes: [0, 0],\n"
        "            exceptions: [0, 0],\n"
        "            oom_errors: [0, 0],\n"
        "            budget_exceeded: [0, 0],\n"
        "            nested_dropped: [0, 0],\n"
        "            deferred_dropped: [0, 0]\n"
        "        });\n"
        "        errors++;\n"
        "    } catch(e) {}\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG | MBPF_CAP_STATS);
}

/*
 * Test 15: Stress test with rapid helper calls
 */
static int test_stress_helpers(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var buf = new Uint8Array(16);\n"
        "    var out = [0, 0];\n"
        "    \n"
        "    // Rapid fire valid calls\n"
        "    for (var i = 0; i < 100; i++) {\n"
        "        mbpf.u64LoadLE(buf, 0, out);\n"
        "        mbpf.u64StoreLE(buf, 0, out);\n"
        "        mbpf.u64LoadLE(buf, 8, out);\n"
        "        mbpf.u64StoreLE(buf, 8, out);\n"
        "    }\n"
        "    \n"
        "    // Rapid fire error cases (should all throw but not crash)\n"
        "    for (var i = 0; i < 50; i++) {\n"
        "        try { mbpf.u64LoadLE(null, 0, out); } catch(e) {}\n"
        "        try { mbpf.u64LoadLE(buf, -1, out); } catch(e) {}\n"
        "        try { mbpf.u64LoadLE(buf, 100, out); } catch(e) {}\n"
        "    }\n"
        "    \n"
        "    return 0;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG);
}

/*
 * Test 16: Edge case offset values
 */
static int test_edge_offsets(void) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var errors = 0;\n"
        "    var buf = new Uint8Array(256);\n"
        "    var out = [0, 0];\n"
        "    \n"
        "    // Test edge offset values\n"
        "    var offsets = [\n"
        "        0, 1, 2, 247, 248, 249,  // around boundaries\n"
        "        0.5, 1.5, 247.5,         // fractional\n"
        "        -0, -0.0,                // negative zero\n"
        "        Number.MIN_VALUE,\n"
        "        Number.MAX_VALUE,\n"
        "        Number.MIN_SAFE_INTEGER,\n"
        "        Number.MAX_SAFE_INTEGER,\n"
        "        1e10, 1e20, 1e308        // very large\n"
        "    ];\n"
        "    \n"
        "    for (var i = 0; i < offsets.length; i++) {\n"
        "        var off = offsets[i];\n"
        "        try {\n"
        "            mbpf.u64LoadLE(buf, off, out);\n"
        "            // Should succeed only for valid offsets [0, 248]\n"
        "            if (off < 0 || off > 248 || !Number.isFinite(off)) {\n"
        "                errors++;\n"
        "            }\n"
        "        } catch(e) {\n"
        "            // Should throw for invalid offsets\n"
        "            if (off >= 0 && off <= 248 && Number.isFinite(off) && Math.floor(off) === off) {\n"
        "                errors++;\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    return errors;\n"
        "}\n";

    return run_helper_fuzz_test(js_code, MBPF_CAP_LOG);
}

/* ============================================================================
 * Main Test Runner
 * ============================================================================ */

#define RUN_FUZZ_TEST(name) do { \
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

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Helper Boundary Fuzz Tests\n");
    printf("====================================\n\n");

    printf("u64 helper tests:\n");
    RUN_FUZZ_TEST(u64LoadLE_malformed);
    RUN_FUZZ_TEST(u64StoreLE_malformed);

    printf("\nContext read method tests:\n");
    RUN_FUZZ_TEST(readU8_malformed);
    RUN_FUZZ_TEST(readU16LE_malformed);
    RUN_FUZZ_TEST(readU32LE_malformed);
    RUN_FUZZ_TEST(readBytes_malformed);

    printf("\nMap operation tests:\n");
    RUN_FUZZ_TEST(map_lookup_malformed);
    RUN_FUZZ_TEST(map_update_malformed);
    RUN_FUZZ_TEST(map_delete_malformed);
    RUN_FUZZ_TEST(map_nextKey_malformed);

    printf("\nOther helper tests:\n");
    RUN_FUZZ_TEST(log_malformed);
    RUN_FUZZ_TEST(nowNs_malformed);
    RUN_FUZZ_TEST(emit_malformed);
    RUN_FUZZ_TEST(stats_malformed);

    printf("\nStress and edge case tests:\n");
    RUN_FUZZ_TEST(stress_helpers);
    RUN_FUZZ_TEST(edge_offsets);

    printf("\n====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
