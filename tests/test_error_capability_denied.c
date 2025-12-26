/*
 * microBPF Error Capability Denied Tests
 *
 * Tests for capability denial errors:
 * 1. Load program requesting ungrantable capability - verify error
 * 2. Call helper without required capability - verify exception
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

/* Helper to build a manifest with specified capabilities and optional maps */
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type,
                             const char *capabilities, const char *maps) {
    char json[4096];
    if (maps && strlen(maps) > 0) {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"cap_denied_test\","
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
            hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(),
            capabilities, maps);
    } else {
        snprintf(json, sizeof(json),
            "{"
            "\"program_name\":\"cap_denied_test\","
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
            hook_type, mbpf_runtime_word_size(), mbpf_runtime_endianness(),
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
    const char *js_file = "/tmp/test_cap_denied.js";
    const char *bc_file = "/tmp/test_cap_denied.qjbc";

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
 * Test Cases - Load ungrantable capability
 * ============================================================================ */

/*
 * Test: Load program requesting CAP_EMIT without runtime granting it
 * This verifies the first step: "Load program requesting ungrantable capability - verify error"
 */
TEST(load_ungrantable_cap_emit) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_EMIT\"",  /* Request CAP_EMIT */
                                         NULL);
    ASSERT(pkg_len > 0);

    /* Runtime does NOT allow CAP_EMIT */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG,  /* Only LOG allowed */
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Verify error code is MBPF_ERR_CAPABILITY_DENIED */
    ASSERT_EQ(err, MBPF_ERR_CAPABILITY_DENIED);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Load program requesting CAP_TIME without runtime granting it
 */
TEST(load_ungrantable_cap_time) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_TIME\"",  /* Request CAP_TIME */
                                         NULL);
    ASSERT(pkg_len > 0);

    /* Runtime does NOT allow CAP_TIME (default doesn't include it) */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_CAPABILITY_DENIED);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Load program requesting CAP_STATS without runtime granting it
 */
TEST(load_ungrantable_cap_stats) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_STATS\"",
                                         NULL);
    ASSERT(pkg_len > 0);

    /* Runtime does NOT allow CAP_STATS */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_CAPABILITY_DENIED);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Load program requesting CAP_MAP_ITERATE without runtime granting it
 */
TEST(load_ungrantable_cap_map_iterate) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_MAP_ITERATE\"",
                                         NULL);
    ASSERT(pkg_len > 0);

    /* Runtime does NOT allow CAP_MAP_ITERATE */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_CAPABILITY_DENIED);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Load program requesting multiple caps, one ungrantable
 */
TEST(load_ungrantable_one_of_many) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\",\"CAP_EMIT\"",
                                         NULL);
    ASSERT(pkg_len > 0);

    /* Runtime allows LOG and TIME but NOT EMIT */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_CAPABILITY_DENIED);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Runtime with zero allowed capabilities rejects any capability request
 */
TEST(load_ungrantable_zero_allowed) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\"",
                                         NULL);
    ASSERT(pkg_len > 0);

    /* Runtime allows NOTHING */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = 0,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    ASSERT_EQ(err, MBPF_ERR_CAPABILITY_DENIED);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* ============================================================================
 * Test Cases - Call helper without required capability (exception)
 * ============================================================================ */

/*
 * Test: Call mbpf.nowNs without CAP_TIME throws TypeError (undefined)
 * This verifies step 2: "Call helper without required capability - verify exception"
 */
TEST(call_nowNs_without_cap_time) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        var out = [0, 0];\n"
        "        mbpf.nowNs(out);  /* Should throw - nowNs is undefined */\n"
        "        return -1;  /* Should not reach here */\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) return 0;\n"
        "        return -2;  /* Wrong exception type */\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\"",  /* No CAP_TIME */
                                         NULL);
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
    ASSERT_EQ(rc, 0);  /* Program caught exception, returned 0 */

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test: Call mbpf.emit without CAP_EMIT throws TypeError (undefined)
 */
TEST(call_emit_without_cap_emit) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        mbpf.emit(1, new Uint8Array(4));\n"
        "        return -1;\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) return 0;\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\"",  /* No CAP_EMIT */
                                         NULL);
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
 * Test: Call mbpf.stats without CAP_STATS throws TypeError (undefined)
 */
TEST(call_stats_without_cap_stats) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        var out = {};\n"
        "        mbpf.stats(out);\n"
        "        return -1;\n"
        "    } catch (e) {\n"
        "        if (e instanceof TypeError) return 0;\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\"",  /* No CAP_STATS */
                                         NULL);
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
 * Test: Call maps.lookup without CAP_MAP_READ throws with message
 */
TEST(call_map_lookup_without_cap_map_read) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        var buf = new Uint8Array(4);\n"
        "        maps.testmap.lookup(0, buf);\n"
        "        return -1;\n"
        "    } catch (e) {\n"
        "        if (e.message && e.message.indexOf('CAP_MAP_READ') >= 0) return 0;\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_MAP_WRITE\"",  /* No CAP_MAP_READ */
                                         "{\"name\":\"testmap\",\"type\":1,"
                                         "\"key_size\":4,\"max_entries\":10,\"value_size\":4}");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_MAP_WRITE,
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
 * Test: Call maps.update without CAP_MAP_WRITE throws with message
 */
TEST(call_map_update_without_cap_map_write) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        var buf = new Uint8Array(4);\n"
        "        buf[0] = 42;\n"
        "        maps.testmap.update(0, buf);\n"
        "        return -1;\n"
        "    } catch (e) {\n"
        "        if (e.message && e.message.indexOf('CAP_MAP_WRITE') >= 0) return 0;\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_MAP_READ\"",  /* No CAP_MAP_WRITE */
                                         "{\"name\":\"testmap\",\"type\":1,"
                                         "\"key_size\":4,\"max_entries\":10,\"value_size\":4}");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_MAP_READ,
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
 * Test: Call maps.nextKey without CAP_MAP_ITERATE throws with message
 */
TEST(call_map_nextkey_without_cap_map_iterate) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        var outKey = new Uint8Array(4);\n"
        "        maps.testmap.nextKey(null, outKey);\n"
        "        return -1;\n"
        "    } catch (e) {\n"
        "        if (e.message && e.message.indexOf('CAP_MAP_ITERATE') >= 0) return 0;\n"
        "        return -2;\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"",  /* No CAP_MAP_ITERATE */
                                         "{\"name\":\"testmap\",\"type\":2,"
                                         "\"key_size\":4,\"max_entries\":10,\"value_size\":4}");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
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
 * Test Cases - Error message verification
 * ============================================================================ */

/*
 * Test: mbpf_error_string returns informative message for CAPABILITY_DENIED
 */
TEST(error_string_capability_denied) {
    const char *msg = mbpf_error_string(MBPF_ERR_CAPABILITY_DENIED);
    ASSERT_NOT_NULL(msg);
    ASSERT(strlen(msg) > 0);
    /* Verify the message mentions "capability" */
    ASSERT(strstr(msg, "capability") != NULL);
    return 0;
}

/*
 * Test: Error string is different from unknown error
 */
TEST(error_string_not_unknown) {
    const char *cap_denied_msg = mbpf_error_string(MBPF_ERR_CAPABILITY_DENIED);
    const char *unknown_msg = mbpf_error_string((mbpf_error_t)-999);
    ASSERT(strcmp(cap_denied_msg, unknown_msg) != 0);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Error Capability Denied Tests\n");
    printf("=======================================\n\n");

    printf("Load ungrantable capability tests:\n");
    RUN_TEST(load_ungrantable_cap_emit);
    RUN_TEST(load_ungrantable_cap_time);
    RUN_TEST(load_ungrantable_cap_stats);
    RUN_TEST(load_ungrantable_cap_map_iterate);
    RUN_TEST(load_ungrantable_one_of_many);
    RUN_TEST(load_ungrantable_zero_allowed);

    printf("\nCall helper without required capability tests:\n");
    RUN_TEST(call_nowNs_without_cap_time);
    RUN_TEST(call_emit_without_cap_emit);
    RUN_TEST(call_stats_without_cap_stats);
    RUN_TEST(call_map_lookup_without_cap_map_read);
    RUN_TEST(call_map_update_without_cap_map_write);
    RUN_TEST(call_map_nextkey_without_cap_map_iterate);

    printf("\nError message verification tests:\n");
    RUN_TEST(error_string_capability_denied);
    RUN_TEST(error_string_not_unknown);

    printf("\n=======================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
