/*
 * microBPF Capability Enforcement Tests
 *
 * Tests for capability enforcement during load and runtime:
 * 1. Load program declaring CAP_LOG - verify succeeds
 * 2. Load program declaring CAP_EMIT without platform granting it - verify load fails
 * 3. Call helper requiring CAP_TIME without capability - verify throws
 * 4. Configure platform allow-list and verify enforcement
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

/* Helper to build a manifest with specified capabilities */
static size_t build_manifest_with_caps(uint8_t *buf, size_t cap, int hook_type,
                                       const char *capabilities) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"cap_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[%s]"
        "}",
        hook_type, capabilities);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type, const char *capabilities) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_caps(manifest, sizeof(manifest),
                                                    hook_type, capabilities);
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
    const char *js_file = "/tmp/test_cap.js";
    const char *bc_file = "/tmp/test_cap.qjbc";

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
 * Test Cases - capability-enforcement
 * ============================================================================ */

/*
 * Test 1: Load program declaring CAP_LOG - verify succeeds
 * CAP_LOG is allowed by default in the runtime.
 */
TEST(cap_log_allowed_succeeds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.log(0, 'test');\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\"");
    ASSERT(pkg_len > 0);

    /* Default runtime allows CAP_LOG */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Load program declaring CAP_EMIT without platform granting it - verify load fails
 */
TEST(cap_emit_denied_fails) {
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
                                         "\"CAP_LOG\",\"CAP_EMIT\"");
    ASSERT(pkg_len > 0);

    /* Runtime does NOT allow CAP_EMIT */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG,  /* Only LOG allowed */
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
 * Test 3: Load program declaring CAP_EMIT when platform grants it - verify succeeds
 */
TEST(cap_emit_allowed_succeeds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.emit !== 'function') return -1;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_EMIT\"");
    ASSERT(pkg_len > 0);

    /* Runtime allows CAP_EMIT */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

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
 * Test 4: Call helper requiring CAP_TIME without capability - helper not available
 * When a program doesn't declare CAP_TIME, the nowNs function is not installed.
 */
TEST(cap_time_helper_not_available) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.nowNs === 'undefined') return 0;\n"
        "    return -1;  /* Should not have nowNs */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\"");  /* No CAP_TIME */
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
 * Test 5: CAP_TIME denied at load time
 */
TEST(cap_time_denied_fails) {
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
                                         "\"CAP_LOG\",\"CAP_TIME\"");
    ASSERT(pkg_len > 0);

    /* Runtime does NOT allow CAP_TIME */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG,  /* Only LOG allowed */
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
 * Test 6: CAP_STATS denied at load time
 */
TEST(cap_stats_denied_fails) {
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
                                         "\"CAP_LOG\",\"CAP_STATS\"");
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
 * Test 7: Platform allow-list configuration - multiple caps
 */
TEST(platform_allowlist_multiple_caps) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.nowNs !== 'function') return -1;\n"
        "    if (typeof mbpf.emit !== 'function') return -2;\n"
        "    if (typeof mbpf.stats !== 'function') return -3;\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\",\"CAP_TIME\",\"CAP_EMIT\",\"CAP_STATS\"");
    ASSERT(pkg_len > 0);

    /* Runtime allows all these capabilities */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_TIME |
                               MBPF_CAP_EMIT | MBPF_CAP_STATS,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

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
 * Test 8: One missing cap in allowlist rejects
 */
TEST(platform_allowlist_partial_match_fails) {
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
                                         "\"CAP_LOG\",\"CAP_TIME\",\"CAP_EMIT\"");
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
 * Test 9: Empty capability request succeeds with restrictive allowlist
 */
TEST(empty_caps_request_succeeds) {
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
                                         "");  /* No capabilities */
    ASSERT(pkg_len > 0);

    /* Runtime only allows LOG */
    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG,
    };
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: CAP_MAP_READ/WRITE enforcement
 */
TEST(cap_map_read_write_denied) {
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
                                         "\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"");
    ASSERT(pkg_len > 0);

    /* Runtime doesn't allow map capabilities */
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
 * Test 11: Runtime without allowed_capabilities set uses defaults
 */
TEST(default_allowlist_allows_log_mapread_mapwrite) {
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
                                         "\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"");
    ASSERT(pkg_len > 0);

    /* Use default config */
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Calling undefined helper throws TypeError
 */
TEST(calling_undefined_helper_throws) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        mbpf.nowNs([0, 0]);\n"
        "        return -1;  /* Should have thrown */\n"
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
                                         "\"CAP_LOG\"");  /* No CAP_TIME */
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

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Capability Enforcement Tests\n");
    printf("======================================\n\n");

    printf("Load-time capability enforcement tests:\n");
    RUN_TEST(cap_log_allowed_succeeds);
    RUN_TEST(cap_emit_denied_fails);
    RUN_TEST(cap_emit_allowed_succeeds);
    RUN_TEST(cap_time_denied_fails);
    RUN_TEST(cap_stats_denied_fails);
    RUN_TEST(cap_map_read_write_denied);

    printf("\nRuntime capability enforcement tests:\n");
    RUN_TEST(cap_time_helper_not_available);
    RUN_TEST(calling_undefined_helper_throws);

    printf("\nPlatform allow-list configuration tests:\n");
    RUN_TEST(platform_allowlist_multiple_caps);
    RUN_TEST(platform_allowlist_partial_match_fails);
    RUN_TEST(empty_caps_request_succeeds);
    RUN_TEST(default_allowlist_allows_log_mapread_mapwrite);

    printf("\n======================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
