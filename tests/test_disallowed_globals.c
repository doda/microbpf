/*
 * microBPF Disallowed Globals Security Tests
 *
 * Tests for security restrictions on dangerous global APIs:
 * 1. Verify Function constructor is not available
 * 2. Verify eval is not available (unless explicitly enabled)
 * 3. Verify filesystem APIs are not available
 * 4. Verify network APIs are not available
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

/* Log capture buffer */
static char captured_logs[8192];
static size_t captured_log_offset = 0;

static void reset_log_capture(void) {
    captured_logs[0] = '\0';
    captured_log_offset = 0;
}

static void test_log_fn(int level, const char *msg) {
    (void)level;
    size_t len = strlen(msg);
    if (captured_log_offset + len + 2 < sizeof(captured_logs)) {
        memcpy(captured_logs + captured_log_offset, msg, len);
        captured_log_offset += len;
        captured_logs[captured_log_offset++] = '\n';
        captured_logs[captured_log_offset] = '\0';
    }
}

/* Helper to build a basic manifest */
static size_t build_manifest(uint8_t *buf, size_t cap, int hook_type) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"security_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        hook_type);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest(manifest, sizeof(manifest), hook_type);
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
    const char *js_file = "/tmp/test_security.js";
    const char *bc_file = "/tmp/test_security.qjbc";

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

/* Helper to run a JS program and get return code */
static int run_js_program(const char *js_code, int32_t *out_rc) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    if (!bytecode) return -1;

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT);
    if (pkg_len == 0) {
        free(bytecode);
        return -1;
    }

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    cfg.default_heap_size = 65536;
    cfg.default_max_steps = 100000;
    cfg.allowed_capabilities = MBPF_CAP_LOG;

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    if (!rt) {
        free(bytecode);
        return -1;
    }

    reset_log_capture();

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    if (err != MBPF_OK) {
        mbpf_runtime_shutdown(rt);
        free(bytecode);
        return -1;
    }

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    if (err != MBPF_OK) {
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        free(bytecode);
        return -1;
    }

    *out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, out_rc);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);

    return err;
}

/* ============================================================================
 * Test Cases - Function constructor is not available
 * ============================================================================ */

/*
 * Test 1: Function constructor is undefined
 *
 * Verification: typeof Function === 'undefined'
 */
TEST(function_constructor_undefined) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof Function === 'undefined') return 1;\n"
        "    return -1;\n"  /* Failure: Function should be undefined */
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* Function is undefined */
    return 0;
}

/*
 * Test 2: Attempting to use Function constructor throws
 *
 * Verification: new Function(...) throws an error
 */
TEST(function_constructor_throws) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        var f = new Function('return 42');\n"
        "        return -1;\n"  /* Should not reach here */
        "    } catch (e) {\n"
        "        return 1;\n"  /* Exception caught as expected */
        "    }\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* Exception caught */
    return 0;
}

/*
 * Test 3: Direct Function constructor access is blocked
 *
 * Verification: Using the global Function constructor throws.
 */
TEST(function_direct_access_blocked) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Direct Function access is blocked */\n"
        "    try {\n"
        "        Function('return 42');\n"
        "        return -1;\n"  /* Should not reach here */
        "    } catch (e) {\n"
        "        return 1;\n"  /* Exception caught as expected */
        "    }\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* Exception caught */
    return 0;
}

/*
 * Test 4: Function constructor is not reachable via function.prototype
 *
 * Verification: (function(){}).constructor is undefined
 */
TEST(function_constructor_property_undefined) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var ctor = (function(){}).constructor;\n"
        "    if (typeof ctor === 'undefined') return 1;\n"
        "    return -1;\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* constructor is undefined */
    return 0;
}

/* ============================================================================
 * Test Cases - eval is not available
 * ============================================================================ */

/*
 * Test 5: eval is undefined
 *
 * Verification: typeof eval === 'undefined'
 */
TEST(eval_undefined) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof eval === 'undefined') return 1;\n"
        "    return -1;\n"  /* Failure: eval should be undefined */
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* eval is undefined */
    return 0;
}

/*
 * Test 6: Attempting to use eval throws
 *
 * Verification: eval(...) throws an error
 */
TEST(eval_throws) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        var result = eval('1 + 1');\n"
        "        return -1;\n"  /* Should not reach here */
        "    } catch (e) {\n"
        "        return 1;\n"  /* Exception caught as expected */
        "    }\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* Exception caught */
    return 0;
}

/* ============================================================================
 * Test Cases - Filesystem APIs are not available
 * ============================================================================ */

/*
 * Test 7: require is not available
 *
 * Verification: typeof require === 'undefined'
 */
TEST(require_not_available) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof require === 'undefined') return 1;\n"
        "    return -1;\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* require is undefined */
    return 0;
}

/*
 * Test 8: process is not available (Node.js global)
 *
 * Verification: typeof process === 'undefined'
 */
TEST(process_not_available) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof process === 'undefined') return 1;\n"
        "    return -1;\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* process is undefined */
    return 0;
}

/*
 * Test 9: Deno global not available
 *
 * Verification: typeof Deno === 'undefined'
 */
TEST(deno_not_available) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof Deno === 'undefined') return 1;\n"
        "    return -1;\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* Deno is undefined */
    return 0;
}

/*
 * Test 10: load() throws (disabled in mbpf_stdlib.c)
 *
 * Verification: load() is not functional
 */
TEST(load_throws) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        load('/etc/passwd');\n"
        "        return -1;\n"  /* Should not reach here */
        "    } catch (e) {\n"
        "        return 1;\n"  /* Exception caught as expected */
        "    }\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* Exception caught */
    return 0;
}

/* ============================================================================
 * Test Cases - Network APIs are not available
 * ============================================================================ */

/*
 * Test 11: fetch is not available
 *
 * Verification: typeof fetch === 'undefined'
 */
TEST(fetch_not_available) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof fetch === 'undefined') return 1;\n"
        "    return -1;\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* fetch is undefined */
    return 0;
}

/*
 * Test 12: XMLHttpRequest is not available
 *
 * Verification: typeof XMLHttpRequest === 'undefined'
 */
TEST(xmlhttprequest_not_available) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof XMLHttpRequest === 'undefined') return 1;\n"
        "    return -1;\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* XMLHttpRequest is undefined */
    return 0;
}

/*
 * Test 13: WebSocket is not available
 *
 * Verification: typeof WebSocket === 'undefined'
 */
TEST(websocket_not_available) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof WebSocket === 'undefined') return 1;\n"
        "    return -1;\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* WebSocket is undefined */
    return 0;
}

/* ============================================================================
 * Test Cases - Additional security checks
 * ============================================================================ */

/*
 * Test 14: setTimeout is not functional
 *
 * Verification: setTimeout throws (disabled in mbpf_stdlib.c)
 */
TEST(settimeout_throws) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        setTimeout(function(){}, 100);\n"
        "        return -1;\n"  /* Should not reach here */
        "    } catch (e) {\n"
        "        return 1;\n"  /* Exception caught as expected */
        "    }\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* Exception caught */
    return 0;
}

/*
 * Test 15: clearTimeout is not functional
 *
 * Verification: clearTimeout throws (disabled in mbpf_stdlib.c)
 */
TEST(cleartimeout_throws) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        clearTimeout(1);\n"
        "        return -1;\n"  /* Should not reach here */
        "    } catch (e) {\n"
        "        return 1;\n"  /* Exception caught as expected */
        "    }\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* Exception caught */
    return 0;
}

/*
 * Test 16: Normal JS operations still work
 *
 * Verification: Basic JS operations are not affected by security restrictions
 */
TEST(normal_operations_work) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var arr = [1, 2, 3];\n"
        "    var sum = arr.reduce(function(a, b) { return a + b; }, 0);\n"
        "    if (sum !== 6) return -1;\n"
        "    \n"
        "    var obj = {a: 1, b: 2};\n"
        "    if (obj.a + obj.b !== 3) return -2;\n"
        "    \n"
        "    var str = 'hello';\n"
        "    if (str.length !== 5) return -3;\n"
        "    \n"
        "    return 1;\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* All operations work */
    return 0;
}

/*
 * Test 17: mbpf helpers are still available
 *
 * Verification: mbpf.log and other helpers work despite security restrictions
 */
TEST(mbpf_helpers_available) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf === 'undefined') return -1;\n"
        "    if (typeof mbpf.log !== 'function') return -2;\n"
        "    if (typeof mbpf.apiVersion === 'undefined') return -3;\n"
        "    mbpf.log(1, 'security test log');\n"
        "    return 1;\n"
        "}\n";

    int32_t rc;
    int err = run_js_program(js_code, &rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(rc, 1);  /* mbpf helpers work */
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Disallowed Globals Security Tests\n");
    printf("===========================================\n\n");

    printf("Function constructor tests:\n");
    RUN_TEST(function_constructor_undefined);
    RUN_TEST(function_constructor_throws);
    RUN_TEST(function_direct_access_blocked);
    RUN_TEST(function_constructor_property_undefined);

    printf("\neval tests:\n");
    RUN_TEST(eval_undefined);
    RUN_TEST(eval_throws);

    printf("\nFilesystem API tests:\n");
    RUN_TEST(require_not_available);
    RUN_TEST(process_not_available);
    RUN_TEST(deno_not_available);
    RUN_TEST(load_throws);

    printf("\nNetwork API tests:\n");
    RUN_TEST(fetch_not_available);
    RUN_TEST(xmlhttprequest_not_available);
    RUN_TEST(websocket_not_available);

    printf("\nAdditional security tests:\n");
    RUN_TEST(settimeout_throws);
    RUN_TEST(cleartimeout_throws);
    RUN_TEST(normal_operations_work);
    RUN_TEST(mbpf_helpers_available);

    printf("\n===========================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
