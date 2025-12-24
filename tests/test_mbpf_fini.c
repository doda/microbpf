/*
 * microBPF mbpf_fini Entry Point Tests
 *
 * Tests for optional mbpf_fini entry function:
 * - Load program defining mbpf_fini function
 * - Unload program
 * - Verify mbpf_fini was called (best-effort)
 * - Load program without mbpf_fini - verify unload succeeds
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

/* Log capture for verifying mbpf_fini was called */
static char last_log_message[256] = {0};
static int fini_log_count = 0;

static void test_log_fn(int level, const char *msg) {
    (void)level;
    strncpy(last_log_message, msg, sizeof(last_log_message) - 1);
    last_log_message[sizeof(last_log_message) - 1] = '\0';
    if (strstr(msg, "mbpf_fini") != NULL) {
        fini_log_count++;
    }
}

/* Helper to build a minimal valid JSON manifest */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    const char *json =
        "{"
        "\"program_name\":\"fini_test\","
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

    uint8_t manifest[1024];
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
    /* magic "MBPF" in little-endian: 0x4D425046 */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    /* format_version = 1 */
    *p++ = 0x01; *p++ = 0x00;
    /* header_size */
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    /* flags = 0 */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* section_count = 2 */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    /* file_crc32 = 0 (disabled) */
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 0: MANIFEST (type=1) */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* crc32 */

    /* Section 1: BYTECODE (type=2) */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* type */
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
    const char *js_file = "/tmp/test_mbpf_fini.js";
    const char *bc_file = "/tmp/test_mbpf_fini.qjbc";

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
 * Test Cases - mbpf_fini entry point
 * ============================================================================ */

/*
 * Test 1: Load program defining mbpf_fini, unload, verify fini was called
 * We verify fini was called by having it throw (which logs a message).
 */
TEST(mbpf_fini_called_at_unload) {
    /* Program with mbpf_fini that throws - this is logged as best-effort */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "function mbpf_fini() {\n"
        "    throw new Error('fini was called');\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);
    ASSERT(pkg_len > 0);

    /* Reset log capture */
    last_log_message[0] = '\0';
    fini_log_count = 0;

    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    /* Unload - this should call mbpf_fini which throws */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Verify mbpf_fini was called by checking the exception log */
    ASSERT(fini_log_count > 0);
    ASSERT(strstr(last_log_message, "mbpf_fini") != NULL);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Program without mbpf_fini - unload should succeed
 */
TEST(unload_without_mbpf_fini_succeeds) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 42;\n"
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
    ASSERT_NOT_NULL(prog);

    /* Verify program works before unload */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Unload should succeed without mbpf_fini */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: mbpf_fini exception doesn't crash unload
 */
TEST(mbpf_fini_exception_handled) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n"
        "function mbpf_fini() { return undefined_variable.access; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);

    last_log_message[0] = '\0';
    fini_log_count = 0;
    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Unload should succeed despite mbpf_fini throwing */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Exception should have been logged */
    ASSERT(fini_log_count > 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: mbpf_fini that succeeds silently
 */
TEST(mbpf_fini_success_silent) {
    /* mbpf_fini that does nothing special - should not log errors */
    const char *js_code =
        "var fini_called = false;\n"
        "function mbpf_prog(ctx) { return 0; }\n"
        "function mbpf_fini() { fini_called = true; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);

    last_log_message[0] = '\0';
    fini_log_count = 0;
    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    /* No error should have been logged for successful fini */
    ASSERT_EQ(fini_log_count, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: mbpf_fini return value is ignored
 */
TEST(mbpf_fini_return_value_ignored) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n"
        "function mbpf_fini() { return 999; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Unload should succeed regardless of return value */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: mbpf_fini called per instance
 * This is verified by having mbpf_fini throw, which logs once per instance.
 */
TEST(mbpf_fini_called_per_instance) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n"
        "function mbpf_fini() { throw new Error('fini'); }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);

    last_log_message[0] = '\0';
    fini_log_count = 0;
    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Should have exactly 1 instance, so 1 fini call */
    ASSERT_EQ(fini_log_count, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: mbpf_fini can access global state
 */
TEST(mbpf_fini_access_global_state) {
    /* mbpf_fini accesses global state - should not crash */
    const char *js_code =
        "var counter = 0;\n"
        "function mbpf_init() { counter = 100; }\n"
        "function mbpf_prog(ctx) { counter++; return counter; }\n"
        "function mbpf_fini() {\n"
        "    if (counter < 100) {\n"
        "        throw new Error('counter not initialized');\n"
        "    }\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len);

    last_log_message[0] = '\0';
    fini_log_count = 0;
    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);

    /* Run a few times to modify counter */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = 0;
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(out_rc, 101);
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(out_rc, 102);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Unload - mbpf_fini checks counter >= 100, should not throw */
    err = mbpf_program_unload(rt, prog);
    ASSERT_EQ(err, MBPF_OK);

    /* No error logged means fini succeeded */
    ASSERT_EQ(fini_log_count, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Multiple programs with mbpf_fini
 */
TEST(multiple_programs_with_fini) {
    const char *js_code1 =
        "function mbpf_prog(ctx) { return 1; }\n"
        "function mbpf_fini() { throw new Error('fini1'); }\n";
    const char *js_code2 =
        "function mbpf_prog(ctx) { return 2; }\n"
        "function mbpf_fini() { throw new Error('fini2'); }\n";

    size_t bc_len1, bc_len2;
    uint8_t *bc1 = compile_js_to_bytecode(js_code1, &bc_len1);
    uint8_t *bc2 = compile_js_to_bytecode(js_code2, &bc_len2);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);

    uint8_t pkg1[8192], pkg2[8192];
    size_t pkg_len1 = build_mbpf_package(pkg1, sizeof(pkg1), bc1, bc_len1);
    size_t pkg_len2 = build_mbpf_package(pkg2, sizeof(pkg2), bc2, bc_len2);

    last_log_message[0] = '\0';
    fini_log_count = 0;
    mbpf_runtime_config_t cfg = {0};
    cfg.log_fn = test_log_fn;
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);

    mbpf_program_t *prog1 = NULL, *prog2 = NULL;
    int err = mbpf_program_load(rt, pkg1, pkg_len1, NULL, &prog1);
    ASSERT_EQ(err, MBPF_OK);
    err = mbpf_program_load(rt, pkg2, pkg_len2, NULL, &prog2);
    ASSERT_EQ(err, MBPF_OK);

    /* Unload first program */
    fini_log_count = 0;
    err = mbpf_program_unload(rt, prog1);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(fini_log_count, 1);

    /* Unload second program */
    fini_log_count = 0;
    err = mbpf_program_unload(rt, prog2);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(fini_log_count, 1);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

int main(void) {
    int passed = 0, failed = 0;

    printf("microBPF mbpf_fini Entry Point Tests\n");
    printf("=====================================\n\n");

    printf("mbpf_fini call verification tests:\n");
    RUN_TEST(mbpf_fini_called_at_unload);
    RUN_TEST(mbpf_fini_called_per_instance);

    printf("\nOptional behavior tests:\n");
    RUN_TEST(unload_without_mbpf_fini_succeeds);
    RUN_TEST(mbpf_fini_return_value_ignored);

    printf("\nGlobal access tests:\n");
    RUN_TEST(mbpf_fini_access_global_state);
    RUN_TEST(mbpf_fini_success_silent);

    printf("\nError handling tests:\n");
    RUN_TEST(mbpf_fini_exception_handled);

    printf("\nMultiple program tests:\n");
    RUN_TEST(multiple_programs_with_fini);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
