/*
 * microBPF Program Attach/Detach Tests
 *
 * Tests for mbpf_program_attach and mbpf_program_detach APIs:
 * - Load a program targeting MBPF_HOOK_TRACEPOINT
 * - Call mbpf_program_attach with matching hook
 * - Verify attach returns success
 * - Call mbpf_program_detach
 * - Verify detach returns success
 * - Verify program no longer runs when hook fires after detach
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

/* Helper to build a minimal valid JSON manifest with specific hook type */
static size_t build_test_manifest(uint8_t *buf, size_t cap, int hook_type) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"attach_test\","
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

/* Build a complete .mbpf package with bytecode */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *bytecode, size_t bc_len,
                                  int hook_type) {
    if (cap < 256) return 0;

    uint8_t manifest[512];
    size_t manifest_len = build_test_manifest(manifest, sizeof(manifest), hook_type);
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
    const char *js_file = "/tmp/test_attach_detach.js";
    const char *bc_file = "/tmp/test_attach_detach.qjbc";

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
 * Test Cases - program-attach-detach
 * ============================================================================ */

/* Test 1: Load a program targeting MBPF_HOOK_TRACEPOINT */
TEST(load_tracepoint_program) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 2: Call mbpf_program_attach with matching hook - verify success */
TEST(attach_returns_success) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Attach to TRACEPOINT hook */
    int err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 3: Call mbpf_program_detach - verify success */
TEST(detach_returns_success) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Attach first */
    int err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Detach */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 4: Verify program runs when attached and hook fires */
TEST(program_runs_when_attached) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 42; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Attach */
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Fire the hook */
    int32_t out_rc = 0;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);  /* Program should have run and returned 42 */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 5: Verify program no longer runs when hook fires after detach */
TEST(program_not_run_after_detach) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 99; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Attach */
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Verify program runs when attached */
    int32_t out_rc = 0;
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(out_rc, 99);

    /* Check invocation count increased */
    mbpf_stats_t stats = {0};
    mbpf_program_stats(prog, &stats);
    uint64_t invocations_before = stats.invocations;
    ASSERT(invocations_before > 0);

    /* Detach */
    int err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Fire the hook again */
    out_rc = -1;  /* Set to different value to detect if it's modified */
    err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);

    /* Should return default (MBPF_NET_PASS = 0) since no programs attached */
    ASSERT_EQ(out_rc, MBPF_NET_PASS);

    /* Invocation count should NOT have increased */
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, invocations_before);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 6: Verify stats tracking during attach/run cycle */
TEST(stats_tracked_correctly) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 1; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Run multiple times */
    for (int i = 0; i < 5; i++) {
        int32_t out_rc = 0;
        mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    }

    mbpf_stats_t stats = {0};
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 5);
    ASSERT_EQ(stats.successes, 5);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 7: Attach errors - already attached */
TEST(attach_already_attached_error) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* First attach succeeds */
    int err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    /* Second attach fails */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_ALREADY_ATTACHED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 8: Detach errors - not attached */
TEST(detach_not_attached_error) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Detach without attach fails */
    int err = mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_NOT_ATTACHED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 9: Detach errors - wrong hook */
TEST(detach_wrong_hook_error) {
    const char *js_code =
        "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* Attach to TRACEPOINT */
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);

    /* Detach from TIMER fails (wrong hook) */
    int err = mbpf_program_detach(rt, prog, MBPF_HOOK_TIMER);
    ASSERT_EQ(err, MBPF_ERR_NOT_ATTACHED);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 10: Invalid args - NULL runtime */
TEST(invalid_args_null_runtime) {
    int err = mbpf_program_attach(NULL, (mbpf_program_t *)0x1234, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    err = mbpf_program_detach(NULL, (mbpf_program_t *)0x1234, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    return 0;
}

/* Test 11: Invalid args - NULL program */
TEST(invalid_args_null_program) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    int err = mbpf_program_attach(rt, NULL, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    err = mbpf_program_detach(rt, NULL, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 12: Multiple programs attached to same hook */
TEST(multiple_programs_same_hook) {
    const char *js_code1 = "function mbpf_prog(ctx) { return 1; }\n";
    const char *js_code2 = "function mbpf_prog(ctx) { return 2; }\n";

    size_t bc_len1, bc_len2;
    uint8_t *bc1 = compile_js_to_bytecode(js_code1, &bc_len1);
    uint8_t *bc2 = compile_js_to_bytecode(js_code2, &bc_len2);
    ASSERT_NOT_NULL(bc1);
    ASSERT_NOT_NULL(bc2);

    uint8_t pkg1[8192], pkg2[8192];
    size_t len1 = build_mbpf_package(pkg1, sizeof(pkg1), bc1, bc_len1, MBPF_HOOK_TRACEPOINT);
    size_t len2 = build_mbpf_package(pkg2, sizeof(pkg2), bc2, bc_len2, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog1 = NULL, *prog2 = NULL;
    ASSERT_EQ(mbpf_program_load(rt, pkg1, len1, NULL, &prog1), MBPF_OK);
    ASSERT_EQ(mbpf_program_load(rt, pkg2, len2, NULL, &prog2), MBPF_OK);

    /* Attach both to same hook */
    ASSERT_EQ(mbpf_program_attach(rt, prog1, MBPF_HOOK_TRACEPOINT), MBPF_OK);
    ASSERT_EQ(mbpf_program_attach(rt, prog2, MBPF_HOOK_TRACEPOINT), MBPF_OK);

    /* Both should run (last one's return wins) */
    int32_t out_rc = 0;
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    /* Either 1 or 2 is acceptable, depending on execution order */
    ASSERT(out_rc == 1 || out_rc == 2);

    /* Check both have invocations */
    mbpf_stats_t stats1 = {0}, stats2 = {0};
    mbpf_program_stats(prog1, &stats1);
    mbpf_program_stats(prog2, &stats2);
    ASSERT_EQ(stats1.invocations, 1);
    ASSERT_EQ(stats2.invocations, 1);

    mbpf_runtime_shutdown(rt);
    free(bc1);
    free(bc2);
    return 0;
}

/* Test 13: Attach to different hook types */
TEST(attach_to_different_hooks) {
    const char *js_code = "function mbpf_prog(ctx) { return 0; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    /* Create packages for different hook types */
    uint8_t pkg_tp[8192], pkg_timer[8192];
    size_t len_tp = build_mbpf_package(pkg_tp, sizeof(pkg_tp), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);
    size_t len_timer = build_mbpf_package(pkg_timer, sizeof(pkg_timer), bytecode, bc_len, MBPF_HOOK_TIMER);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog_tp = NULL, *prog_timer = NULL;
    ASSERT_EQ(mbpf_program_load(rt, pkg_tp, len_tp, NULL, &prog_tp), MBPF_OK);
    ASSERT_EQ(mbpf_program_load(rt, pkg_timer, len_timer, NULL, &prog_timer), MBPF_OK);

    /* Attach each to their hook */
    ASSERT_EQ(mbpf_program_attach(rt, prog_tp, MBPF_HOOK_TRACEPOINT), MBPF_OK);
    ASSERT_EQ(mbpf_program_attach(rt, prog_timer, MBPF_HOOK_TIMER), MBPF_OK);

    /* Fire TRACEPOINT - only prog_tp runs */
    int32_t out_rc = 0;
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);

    mbpf_stats_t stats_tp = {0}, stats_timer = {0};
    mbpf_program_stats(prog_tp, &stats_tp);
    mbpf_program_stats(prog_timer, &stats_timer);
    ASSERT_EQ(stats_tp.invocations, 1);
    ASSERT_EQ(stats_timer.invocations, 0);

    /* Fire TIMER - only prog_timer runs */
    mbpf_run(rt, MBPF_HOOK_TIMER, NULL, 0, &out_rc);

    mbpf_program_stats(prog_tp, &stats_tp);
    mbpf_program_stats(prog_timer, &stats_timer);
    ASSERT_EQ(stats_tp.invocations, 1);   /* Still 1 */
    ASSERT_EQ(stats_timer.invocations, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 14: Re-attach after detach */
TEST(reattach_after_detach) {
    const char *js_code = "function mbpf_prog(ctx) { return 77; }\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg), bytecode, bc_len, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog = NULL;
    mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);

    /* First attach/detach cycle */
    mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    int32_t out_rc = 0;
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(out_rc, 77);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(out_rc, 0);  /* Default */

    /* Second attach cycle */
    int err = mbpf_program_attach(rt, prog, MBPF_HOOK_TRACEPOINT);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(out_rc, 77);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/* Test 15: Exception in program doesn't prevent other programs from running */
TEST(exception_doesnt_block_others) {
    const char *js_code_bad = "function mbpf_prog(ctx) { throw new Error('oops'); }\n";
    const char *js_code_good = "function mbpf_prog(ctx) { return 55; }\n";

    size_t bc_len_bad, bc_len_good;
    uint8_t *bc_bad = compile_js_to_bytecode(js_code_bad, &bc_len_bad);
    uint8_t *bc_good = compile_js_to_bytecode(js_code_good, &bc_len_good);
    ASSERT_NOT_NULL(bc_bad);
    ASSERT_NOT_NULL(bc_good);

    uint8_t pkg_bad[8192], pkg_good[8192];
    size_t len_bad = build_mbpf_package(pkg_bad, sizeof(pkg_bad), bc_bad, bc_len_bad, MBPF_HOOK_TRACEPOINT);
    size_t len_good = build_mbpf_package(pkg_good, sizeof(pkg_good), bc_good, bc_len_good, MBPF_HOOK_TRACEPOINT);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    mbpf_program_t *prog_bad = NULL, *prog_good = NULL;
    ASSERT_EQ(mbpf_program_load(rt, pkg_bad, len_bad, NULL, &prog_bad), MBPF_OK);
    ASSERT_EQ(mbpf_program_load(rt, pkg_good, len_good, NULL, &prog_good), MBPF_OK);

    /* Attach both */
    mbpf_program_attach(rt, prog_bad, MBPF_HOOK_TRACEPOINT);
    mbpf_program_attach(rt, prog_good, MBPF_HOOK_TRACEPOINT);

    /* Run hook */
    int32_t out_rc = 0;
    int err = mbpf_run(rt, MBPF_HOOK_TRACEPOINT, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);

    /* Both should have run */
    mbpf_stats_t stats_bad = {0}, stats_good = {0};
    mbpf_program_stats(prog_bad, &stats_bad);
    mbpf_program_stats(prog_good, &stats_good);
    ASSERT_EQ(stats_bad.invocations, 1);
    ASSERT_EQ(stats_bad.exceptions, 1);
    ASSERT_EQ(stats_good.invocations, 1);
    ASSERT_EQ(stats_good.successes, 1);

    mbpf_runtime_shutdown(rt);
    free(bc_bad);
    free(bc_good);
    return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Program Attach/Detach Tests\n");
    printf("=====================================\n");

    printf("\nBasic attach/detach tests:\n");
    RUN_TEST(load_tracepoint_program);
    RUN_TEST(attach_returns_success);
    RUN_TEST(detach_returns_success);

    printf("\nHook execution tests:\n");
    RUN_TEST(program_runs_when_attached);
    RUN_TEST(program_not_run_after_detach);
    RUN_TEST(stats_tracked_correctly);

    printf("\nError handling tests:\n");
    RUN_TEST(attach_already_attached_error);
    RUN_TEST(detach_not_attached_error);
    RUN_TEST(detach_wrong_hook_error);
    RUN_TEST(invalid_args_null_runtime);
    RUN_TEST(invalid_args_null_program);

    printf("\nAdvanced scenarios:\n");
    RUN_TEST(multiple_programs_same_hook);
    RUN_TEST(attach_to_different_hooks);
    RUN_TEST(reattach_after_detach);
    RUN_TEST(exception_doesnt_block_others);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
