/*
 * microBPF SECURITY Hook Tests
 *
 * Tests for MBPF_HOOK_SECURITY authorization hook:
 * 1. Load program targeting MBPF_HOOK_SECURITY
 * 2. Attach to security decision hook
 * 3. Invoke with authorization context
 * 4. Verify allow/deny return codes are honored
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

/* Helper to build a minimal valid JSON manifest with SECURITY hook type */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    const char *json =
        "{"
        "\"program_name\":\"security_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":5,"
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

    uint8_t manifest[512];
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
    const char *js_file = "/tmp/test_hook_security.js";
    const char *bc_file = "/tmp/test_hook_security.qjbc";

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
 * Test Cases - hook-security
 * ============================================================================ */

/*
 * Test 1: Load program targeting MBPF_HOOK_SECURITY
 */
TEST(load_security_program) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
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

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 2: Attach to security decision hook
 */
TEST(attach_to_security) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 3: Verify hook ABI version for SECURITY
 */
TEST(hook_abi_version) {
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_SECURITY), 1);
    return 0;
}

/*
 * Test 4: Invoke with authorization context
 */
TEST(invoke_with_auth_context) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    if (ctx.subject_id !== 1000) return -2;\n"
        "    if (ctx.object_id !== 42) return -3;\n"
        "    if (ctx.action !== 1) return -4;\n"
        "    return 0;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    /* Create SECURITY context */
    mbpf_ctx_security_v1_t ctx = {
        .abi_version = 1,
        .subject_id = 1000,
        .object_id = 42,
        .action = 1,
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_ALLOW);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: MBPF_SEC_ALLOW (0) allows the operation
 */
TEST(sec_allow_allows_operation) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_security_v1_t ctx = {
        .abi_version = 1,
        .subject_id = 100,
        .object_id = 1,
        .action = 0,
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_ALLOW);

    /* Verify stats show success */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: MBPF_SEC_DENY (1) denies the operation
 */
TEST(sec_deny_denies_operation) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_security_v1_t ctx = {
        .abi_version = 1,
        .subject_id = 100,
        .object_id = 1,
        .action = 0,
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);

    /* Verify stats show success (program ran successfully, just returned DENY) */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);
    ASSERT_EQ(stats.exceptions, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: MBPF_SEC_ABORT (2) handled appropriately
 */
TEST(sec_abort_handled) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 2;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_security_v1_t ctx = {
        .abi_version = 1,
        .subject_id = 100,
        .object_id = 1,
        .action = 0,
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_ABORT);

    /* Verify stats show success (program ran successfully) */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.successes, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Decision based on subject/object - policy enforcement
 * Deny access if subject_id 0 (unprivileged) tries to access object_id 1 (privileged resource)
 */
TEST(decision_based_on_policy) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Deny unprivileged (subject 0) access to privileged resource (object 1) */\n"
        "    if (ctx.subject_id === 0 && ctx.object_id === 1) {\n"
        "        return 1;\n"
        "    }\n"
        "    return 0;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    /* Unprivileged trying privileged access - should be denied */
    mbpf_ctx_security_v1_t ctx1 = {
        .abi_version = 1,
        .subject_id = 0,  /* unprivileged */
        .object_id = 1,   /* privileged resource */
        .action = 0,
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx1, sizeof(ctx1), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);

    /* Privileged access - should be allowed */
    mbpf_ctx_security_v1_t ctx2 = {
        .abi_version = 1,
        .subject_id = 1000,  /* privileged */
        .object_id = 1,      /* privileged resource */
        .action = 0,
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx2, sizeof(ctx2), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_ALLOW);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Decision based on action - only allow read (action=1), deny write (action=2)
 */
TEST(decision_based_on_action) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Only allow read (1), deny write (2) */\n"
        "    if (ctx.action === 2) {\n"
        "        return 1;\n"
        "    }\n"
        "    return 0;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    /* Read action - should be allowed */
    mbpf_ctx_security_v1_t ctx_read = {
        .abi_version = 1,
        .subject_id = 100,
        .object_id = 1,
        .action = 1,  /* read */
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx_read, sizeof(ctx_read), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_ALLOW);

    /* Write action - should be denied */
    mbpf_ctx_security_v1_t ctx_write = {
        .abi_version = 1,
        .subject_id = 100,
        .object_id = 1,
        .action = 2,  /* write */
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx_write, sizeof(ctx_write), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Exception in program returns safe default (DENY for security hooks).
 * Security hooks use fail-safe semantics: if a program fails, deny the operation.
 */
TEST(exception_returns_safe_default) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    throw new Error('intentional error');\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_security_v1_t ctx = {
        .abi_version = 1,
        .subject_id = 100,
        .object_id = 1,
        .action = 0,
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    /* On exception, security hooks return DENY (fail-safe) */
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);

    /* Verify exception was counted */
    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.exceptions, 1);
    ASSERT_EQ(stats.successes, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 11: Verify flags field is accessible
 */
TEST(flags_field_accessible) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.flags !== 1) return -1;\n"
        "    return 0;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_security_v1_t ctx = {
        .abi_version = 1,
        .subject_id = 100,
        .object_id = 1,
        .action = 0,
        .flags = MBPF_CTX_F_TRUNCATED,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Read context data using read methods
 */
TEST(read_context_data) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.data_len < 8) return -1;\n"
        "    if (ctx.readU8(0) !== 0xDE) return -2;\n"
        "    if (ctx.readU8(1) !== 0xAD) return -3;\n"
        "    if (ctx.readU16LE(0) !== 0xADDE) return -4;\n"
        "    if (ctx.readU32LE(0) !== 0xEFBEADDE) return -5;\n"
        "    var buf = new Uint8Array(4);\n"
        "    var n = ctx.readBytes(4, 4, buf);\n"
        "    if (n !== 4) return -6;\n"
        "    if (buf[0] !== 0x12) return -7;\n"
        "    if (buf[1] !== 0x34) return -8;\n"
        "    if (buf[2] !== 0x56) return -9;\n"
        "    if (buf[3] !== 0x78) return -10;\n"
        "    return 0;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    /* 0xDEADBEEF in little-endian, followed by 0x12345678 */
    uint8_t context_data[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78};
    mbpf_ctx_security_v1_t ctx = {
        .abi_version = 1,
        .subject_id = 100,
        .object_id = 1,
        .action = 0,
        .flags = 0,
        .data_len = 8,
        .data = context_data,
        .read_fn = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 13: Multiple invocations update stats correctly
 */
TEST(multiple_invocations) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    for (int i = 0; i < 10; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_SECURITY, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, MBPF_SEC_ALLOW);
    }

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 10);
    ASSERT_EQ(stats.successes, 10);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 14: Null context returns null to JS
 */
TEST(null_context) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return 0;\n"
        "    return 1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_ALLOW);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 15: Detach and verify program no longer runs
 */
TEST(detach_stops_execution) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_security_v1_t ctx = {
        .abi_version = 1,
        .subject_id = 100,
        .object_id = 1,
        .action = 0,
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };

    /* Run while attached - should return DENY */
    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);

    /* Detach */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    /* Run after detach - should return default (ALLOW/0) */
    out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, MBPF_SEC_ALLOW);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 16: Hook type mismatch - SECURITY program cannot attach to NET_RX
 */
TEST(hook_mismatch_rejected) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    return 0;\n"
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

    /* Try to attach SECURITY program to NET_RX hook - should fail */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 17: Complex policy - RBAC style with data inspection
 */
TEST(rbac_policy_with_data) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* RBAC policy:\n"
        "     * - subject_id 0-99: no access\n"
        "     * - subject_id 100-999: read-only (action 1)\n"
        "     * - subject_id 1000+: full access\n"
        "     */\n"
        "    if (ctx.subject_id < 100) {\n"
        "        return 1;\n"
        "    }\n"
        "    if (ctx.subject_id < 1000 && ctx.action !== 1) {\n"
        "        return 1;\n"
        "    }\n"
        "    return 0;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_SECURITY);
    ASSERT_EQ(err, MBPF_OK);

    /* Test 1: No access for subject_id 50 */
    mbpf_ctx_security_v1_t ctx1 = {
        .abi_version = 1,
        .subject_id = 50,
        .object_id = 1,
        .action = 1,  /* read */
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };
    int32_t out_rc;
    mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx1, sizeof(ctx1), &out_rc);
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);

    /* Test 2: Read-only for subject_id 500 */
    mbpf_ctx_security_v1_t ctx2 = {
        .abi_version = 1,
        .subject_id = 500,
        .object_id = 1,
        .action = 1,  /* read - allowed */
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };
    mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx2, sizeof(ctx2), &out_rc);
    ASSERT_EQ(out_rc, MBPF_SEC_ALLOW);

    /* Test 3: Write denied for subject_id 500 */
    mbpf_ctx_security_v1_t ctx3 = {
        .abi_version = 1,
        .subject_id = 500,
        .object_id = 1,
        .action = 2,  /* write - denied */
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };
    mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx3, sizeof(ctx3), &out_rc);
    ASSERT_EQ(out_rc, MBPF_SEC_DENY);

    /* Test 4: Full access for subject_id 1500 */
    mbpf_ctx_security_v1_t ctx4 = {
        .abi_version = 1,
        .subject_id = 1500,
        .object_id = 1,
        .action = 2,  /* write - allowed */
        .flags = 0,
        .data_len = 0,
        .data = NULL,
        .read_fn = NULL
    };
    mbpf_run(rt, MBPF_HOOK_SECURITY, &ctx4, sizeof(ctx4), &out_rc);
    ASSERT_EQ(out_rc, MBPF_SEC_ALLOW);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF SECURITY Hook Tests\n");
    printf("============================\n\n");

    printf("Load and attach tests:\n");
    RUN_TEST(load_security_program);
    RUN_TEST(attach_to_security);
    RUN_TEST(hook_abi_version);

    printf("\nContext and execution tests:\n");
    RUN_TEST(invoke_with_auth_context);
    RUN_TEST(null_context);
    RUN_TEST(multiple_invocations);

    printf("\nDecision return value tests:\n");
    RUN_TEST(sec_allow_allows_operation);
    RUN_TEST(sec_deny_denies_operation);
    RUN_TEST(sec_abort_handled);

    printf("\nPolicy enforcement tests:\n");
    RUN_TEST(decision_based_on_policy);
    RUN_TEST(decision_based_on_action);
    RUN_TEST(rbac_policy_with_data);

    printf("\nContext field tests:\n");
    RUN_TEST(flags_field_accessible);
    RUN_TEST(read_context_data);

    printf("\nError handling tests:\n");
    RUN_TEST(exception_returns_safe_default);

    printf("\nHook validation tests:\n");
    RUN_TEST(hook_mismatch_rejected);

    printf("\nLifecycle tests:\n");
    RUN_TEST(detach_stops_execution);

    printf("\n============================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
