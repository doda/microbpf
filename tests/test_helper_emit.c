/*
 * microBPF Helper emit Tests
 *
 * Tests for mbpf.emit(eventId, bytes) helper:
 * 1. Request CAP_EMIT capability
 * 2. Call mbpf.emit(42, eventData)
 * 3. Verify event appears in ring buffer or platform event pipe
 * 4. Verify eventId and data are correctly captured
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
        "\"program_name\":\"emit_test\","
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
    const char *js_file = "/tmp/test_emit.js";
    const char *bc_file = "/tmp/test_emit.qjbc";

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
 * Test Cases - helper-emit
 * ============================================================================ */

/*
 * Test 1: emit function exists when CAP_EMIT is granted
 */
TEST(function_exists_with_cap_emit) {
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

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
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
 * Test 2: emit function does NOT exist without CAP_EMIT
 */
TEST(function_not_exists_without_cap_emit) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (typeof mbpf.emit === 'undefined') return 0;\n"
        "    return -1;  /* Should not have emit */\n"
        "}\n";

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(js_code, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[16384];
    size_t pkg_len = build_mbpf_package(pkg, sizeof(pkg),
                                         bytecode, bc_len,
                                         MBPF_HOOK_TRACEPOINT,
                                         "\"CAP_LOG\"");  /* No CAP_EMIT */
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
 * Test 3: emit returns true for valid event and event appears in buffer
 */
TEST(emit_basic_event) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var data = new Uint8Array([0x48, 0x65, 0x6C, 0x6C, 0x6F]);  /* 'Hello' */\n"
        "    var result = mbpf.emit(42, data);\n"
        "    return result ? 0 : -1;\n"
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

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
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

    /* Verify event was emitted */
    int count = mbpf_emit_count(prog);
    ASSERT_EQ(count, 1);

    /* Read the event */
    uint32_t event_id = 0;
    uint8_t data[64];
    int data_len = mbpf_emit_read(prog, &event_id, data, sizeof(data));
    ASSERT_EQ(data_len, 5);
    ASSERT_EQ(event_id, 42);
    ASSERT_EQ(data[0], 0x48);  /* 'H' */
    ASSERT_EQ(data[1], 0x65);  /* 'e' */
    ASSERT_EQ(data[2], 0x6C);  /* 'l' */
    ASSERT_EQ(data[3], 0x6C);  /* 'l' */
    ASSERT_EQ(data[4], 0x6F);  /* 'o' */

    /* Buffer should now be empty */
    count = mbpf_emit_count(prog);
    ASSERT_EQ(count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: emit multiple events
 */
TEST(emit_multiple_events) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.emit(1, new Uint8Array([0x41]));\n"
        "    mbpf.emit(2, new Uint8Array([0x42, 0x42]));\n"
        "    mbpf.emit(3, new Uint8Array([0x43, 0x43, 0x43]));\n"
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

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
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

    /* Verify 3 events were emitted */
    int count = mbpf_emit_count(prog);
    ASSERT_EQ(count, 3);

    /* Read event 1 */
    uint32_t event_id = 0;
    uint8_t data[64];
    int data_len = mbpf_emit_read(prog, &event_id, data, sizeof(data));
    ASSERT_EQ(data_len, 1);
    ASSERT_EQ(event_id, 1);
    ASSERT_EQ(data[0], 0x41);

    /* Read event 2 */
    data_len = mbpf_emit_read(prog, &event_id, data, sizeof(data));
    ASSERT_EQ(data_len, 2);
    ASSERT_EQ(event_id, 2);
    ASSERT_EQ(data[0], 0x42);
    ASSERT_EQ(data[1], 0x42);

    /* Read event 3 */
    data_len = mbpf_emit_read(prog, &event_id, data, sizeof(data));
    ASSERT_EQ(data_len, 3);
    ASSERT_EQ(event_id, 3);
    ASSERT_EQ(data[0], 0x43);
    ASSERT_EQ(data[1], 0x43);
    ASSERT_EQ(data[2], 0x43);

    /* Buffer should now be empty */
    count = mbpf_emit_count(prog);
    ASSERT_EQ(count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 5: emit with empty data
 */
TEST(emit_empty_data) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var data = new Uint8Array(0);\n"
        "    return mbpf.emit(100, data) ? 0 : -1;\n"
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

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
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

    /* Verify event was emitted with zero-length data */
    int count = mbpf_emit_count(prog);
    ASSERT_EQ(count, 1);

    uint32_t event_id = 0;
    uint8_t data[64];
    int data_len = mbpf_emit_read(prog, &event_id, data, sizeof(data));
    ASSERT_EQ(data_len, 0);
    ASSERT_EQ(event_id, 100);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: emit_peek reads without consuming
 */
TEST(emit_peek) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    mbpf.emit(77, new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]));\n"
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

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
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

    /* Peek at event */
    uint32_t event_id = 0;
    uint8_t data[64];
    int data_len = mbpf_emit_peek(prog, &event_id, data, sizeof(data));
    ASSERT_EQ(data_len, 4);
    ASSERT_EQ(event_id, 77);
    ASSERT_EQ(data[0], 0xDE);
    ASSERT_EQ(data[1], 0xAD);

    /* Count should still be 1 */
    int count = mbpf_emit_count(prog);
    ASSERT_EQ(count, 1);

    /* Read should return same event */
    event_id = 0;
    data_len = mbpf_emit_read(prog, &event_id, data, sizeof(data));
    ASSERT_EQ(data_len, 4);
    ASSERT_EQ(event_id, 77);

    /* Now count should be 0 */
    count = mbpf_emit_count(prog);
    ASSERT_EQ(count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: emit returns false for event too large (>256 bytes)
 */
TEST(emit_too_large) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var data = new Uint8Array(300);  /* Too large, max is 256 */\n"
        "    for (var i = 0; i < 300; i++) data[i] = i & 0xFF;\n"
        "    var result = mbpf.emit(1, data);\n"
        "    return result ? -1 : 0;  /* Expect false (failure) */\n"
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

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
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

    /* No events should be in buffer */
    int count = mbpf_emit_count(prog);
    ASSERT_EQ(count, 0);

    mbpf_program_detach(rt, prog, MBPF_HOOK_TRACEPOINT);
    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: TypeError for invalid eventId (not a number)
 */
TEST(type_error_invalid_event_id) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        mbpf.emit('not a number', new Uint8Array([1, 2, 3]));\n"
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
                                         "\"CAP_LOG\",\"CAP_EMIT\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
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
 * Test 9: TypeError for invalid bytes (not Uint8Array)
 */
TEST(type_error_invalid_bytes) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    try {\n"
        "        mbpf.emit(42, 'not a Uint8Array');\n"
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
                                         "\"CAP_LOG\",\"CAP_EMIT\"");
    ASSERT(pkg_len > 0);

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
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
 * Test 10: emit_dropped counts overflow
 */
TEST(emit_overflow_dropped) {
    /* Emit many small events to overflow the 4KB buffer.
     * Each event takes: 4 (eventId) + 4 (dataLen) + data = 8 + data bytes
     * With 10-byte data, each event = 18 bytes
     * 4096 / 18 ~ 227 events max
     * We emit 300 to ensure overflow */
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var data = new Uint8Array([0,1,2,3,4,5,6,7,8,9]);  /* 10 bytes */\n"
        "    for (var i = 0; i < 300; i++) {\n"
        "        mbpf.emit(i, data);\n"
        "    }\n"
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

    mbpf_runtime_config_t cfg = {
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_EMIT,
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

    /* Some events should have been dropped */
    int dropped = mbpf_emit_dropped(prog);
    ASSERT(dropped > 0);

    /* The remaining events + dropped should equal 300 */
    int count = mbpf_emit_count(prog);
    ASSERT(count + dropped == 300);

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

    printf("microBPF Helper emit Tests\n");
    printf("==========================\n\n");

    printf("Capability gating tests:\n");
    RUN_TEST(function_exists_with_cap_emit);
    RUN_TEST(function_not_exists_without_cap_emit);

    printf("\nBasic functionality tests:\n");
    RUN_TEST(emit_basic_event);
    RUN_TEST(emit_multiple_events);
    RUN_TEST(emit_empty_data);
    RUN_TEST(emit_peek);

    printf("\nEdge case tests:\n");
    RUN_TEST(emit_too_large);
    RUN_TEST(type_error_invalid_event_id);
    RUN_TEST(type_error_invalid_bytes);
    RUN_TEST(emit_overflow_dropped);

    printf("\n==========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
