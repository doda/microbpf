/*
 * microBPF CUSTOM Hook Tests
 *
 * Tests for MBPF_HOOK_CUSTOM platform-defined hooks:
 * 1. Define custom hook with versioned schema
 * 2. Load program targeting custom hook
 * 3. Attach and invoke with custom context
 * 4. Verify custom context fields accessible
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

/* Helper to build a minimal valid JSON manifest with CUSTOM hook type */
static size_t build_test_manifest(uint8_t *buf, size_t cap) {
    char json[1024];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"custom_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":6,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":262144,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness());
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
    const char *js_file = "/tmp/test_hook_custom.js";
    const char *bc_file = "/tmp/test_hook_custom.qjbc";

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

static const uint8_t custom_read_data[] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0x99, 0x88, 0x77, 0x66
};
static const uint8_t custom_short_data[] = {
    0x01, 0x23, 0x45, 0x67
};

static int custom_read_fn(const void *ctx_blob, uint32_t off, uint32_t len, uint8_t *dst) {
    (void)ctx_blob;
    if (!dst || off >= sizeof(custom_read_data)) {
        return 0;
    }
    uint32_t avail = (uint32_t)sizeof(custom_read_data) - off;
    uint32_t to_copy = len < avail ? len : avail;
    memcpy(dst, custom_read_data + off, to_copy);
    return (int)to_copy;
}

static int custom_short_read_fn(const void *ctx_blob, uint32_t off, uint32_t len, uint8_t *dst) {
    (void)ctx_blob;
    if (!dst || off >= sizeof(custom_short_data)) {
        return 0;
    }
    uint32_t avail = (uint32_t)sizeof(custom_short_data) - off;
    uint32_t to_copy = len < avail ? len : avail;
    memcpy(dst, custom_short_data + off, to_copy);
    return (int)to_copy;
}

/* ============================================================================
 * Test Cases - hook-custom
 * ============================================================================ */

/*
 * Test 1: Define custom hook with versioned schema
 * Verify that the mbpf_ctx_custom_v1_t structure exists and can be populated
 */
TEST(define_custom_hook_schema) {
    /* Create a custom field schema for a hypothetical GPIO hook */
    mbpf_custom_field_t fields[] = {
        { .name = "gpio_pin", .offset = 0, .length = 0, .type = MBPF_FIELD_U8 },
        { .name = "gpio_value", .offset = 1, .length = 0, .type = MBPF_FIELD_U8 },
        { .name = "timestamp", .offset = 2, .length = 0, .type = MBPF_FIELD_U32 },
    };

    /* Create custom context with schema */
    uint8_t data[6] = {5, 1, 0x78, 0x56, 0x34, 0x12};  /* pin=5, value=1, timestamp=0x12345678 */
    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 100,  /* Platform-defined: GPIO event */
        .schema_version = 1,
        .flags = 0,
        .field_count = 3,
        .data_len = 6,
        .data = data,
        .read_fn = NULL,
        .fields = fields
    };

    ASSERT_EQ(ctx.abi_version, 1);
    ASSERT_EQ(ctx.custom_hook_id, 100);
    ASSERT_EQ(ctx.schema_version, 1);
    ASSERT_EQ(ctx.field_count, 3);
    ASSERT_EQ(ctx.data_len, 6);
    ASSERT_NOT_NULL(ctx.data);
    ASSERT_NOT_NULL(ctx.fields);

    return 0;
}

/*
 * Test 2: Load program targeting custom hook
 */
TEST(load_custom_program) {
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
 * Test 3: Attach to custom hook
 */
TEST(attach_to_custom) {
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 4: Verify hook ABI version for CUSTOM
 */
TEST(hook_abi_version) {
    ASSERT_EQ(mbpf_hook_abi_version(MBPF_HOOK_CUSTOM), 1);
    return 0;
}

/*
 * Test 5: Invoke with custom context and verify base fields accessible
 */
TEST(invoke_with_custom_context) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx === null) return -1;\n"
        "    if (ctx.custom_hook_id !== 100) return -2;\n"
        "    if (ctx.schema_version !== 1) return -3;\n"
        "    if (ctx.field_count !== 3) return -4;\n"
        "    if (ctx.data_len !== 6) return -5;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    /* Create custom field schema */
    mbpf_custom_field_t fields[] = {
        { .name = "gpio_pin", .offset = 0, .length = 0, .type = MBPF_FIELD_U8 },
        { .name = "gpio_value", .offset = 1, .length = 0, .type = MBPF_FIELD_U8 },
        { .name = "timestamp", .offset = 2, .length = 0, .type = MBPF_FIELD_U32 },
    };

    /* Create CUSTOM context */
    uint8_t data[6] = {5, 1, 0x78, 0x56, 0x34, 0x12};
    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 100,
        .schema_version = 1,
        .flags = 0,
        .field_count = 3,
        .data_len = 6,
        .data = data,
        .read_fn = NULL,
        .fields = fields
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 6: Verify custom schema field accessors - U8 fields
 */
TEST(custom_field_u8_access) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.gpio_pin !== 5) return -1;\n"
        "    if (ctx.gpio_value !== 1) return -2;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_custom_field_t fields[] = {
        { .name = "gpio_pin", .offset = 0, .length = 0, .type = MBPF_FIELD_U8 },
        { .name = "gpio_value", .offset = 1, .length = 0, .type = MBPF_FIELD_U8 },
        { .name = "timestamp", .offset = 2, .length = 0, .type = MBPF_FIELD_U32 },
    };

    uint8_t data[6] = {5, 1, 0x78, 0x56, 0x34, 0x12};
    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 100,
        .schema_version = 1,
        .flags = 0,
        .field_count = 3,
        .data_len = 6,
        .data = data,
        .read_fn = NULL,
        .fields = fields
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 7: Verify custom schema field accessors - U32 field
 */
TEST(custom_field_u32_access) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* timestamp is 0x12345678 in little-endian */\n"
        "    if (ctx.timestamp !== 0x12345678) return -1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_custom_field_t fields[] = {
        { .name = "gpio_pin", .offset = 0, .length = 0, .type = MBPF_FIELD_U8 },
        { .name = "gpio_value", .offset = 1, .length = 0, .type = MBPF_FIELD_U8 },
        { .name = "timestamp", .offset = 2, .length = 0, .type = MBPF_FIELD_U32 },
    };

    uint8_t data[6] = {5, 1, 0x78, 0x56, 0x34, 0x12};  /* timestamp = 0x12345678 LE */
    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 100,
        .schema_version = 1,
        .flags = 0,
        .field_count = 3,
        .data_len = 6,
        .data = data,
        .read_fn = NULL,
        .fields = fields
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 8: Verify custom schema field accessors - U16 field
 */
TEST(custom_field_u16_access) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* voltage is 0x1234 in little-endian */\n"
        "    if (ctx.voltage !== 0x1234) return -1;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_custom_field_t fields[] = {
        { .name = "voltage", .offset = 0, .length = 0, .type = MBPF_FIELD_U16 },
    };

    uint8_t data[2] = {0x34, 0x12};  /* 0x1234 in little-endian */
    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 200,
        .schema_version = 1,
        .flags = 0,
        .field_count = 1,
        .data_len = 2,
        .data = data,
        .read_fn = NULL,
        .fields = fields
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 9: Verify custom schema field accessors - BYTES field
 */
TEST(custom_field_bytes_access) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    var payload = ctx.payload;\n"
        "    if (payload.length !== 4) return -1;\n"
        "    if (payload[0] !== 0xDE) return -2;\n"
        "    if (payload[1] !== 0xAD) return -3;\n"
        "    if (payload[2] !== 0xBE) return -4;\n"
        "    if (payload[3] !== 0xEF) return -5;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_custom_field_t fields[] = {
        { .name = "payload", .offset = 0, .length = 4, .type = MBPF_FIELD_BYTES },
    };

    uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 300,
        .schema_version = 1,
        .flags = 0,
        .field_count = 1,
        .data_len = 4,
        .data = data,
        .read_fn = NULL,
        .fields = fields
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10: Verify read methods work with custom context
 */
TEST(custom_read_methods) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.readU8(0) !== 0xDE) return -1;\n"
        "    if (ctx.readU8(1) !== 0xAD) return -2;\n"
        "    if (ctx.readU16LE(0) !== 0xADDE) return -3;\n"
        "    if (ctx.readU32LE(0) !== 0xEFBEADDE) return -4;\n"
        "    var buf = new Uint8Array(4);\n"
        "    var n = ctx.readBytes(0, 4, buf);\n"
        "    if (n !== 4) return -5;\n"
        "    if (buf[0] !== 0xDE) return -6;\n"
        "    if (buf[3] !== 0xEF) return -7;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 100,
        .schema_version = 1,
        .flags = 0,
        .field_count = 0,
        .data_len = 4,
        .data = data,
        .read_fn = NULL,
        .fields = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10b: Verify read methods work with custom context via read_fn
 */
TEST(custom_read_methods_read_fn) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.data_len !== 8) return -1;\n"
        "    if (ctx.readU32LE(0) !== 0xEFBEADDE) return -2;\n"
        "    var buf = new Uint8Array(4);\n"
        "    var n = ctx.readBytes(4, 4, buf);\n"
        "    if (n !== 4) return -3;\n"
        "    if (buf[0] !== 0x99) return -4;\n"
        "    if (buf[3] !== 0x66) return -5;\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 100,
        .schema_version = 1,
        .flags = 0,
        .field_count = 0,
        .data_len = sizeof(custom_read_data),
        .data = NULL,
        .read_fn = custom_read_fn,
        .fields = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 10c: Short read via read_fn updates data_len and bounds checks
 */
TEST(custom_short_read_fn) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    if (ctx.data_len !== 4) return -1;\n"
        "    if (ctx.readU16LE(0) !== 0x2301) return -2;\n"
        "    try {\n"
        "        ctx.readU8(4);\n"
        "        return -3;\n"
        "    } catch (e) {\n"
        "        return 0;\n"
        "    }\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 100,
        .schema_version = 1,
        .flags = 0,
        .field_count = 0,
        .data_len = 8,
        .data = NULL,
        .read_fn = custom_short_read_fn,
        .fields = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    mbpf_ctx_custom_v1_t ctx = {
        .abi_version = 1,
        .custom_hook_id = 100,
        .schema_version = 1,
        .flags = MBPF_CTX_F_TRUNCATED,
        .field_count = 0,
        .data_len = 4,
        .data = data,
        .read_fn = NULL,
        .fields = NULL
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx, sizeof(ctx), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 12: Null context returns null to JS
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, NULL, 0, &out_rc);
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    for (int i = 0; i < 10; i++) {
        int32_t out_rc = -1;
        err = mbpf_run(rt, MBPF_HOOK_CUSTOM, NULL, 0, &out_rc);
        ASSERT_EQ(err, MBPF_OK);
        ASSERT_EQ(out_rc, 0);
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
 * Test 14: Exception returns safe default
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    int32_t out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* Safe default */

    mbpf_stats_t stats;
    mbpf_program_stats(prog, &stats);
    ASSERT_EQ(stats.invocations, 1);
    ASSERT_EQ(stats.exceptions, 1);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 15: Hook type mismatch rejected
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

    /* Try to attach CUSTOM program to NET_RX hook - should fail */
    err = mbpf_program_attach(rt, prog, MBPF_HOOK_NET_RX);
    ASSERT_EQ(err, MBPF_ERR_HOOK_MISMATCH);

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 16: Detach stops execution
 */
TEST(detach_stops_execution) {
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    /* Run while attached */
    int32_t out_rc = 0;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 42);

    /* Detach */
    err = mbpf_program_detach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    /* Run after detach - should return default (0) */
    out_rc = -1;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, NULL, 0, &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* Default when no programs attached */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

/*
 * Test 17: Complex custom hook - sensor data processing
 * Uses a dynamic temperature threshold check without validating specific values
 */
TEST(complex_sensor_hook) {
    const char *js_code =
        "function mbpf_prog(ctx) {\n"
        "    /* Validate sensor context */\n"
        "    if (ctx.custom_hook_id !== 500) return -1;\n"
        "    if (ctx.schema_version !== 2) return -2;\n"
        "    if (ctx.sensor_id !== 42) return -3;\n"
        "    \n"
        "    /* Check for alert condition: temp > 30C (3000 in units of 0.01C) */\n"
        "    if (ctx.temperature > 3000) {\n"
        "        return 1;  /* Alert */\n"
        "    }\n"
        "    return 0;  /* Normal */\n"
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

    err = mbpf_program_attach(rt, prog, MBPF_HOOK_CUSTOM);
    ASSERT_EQ(err, MBPF_OK);

    /* Define sensor data schema */
    mbpf_custom_field_t fields[] = {
        { .name = "sensor_id", .offset = 0, .length = 0, .type = MBPF_FIELD_U8 },
        { .name = "temperature", .offset = 1, .length = 0, .type = MBPF_FIELD_U16 },
        { .name = "humidity", .offset = 3, .length = 0, .type = MBPF_FIELD_U16 },
    };

    /* Test 1: Normal temperature (2350 = 23.50C, below 30C threshold) */
    /* sensor_id=42, temp=2350 (0x092E), humidity=6500 (0x1964) */
    uint8_t data1[5] = {42, 0x2E, 0x09, 0x64, 0x19};
    mbpf_ctx_custom_v1_t ctx1 = {
        .abi_version = 1,
        .custom_hook_id = 500,
        .schema_version = 2,
        .flags = 0,
        .field_count = 3,
        .data_len = 5,
        .data = data1,
        .read_fn = NULL,
        .fields = fields
    };

    int32_t out_rc = -999;
    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx1, sizeof(ctx1), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 0);  /* Normal (temp 2350 <= 3000) */

    /* Test 2: High temperature (3100 = 31.00C, above 30C threshold) */
    /* sensor_id=42, temp=3100 (0x0C1C), humidity=6500 (0x1964) */
    uint8_t data2[5] = {42, 0x1C, 0x0C, 0x64, 0x19};
    mbpf_ctx_custom_v1_t ctx2 = {
        .abi_version = 1,
        .custom_hook_id = 500,
        .schema_version = 2,
        .flags = 0,
        .field_count = 3,
        .data_len = 5,
        .data = data2,
        .read_fn = NULL,
        .fields = fields
    };

    err = mbpf_run(rt, MBPF_HOOK_CUSTOM, &ctx2, sizeof(ctx2), &out_rc);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_EQ(out_rc, 1);  /* Alert (temp 3100 > 3000) */

    mbpf_runtime_shutdown(rt);
    free(bytecode);
    return 0;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int passed = 0, failed = 0;

    printf("microBPF CUSTOM Hook Tests\n");
    printf("==========================\n\n");

    printf("Schema definition tests:\n");
    RUN_TEST(define_custom_hook_schema);

    printf("\nLoad and attach tests:\n");
    RUN_TEST(load_custom_program);
    RUN_TEST(attach_to_custom);
    RUN_TEST(hook_abi_version);

    printf("\nContext and execution tests:\n");
    RUN_TEST(invoke_with_custom_context);
    RUN_TEST(null_context);
    RUN_TEST(multiple_invocations);

    printf("\nCustom field accessor tests:\n");
    RUN_TEST(custom_field_u8_access);
    RUN_TEST(custom_field_u16_access);
    RUN_TEST(custom_field_u32_access);
    RUN_TEST(custom_field_bytes_access);

    printf("\nRead method tests:\n");
    RUN_TEST(custom_read_methods);
    RUN_TEST(custom_read_methods_read_fn);
    RUN_TEST(custom_short_read_fn);

    printf("\nContext field tests:\n");
    RUN_TEST(flags_field_accessible);

    printf("\nError handling tests:\n");
    RUN_TEST(exception_returns_safe_default);

    printf("\nHook validation tests:\n");
    RUN_TEST(hook_mismatch_rejected);

    printf("\nLifecycle tests:\n");
    RUN_TEST(detach_stops_execution);

    printf("\nComplex scenario tests:\n");
    RUN_TEST(complex_sensor_hook);

    printf("\n==========================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
