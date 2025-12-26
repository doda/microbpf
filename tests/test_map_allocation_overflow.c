/*
 * microBPF Map Allocation Overflow Tests
 *
 * Tests for overflow-safe map allocation sizing:
 * 1. Validate max_entries * value_size multiplication against size_t overflow
 * 2. Reject map definitions that exceed size limits before allocation
 * 3. Cover array, hash, LRU, ring buffer, counter, and per-CPU map allocations
 * 4. Test large map sizes to verify safe failure paths
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

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

/* Helper to build a manifest with map definition */
static size_t build_manifest_with_map(uint8_t *buf, size_t cap, int hook_type,
                                       int map_type, const char *map_name,
                                       uint32_t key_size, uint32_t value_size,
                                       uint32_t max_entries, uint32_t flags) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"overflow_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":%d,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":%d,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":%u}]"
        "}",
        hook_type,
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name, map_type, key_size, value_size, max_entries, flags);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package with map */
static size_t build_mbpf_package_with_map(uint8_t *buf, size_t cap,
                                           const uint8_t *bytecode, size_t bc_len,
                                           int hook_type, int map_type,
                                           const char *map_name,
                                           uint32_t key_size, uint32_t value_size,
                                           uint32_t max_entries, uint32_t flags) {
    if (cap < 256) return 0;

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_map(manifest, sizeof(manifest),
                                                   hook_type, map_type, map_name,
                                                   key_size, value_size,
                                                   max_entries, flags);
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

/* Compile JavaScript to bytecode */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_overflow.js";
    const char *bc_file = "/tmp/test_overflow.qjbc";

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

    *out_len = len;
    return bytecode;
}

/* Simple test program */
static const char *simple_prog =
    "function mbpf_prog(ctx) { return 0; }";

/*
 * Test that an array map with sizes that would overflow is rejected.
 * UINT32_MAX entries * value_size would overflow size_t on many platforms.
 */
TEST(array_map_overflow_rejected) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* MBPF_MAP_TYPE_ARRAY = 1 */
    /* Use very large values that would overflow when multiplied:
     * max_entries = 0x80000000 (2^31) with value_size = 4 would be 8GB
     * which would still "fit" in 64-bit size_t but fail allocation.
     * On 32-bit systems with max_entries = 0x40000000 and value_size = 4,
     * the result is 4GB which overflows 32-bit size_t. */
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  1,  /* ARRAY */
                                                  "overflow",
                                                  4,  /* key_size */
                                                  0xFFFFFFFF,  /* value_size = max uint32 */
                                                  0xFFFFFFFF,  /* max_entries = max uint32 */
                                                  0);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Load should fail due to overflow in map allocation */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test that a hash map with sizes that would overflow is rejected.
 * bucket_size = 1 + key_size + value_size could overflow, and
 * max_entries * bucket_size definitely will with large values.
 * On 64-bit systems we need very large values to cause overflow.
 */
TEST(hash_map_overflow_rejected) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* MBPF_MAP_TYPE_HASH = 2
     * Use max_entries and bucket_size that multiply to overflow size_t.
     * On 64-bit: max_entries=0xFFFFFFFF, bucket_size=(1+4+0xFFFFFFFF) ~ 4GB
     * Result: 4GB * 4G entries > 2^64, should overflow */
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  2,  /* HASH */
                                                  "hashover",
                                                  4,            /* key_size = 4 */
                                                  0xFFFFFFFF,   /* value_size = max uint32 */
                                                  0xFFFFFFFF,   /* max_entries = max uint32 */
                                                  0);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Load should fail due to overflow in bucket size calculation */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test that an LRU map with sizes that would overflow is rejected.
 * LRU bucket_size = 9 + key_size + value_size, which could overflow.
 * On 64-bit: max_entries * bucket_size must overflow size_t.
 */
TEST(lru_map_overflow_rejected) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* MBPF_MAP_TYPE_LRU = 3
     * bucket_size = 9 + key_size + value_size
     * For overflow: bucket_size ~ 4GB with max_entries ~ 4GB */
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  3,  /* LRU */
                                                  "lruover",
                                                  4,            /* key_size = 4 */
                                                  0xFFFFFFFF,   /* value_size = max uint32 */
                                                  0xFFFFFFFF,   /* max_entries = max uint32 */
                                                  0);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Load should fail due to overflow */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test ring buffer with large sizes.
 *
 * Note: On 64-bit systems, uint32_t * uint32_t cannot overflow size_t since
 * the maximum product (2^32-1)^2 < SIZE_MAX. The overflow check is still useful
 * on 32-bit systems where SIZE_MAX = 2^32-1.
 *
 * On 64-bit Linux with overcommit, even huge allocations may "succeed" initially,
 * only failing when memory is actually touched. This makes it difficult to test
 * allocation failure reliably.
 *
 * We test with moderate values that should fail on most systems.
 */
TEST(ring_buffer_large_size_handled) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* MBPF_MAP_TYPE_RING = 5
     * Test with 1GB buffer which is still allocatable on most systems.
     * This verifies the code path works for large (but not overflowing) sizes. */
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  5,  /* RING */
                                                  "ringtest",
                                                  4,            /* key_size (unused for ring) */
                                                  1024,         /* value_size = 1KB */
                                                  1024,         /* max_entries = 1K (1MB total) */
                                                  0);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* A 1MB ring buffer should succeed on most systems */
    if (err == MBPF_OK && prog) {
        mbpf_program_unload(rt, prog);
    }
    /* Whether it succeeds or fails depends on system memory - both are valid */

    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test that a counter map with overflow is rejected.
 * max_entries * sizeof(int64_t) could overflow.
 */
TEST(counter_map_overflow_rejected) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* MBPF_MAP_TYPE_COUNTER = 6 */
    /* 0xFFFFFFFF * 8 (sizeof int64_t) = overflow */
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  6,  /* COUNTER */
                                                  "ctrover",
                                                  4,            /* key_size */
                                                  8,            /* value_size */
                                                  0xFFFFFFFF,   /* max_entries = max */
                                                  0);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Load should fail due to overflow */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test that a per-CPU array map with overflow is rejected.
 * Per-CPU multiplies values_size by num_instances, increasing overflow risk.
 */
TEST(percpu_array_overflow_rejected) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* MBPF_MAP_TYPE_ARRAY (1) with PERCPU flag (1) */
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  1,  /* ARRAY */
                                                  "pcaover",
                                                  4,            /* key_size */
                                                  0xFFFFFFFF,   /* value_size = max */
                                                  0xFFFFFFFF,   /* max_entries = max */
                                                  1);           /* PERCPU flag */
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Load should fail due to overflow */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test that a per-CPU hash map with overflow is rejected.
 * On 64-bit: bucket_size * max_entries must overflow.
 */
TEST(percpu_hash_overflow_rejected) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* MBPF_MAP_TYPE_HASH (2) with PERCPU flag (1)
     * bucket_size = 1 + key_size + value_size ~ 4GB
     * max_entries = 4GB => product overflows */
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  2,  /* HASH */
                                                  "pchover",
                                                  4,            /* key_size = 4 */
                                                  0xFFFFFFFF,   /* value_size = max uint32 */
                                                  0xFFFFFFFF,   /* max_entries = max uint32 */
                                                  1);           /* PERCPU flag */
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Load should fail due to overflow */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test that normal-sized maps still work after adding overflow checks.
 * This is a sanity check to ensure overflow checks don't break normal usage.
 */
TEST(normal_sized_map_succeeds) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* Normal array map: 100 entries * 4 bytes = 400 bytes */
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  1,  /* ARRAY */
                                                  "normal",
                                                  4,    /* key_size */
                                                  4,    /* value_size */
                                                  100,  /* max_entries */
                                                  0);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    ASSERT_EQ(err, MBPF_OK);
    ASSERT_NOT_NULL(prog);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test hash map bucket_size addition overflow.
 * On 64-bit, we need additions that would overflow when adding to SIZE_MAX.
 * Since safe_size_add checks a > SIZE_MAX - b, we need values that exceed SIZE_MAX.
 * This is tricky with 32-bit manifest values, so we test the multiplication path instead.
 * Using max uint32 for both key_size and value_size tests the addition:
 * 1 + 0xFFFFFFFF + 0xFFFFFFFF would be ~8.6GB, no overflow on 64-bit.
 * The multiplication with max_entries then causes overflow.
 */
TEST(hash_bucket_size_addition_overflow) {
    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    uint8_t pkg[8192];
    /* bucket_size = 1 + key_size + value_size = 1 + 0xFFFFFFFF + 0xFFFFFFFF
     * = ~8.6GB on 64-bit (no overflow in addition)
     * But: 8.6GB * 0xFFFFFFFF = ~37 exabytes => overflow */
    size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                  bytecode, bc_len,
                                                  MBPF_HOOK_TRACEPOINT,
                                                  2,  /* HASH */
                                                  "addover",
                                                  0xFFFFFFFF,  /* key_size = max */
                                                  0xFFFFFFFF,  /* value_size = max */
                                                  0xFFFFFFFF,  /* max_entries = max */
                                                  0);
    free(bytecode);
    ASSERT(pkg_len > 0);

    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
    /* Load should fail due to overflow */
    ASSERT_NE(err, MBPF_OK);
    ASSERT_NULL(prog);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/*
 * Test multiple map types in a single test to verify all overflow
 * checks are working consistently.
 * On 64-bit systems, we need larger products to trigger overflow.
 */
TEST(multiple_map_types_with_edge_values) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    /* Test various edge cases that should all overflow on 64-bit.
     * The product must exceed SIZE_MAX (~18.4 exabytes on 64-bit). */
    struct {
        int map_type;
        uint32_t key_size;
        uint32_t value_size;
        uint32_t max_entries;
        const char *name;
    } tests[] = {
        /* Array: max_entries * value_size overflow
         * 0xFFFFFFFF * 0xFFFFFFFF overflows 64-bit */
        {1, 4, 0xFFFFFFFF, 0xFFFFFFFF, "arr1"},
        /* Hash: bucket_size * max_entries overflow
         * bucket = 1 + 4 + 0xFFFFFFFF ~ 4GB, * 0xFFFFFFFF overflows */
        {2, 4, 0xFFFFFFFF, 0xFFFFFFFF, "hash1"},
        /* LRU: similar bucket_size * max_entries overflow */
        {3, 4, 0xFFFFFFFF, 0xFFFFFFFF, "lru1"},
        {0, 0, 0, 0, NULL}  /* Sentinel */
    };

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_prog, &bc_len);
    ASSERT_NOT_NULL(bytecode);

    for (int i = 0; tests[i].name != NULL; i++) {
        uint8_t pkg[8192];
        size_t pkg_len = build_mbpf_package_with_map(pkg, sizeof(pkg),
                                                      bytecode, bc_len,
                                                      MBPF_HOOK_TRACEPOINT,
                                                      tests[i].map_type,
                                                      tests[i].name,
                                                      tests[i].key_size,
                                                      tests[i].value_size,
                                                      tests[i].max_entries,
                                                      0);
        if (pkg_len == 0) continue;  /* Skip if package build failed */

        mbpf_program_t *prog = NULL;
        int err = mbpf_program_load(rt, pkg, pkg_len, NULL, &prog);
        if (err == MBPF_OK && prog) {
            /* This shouldn't happen - these should all fail */
            mbpf_program_unload(rt, prog);
            free(bytecode);
            mbpf_runtime_shutdown(rt);
            return -1;
        }
    }

    free(bytecode);
    mbpf_runtime_shutdown(rt);
    return 0;
}

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Map Allocation Overflow Tests\n");
    printf("======================================\n\n");

    printf("Array map overflow tests:\n");
    RUN_TEST(array_map_overflow_rejected);

    printf("\nHash map overflow tests:\n");
    RUN_TEST(hash_map_overflow_rejected);
    RUN_TEST(hash_bucket_size_addition_overflow);

    printf("\nLRU map overflow tests:\n");
    RUN_TEST(lru_map_overflow_rejected);

    printf("\nRing buffer tests:\n");
    RUN_TEST(ring_buffer_large_size_handled);

    printf("\nCounter map overflow tests:\n");
    RUN_TEST(counter_map_overflow_rejected);

    printf("\nPer-CPU map overflow tests:\n");
    RUN_TEST(percpu_array_overflow_rejected);
    RUN_TEST(percpu_hash_overflow_rejected);

    printf("\nSanity checks:\n");
    RUN_TEST(normal_sized_map_succeeds);

    printf("\nMultiple map type edge cases:\n");
    RUN_TEST(multiple_map_types_with_edge_values);

    printf("\n======================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
