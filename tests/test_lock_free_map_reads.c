/*
 * Test: Lock-Free Map Reads
 *
 * Tests the lock-free map read API using seqlocks.
 * Verifies:
 * 1. Benchmark concurrent map reads
 * 2. Verify no lock contention on reads
 * 3. Verify correctness under concurrent read/write
 */

#define _GNU_SOURCE
#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>
#include <unistd.h>

#define ARRAY_MAP_SIZE 100
#define HASH_MAP_SIZE 100
#define NUM_READER_THREADS 4
#define NUM_OPERATIONS 10000
#define VALUE_SIZE 8

/* Helper to build a manifest with array map definition */
static size_t build_manifest_with_array_map(uint8_t *buf, size_t cap,
                                             const char *map_name, uint32_t max_entries,
                                             uint32_t value_size) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"lockfree_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":1,\"key_size\":4,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with hash map definition */
static size_t build_manifest_with_hash_map(uint8_t *buf, size_t cap,
                                            const char *map_name, uint32_t key_size,
                                            uint32_t value_size, uint32_t max_entries) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"lockfree_hash_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"%s\",\"type\":2,\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,\"flags\":0}]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        map_name, key_size, value_size, max_entries);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Build a complete .mbpf package */
static size_t build_mbpf_package(uint8_t *buf, size_t cap,
                                  const uint8_t *manifest, size_t manifest_len,
                                  const uint8_t *bytecode, size_t bc_len) {
    if (cap < 256) return 0;

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

    return total_size;
}

/* Compile JavaScript to bytecode using mqjs */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_lockfree.js";
    const char *bc_file = "/tmp/test_lockfree.qjbc";

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

    uint8_t *bytecode = malloc((size_t)len);
    if (!bytecode) { fclose(f); return NULL; }
    if (fread(bytecode, 1, (size_t)len, f) != (size_t)len) {
        free(bytecode);
        fclose(f);
        return NULL;
    }
    fclose(f);

    *out_len = (size_t)len;
    return bytecode;
}

static const char *simple_js_code = "function mbpf_prog(ctx) { return 0; }";

/* Thread data for concurrent tests */
typedef struct {
    mbpf_program_t *prog;
    int map_idx;
    int thread_id;
    atomic_uint *total_reads;
    atomic_uint *errors;
    int iterations;
    volatile int *running;
} thread_data_t;

/* Reader thread for array map */
static void *array_reader_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    uint8_t value[VALUE_SIZE];
    unsigned int local_reads = 0;
    unsigned int local_errors = 0;

    while (*data->running) {
        for (uint32_t i = 0; i < ARRAY_MAP_SIZE && *data->running; i++) {
            int result = mbpf_array_map_lookup_lockfree(
                data->prog, data->map_idx, i, value, sizeof(value));

            if (result >= 0) {
                local_reads++;
                /* Verify value consistency - all bytes should be the same */
                if (result == 1) {
                    uint8_t first = value[0];
                    for (size_t j = 1; j < VALUE_SIZE; j++) {
                        if (value[j] != first) {
                            local_errors++;
                            break;
                        }
                    }
                }
            } else {
                local_errors++;
            }
        }
    }

    atomic_fetch_add(data->total_reads, local_reads);
    atomic_fetch_add(data->errors, local_errors);
    return NULL;
}

/* Writer thread for array map */
static void *array_writer_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;

    for (int i = 0; i < data->iterations && *data->running; i++) {
        uint32_t idx = (uint32_t)(i % ARRAY_MAP_SIZE);
        uint8_t value[VALUE_SIZE];
        memset(value, (uint8_t)(i & 0xFF), sizeof(value));

        int result = mbpf_array_map_update_locked(
            data->prog, data->map_idx, idx, value, sizeof(value));

        if (result != 0) {
            atomic_fetch_add(data->errors, 1);
        }
    }

    return NULL;
}

/* Reader thread for hash map */
static void *hash_reader_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    uint8_t value[VALUE_SIZE];
    unsigned int local_reads = 0;
    unsigned int local_errors = 0;

    while (*data->running) {
        for (uint32_t i = 0; i < HASH_MAP_SIZE && *data->running; i++) {
            uint32_t key = i;
            int result = mbpf_hash_map_lookup_lockfree(
                data->prog, data->map_idx, &key, sizeof(key), value, sizeof(value));

            if (result >= 0) {
                local_reads++;
                /* Verify value consistency - all bytes should be the same */
                if (result == 1) {
                    uint8_t first = value[0];
                    for (size_t j = 1; j < VALUE_SIZE; j++) {
                        if (value[j] != first) {
                            local_errors++;
                            break;
                        }
                    }
                }
            } else {
                local_errors++;
            }
        }
    }

    atomic_fetch_add(data->total_reads, local_reads);
    atomic_fetch_add(data->errors, local_errors);
    return NULL;
}

/* Writer thread for hash map */
static void *hash_writer_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;

    for (int i = 0; i < data->iterations && *data->running; i++) {
        uint32_t key = (uint32_t)(i % HASH_MAP_SIZE);
        uint8_t value[VALUE_SIZE];
        memset(value, (uint8_t)(i & 0xFF), sizeof(value));

        int result = mbpf_hash_map_update_locked(
            data->prog, data->map_idx, &key, sizeof(key), value, sizeof(value));

        if (result != 0) {
            atomic_fetch_add(data->errors, 1);
        }
    }

    return NULL;
}

/* Test 1: Benchmark concurrent array map reads */
static int test_array_map_benchmark(void) {
    printf("Test 1: Array map concurrent read benchmark...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js_code, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_array_map(manifest, sizeof(manifest),
                                                         "arr", ARRAY_MAP_SIZE, VALUE_SIZE);
    if (manifest_len == 0) {
        printf("  FAILED: Could not build manifest\n");
        free(bytecode);
        return 1;
    }

    uint8_t package[16384];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len,
                                         bytecode, bc_len);
    free(bytecode);
    if (pkg_len == 0) {
        printf("  FAILED: Could not build package\n");
        return 1;
    }

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    if (!rt) {
        printf("  FAILED: Could not init runtime\n");
        return 1;
    }

    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);

    if (rc != MBPF_OK || !prog) {
        printf("  FAILED: Could not load program (rc=%d)\n", rc);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    int map_idx = mbpf_program_find_map(prog, "arr");
    if (map_idx < 0) {
        printf("  FAILED: Could not find map\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    /* Pre-populate some entries */
    for (uint32_t i = 0; i < ARRAY_MAP_SIZE; i++) {
        uint8_t value[VALUE_SIZE];
        memset(value, (uint8_t)i, sizeof(value));
        mbpf_array_map_update_locked(prog, map_idx, i, value, sizeof(value));
    }

    /* Run concurrent readers */
    atomic_uint total_reads = ATOMIC_VAR_INIT(0);
    atomic_uint errors = ATOMIC_VAR_INIT(0);
    volatile int running = 1;

    pthread_t readers[NUM_READER_THREADS];
    thread_data_t thread_data[NUM_READER_THREADS];

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < NUM_READER_THREADS; i++) {
        thread_data[i].prog = prog;
        thread_data[i].map_idx = map_idx;
        thread_data[i].thread_id = i;
        thread_data[i].total_reads = &total_reads;
        thread_data[i].errors = &errors;
        thread_data[i].running = &running;
        pthread_create(&readers[i], NULL, array_reader_thread, &thread_data[i]);
    }

    /* Run for a short time */
    usleep(100000);  /* 100ms */
    running = 0;

    for (int i = 0; i < NUM_READER_THREADS; i++) {
        pthread_join(readers[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    unsigned int reads = atomic_load(&total_reads);
    unsigned int errs = atomic_load(&errors);

    printf("  Concurrent reads: %u in %.3f seconds (%.0f reads/sec)\n",
           reads, elapsed, reads / elapsed);
    printf("  Errors: %u\n", errs);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    if (errs > 0) {
        printf("  FAILED: Encountered errors during concurrent reads\n");
        return 1;
    }

    printf("  PASSED\n");
    return 0;
}

/* Test 2: Verify no lock contention - multiple readers, no writer */
static int test_no_lock_contention(void) {
    printf("Test 2: Verify no lock contention on reads...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js_code, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash_map(manifest, sizeof(manifest),
                                                        "hash", 4, VALUE_SIZE, HASH_MAP_SIZE);
    if (manifest_len == 0) {
        printf("  FAILED: Could not build manifest\n");
        free(bytecode);
        return 1;
    }

    uint8_t package[16384];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len,
                                         bytecode, bc_len);
    free(bytecode);
    if (pkg_len == 0) {
        printf("  FAILED: Could not build package\n");
        return 1;
    }

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    if (!rt) {
        printf("  FAILED: Could not init runtime\n");
        return 1;
    }

    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);

    if (rc != MBPF_OK || !prog) {
        printf("  FAILED: Could not load program (rc=%d)\n", rc);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    int map_idx = mbpf_program_find_map(prog, "hash");
    if (map_idx < 0) {
        printf("  FAILED: Could not find map\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    /* Pre-populate the hash map */
    for (uint32_t i = 0; i < HASH_MAP_SIZE; i++) {
        uint32_t key = i;
        uint8_t value[VALUE_SIZE];
        memset(value, (uint8_t)i, sizeof(value));
        mbpf_hash_map_update_locked(prog, map_idx, &key, sizeof(key), value, sizeof(value));
    }

    /* Run many concurrent readers with no writer - should scale well */
    atomic_uint total_reads = ATOMIC_VAR_INIT(0);
    atomic_uint errors = ATOMIC_VAR_INIT(0);
    volatile int running = 1;

    pthread_t readers[NUM_READER_THREADS * 2];  /* More readers to test contention */
    thread_data_t thread_data[NUM_READER_THREADS * 2];

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < NUM_READER_THREADS * 2; i++) {
        thread_data[i].prog = prog;
        thread_data[i].map_idx = map_idx;
        thread_data[i].thread_id = i;
        thread_data[i].total_reads = &total_reads;
        thread_data[i].errors = &errors;
        thread_data[i].running = &running;
        pthread_create(&readers[i], NULL, hash_reader_thread, &thread_data[i]);
    }

    usleep(100000);  /* 100ms */
    running = 0;

    for (int i = 0; i < NUM_READER_THREADS * 2; i++) {
        pthread_join(readers[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    unsigned int reads = atomic_load(&total_reads);
    unsigned int errs = atomic_load(&errors);

    printf("  Concurrent reads (%d threads): %u in %.3f seconds (%.0f reads/sec)\n",
           NUM_READER_THREADS * 2, reads, elapsed, reads / elapsed);
    printf("  Errors: %u\n", errs);

    /* With no writers, reads should never fail or produce inconsistent data */
    if (errs > 0) {
        printf("  FAILED: Encountered errors during read-only concurrent access\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    printf("  PASSED\n");
    return 0;
}

/* Test 3: Verify correctness under concurrent read/write */
static int test_concurrent_read_write(void) {
    printf("Test 3: Verify correctness under concurrent read/write...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js_code, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_array_map(manifest, sizeof(manifest),
                                                         "arr", ARRAY_MAP_SIZE, VALUE_SIZE);
    if (manifest_len == 0) {
        printf("  FAILED: Could not build manifest\n");
        free(bytecode);
        return 1;
    }

    uint8_t package[16384];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len,
                                         bytecode, bc_len);
    free(bytecode);
    if (pkg_len == 0) {
        printf("  FAILED: Could not build package\n");
        return 1;
    }

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    if (!rt) {
        printf("  FAILED: Could not init runtime\n");
        return 1;
    }

    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);

    if (rc != MBPF_OK || !prog) {
        printf("  FAILED: Could not load program (rc=%d)\n", rc);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    int map_idx = mbpf_program_find_map(prog, "arr");
    if (map_idx < 0) {
        printf("  FAILED: Could not find map\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    /* Run concurrent readers and writers */
    atomic_uint total_reads = ATOMIC_VAR_INIT(0);
    atomic_uint errors = ATOMIC_VAR_INIT(0);
    volatile int running = 1;

    pthread_t readers[NUM_READER_THREADS];
    pthread_t writer;
    thread_data_t reader_data[NUM_READER_THREADS];
    thread_data_t writer_data;

    /* Start readers */
    for (int i = 0; i < NUM_READER_THREADS; i++) {
        reader_data[i].prog = prog;
        reader_data[i].map_idx = map_idx;
        reader_data[i].thread_id = i;
        reader_data[i].total_reads = &total_reads;
        reader_data[i].errors = &errors;
        reader_data[i].running = &running;
        pthread_create(&readers[i], NULL, array_reader_thread, &reader_data[i]);
    }

    /* Start writer */
    writer_data.prog = prog;
    writer_data.map_idx = map_idx;
    writer_data.thread_id = 100;
    writer_data.total_reads = &total_reads;
    writer_data.errors = &errors;
    writer_data.iterations = NUM_OPERATIONS;
    writer_data.running = &running;
    pthread_create(&writer, NULL, array_writer_thread, &writer_data);

    /* Wait for writer to complete */
    pthread_join(writer, NULL);

    /* Stop readers */
    running = 0;
    for (int i = 0; i < NUM_READER_THREADS; i++) {
        pthread_join(readers[i], NULL);
    }

    unsigned int reads = atomic_load(&total_reads);
    unsigned int errs = atomic_load(&errors);

    printf("  Concurrent reads with writer: %u reads\n", reads);
    printf("  Errors (torn reads detected and retried): %u\n", errs);

    /* The key test: with seqlocks, reads should never see inconsistent data.
     * Errors here would indicate the value bytes weren't all the same,
     * which would mean a torn read wasn't properly detected. */
    if (errs > 0) {
        printf("  FAILED: Detected torn reads - seqlock not working correctly\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    printf("  PASSED\n");
    return 0;
}

/* Test 4: Hash map concurrent read/write */
static int test_hash_concurrent_read_write(void) {
    printf("Test 4: Hash map concurrent read/write...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js_code, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash_map(manifest, sizeof(manifest),
                                                        "hash", 4, VALUE_SIZE, HASH_MAP_SIZE);
    if (manifest_len == 0) {
        printf("  FAILED: Could not build manifest\n");
        free(bytecode);
        return 1;
    }

    uint8_t package[16384];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len,
                                         bytecode, bc_len);
    free(bytecode);
    if (pkg_len == 0) {
        printf("  FAILED: Could not build package\n");
        return 1;
    }

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    if (!rt) {
        printf("  FAILED: Could not init runtime\n");
        return 1;
    }

    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);

    if (rc != MBPF_OK || !prog) {
        printf("  FAILED: Could not load program (rc=%d)\n", rc);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    int map_idx = mbpf_program_find_map(prog, "hash");
    if (map_idx < 0) {
        printf("  FAILED: Could not find map\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    /* Run concurrent readers and writers */
    atomic_uint total_reads = ATOMIC_VAR_INIT(0);
    atomic_uint errors = ATOMIC_VAR_INIT(0);
    volatile int running = 1;

    pthread_t readers[NUM_READER_THREADS];
    pthread_t writer;
    thread_data_t reader_data[NUM_READER_THREADS];
    thread_data_t writer_data;

    /* Start readers */
    for (int i = 0; i < NUM_READER_THREADS; i++) {
        reader_data[i].prog = prog;
        reader_data[i].map_idx = map_idx;
        reader_data[i].thread_id = i;
        reader_data[i].total_reads = &total_reads;
        reader_data[i].errors = &errors;
        reader_data[i].running = &running;
        pthread_create(&readers[i], NULL, hash_reader_thread, &reader_data[i]);
    }

    /* Start writer */
    writer_data.prog = prog;
    writer_data.map_idx = map_idx;
    writer_data.thread_id = 100;
    writer_data.total_reads = &total_reads;
    writer_data.errors = &errors;
    writer_data.iterations = NUM_OPERATIONS;
    writer_data.running = &running;
    pthread_create(&writer, NULL, hash_writer_thread, &writer_data);

    /* Wait for writer to complete */
    pthread_join(writer, NULL);

    /* Stop readers */
    running = 0;
    for (int i = 0; i < NUM_READER_THREADS; i++) {
        pthread_join(readers[i], NULL);
    }

    unsigned int reads = atomic_load(&total_reads);
    unsigned int errs = atomic_load(&errors);

    printf("  Concurrent hash map reads with writer: %u reads\n", reads);
    printf("  Errors: %u\n", errs);

    if (errs > 0) {
        printf("  FAILED: Detected torn reads in hash map\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    printf("  PASSED\n");
    return 0;
}

/* Test 5: Basic API functionality */
static int test_basic_api(void) {
    printf("Test 5: Basic lock-free API functionality...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js_code, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_array_map(manifest, sizeof(manifest),
                                                         "arr", ARRAY_MAP_SIZE, VALUE_SIZE);
    if (manifest_len == 0) {
        printf("  FAILED: Could not build manifest\n");
        free(bytecode);
        return 1;
    }

    uint8_t package[8192];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len,
                                         bytecode, bc_len);
    free(bytecode);
    if (pkg_len == 0) {
        printf("  FAILED: Could not build package\n");
        return 1;
    }

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    if (!rt) {
        printf("  FAILED: Could not init runtime\n");
        return 1;
    }

    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);

    if (rc != MBPF_OK || !prog) {
        printf("  FAILED: Could not load program (rc=%d)\n", rc);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    /* Test mbpf_program_find_map */
    int map_idx = mbpf_program_find_map(prog, "arr");
    if (map_idx < 0) {
        printf("  FAILED: mbpf_program_find_map failed\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }
    printf("  mbpf_program_find_map: OK (idx=%d)\n", map_idx);

    /* Test mbpf_map_get_type */
    int map_type = mbpf_map_get_type(prog, map_idx);
    if (map_type != MBPF_MAP_TYPE_ARRAY) {
        printf("  FAILED: mbpf_map_get_type returned wrong type (%d)\n", map_type);
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }
    printf("  mbpf_map_get_type: OK (type=ARRAY)\n");

    /* Test update and lookup */
    uint8_t write_value[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    rc = mbpf_array_map_update_locked(prog, map_idx, 0, write_value, sizeof(write_value));
    if (rc != 0) {
        printf("  FAILED: mbpf_array_map_update_locked failed\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    uint8_t read_value[8] = {0};
    rc = mbpf_array_map_lookup_lockfree(prog, map_idx, 0, read_value, sizeof(read_value));
    if (rc != 1) {
        printf("  FAILED: mbpf_array_map_lookup_lockfree failed (rc=%d)\n", rc);
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }

    if (memcmp(write_value, read_value, sizeof(write_value)) != 0) {
        printf("  FAILED: Read value doesn't match written value\n");
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }
    printf("  mbpf_array_map_update_locked + lookup_lockfree: OK\n");

    /* Test lookup of non-existent entry */
    rc = mbpf_array_map_lookup_lockfree(prog, map_idx, 50, read_value, sizeof(read_value));
    if (rc != 0) {
        printf("  FAILED: Lookup of unset entry should return 0 (rc=%d)\n", rc);
        mbpf_program_unload(rt, prog);
        mbpf_runtime_shutdown(rt);
        return 1;
    }
    printf("  Lookup of unset entry returns 0: OK\n");

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    printf("  PASSED\n");
    return 0;
}

int main(void) {
    printf("=== Lock-Free Map Reads Tests ===\n\n");

    int failed = 0;

    failed += test_basic_api();
    failed += test_array_map_benchmark();
    failed += test_no_lock_contention();
    failed += test_concurrent_read_write();
    failed += test_hash_concurrent_read_write();

    printf("\n=== Summary ===\n");
    if (failed == 0) {
        printf("All tests PASSED\n");
    } else {
        printf("%d test(s) FAILED\n", failed);
    }

    return failed;
}
