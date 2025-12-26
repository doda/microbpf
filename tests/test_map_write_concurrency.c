/*
 * Test: Map Write Concurrency
 *
 * Tests that multiple concurrent writers to a map are properly serialized
 * via the per-map writer lock. This ensures:
 * 1. Seqlock writers cannot race with each other
 * 2. Map data remains consistent under concurrent writes
 * 3. No data corruption or lost updates
 */

#define _GNU_SOURCE
#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

#define NUM_WRITER_THREADS 4
#define NUM_OPERATIONS 5000
#define ARRAY_SIZE 50
#define HASH_SIZE 50
#define VALUE_SIZE 8

static atomic_uint total_writes;
static atomic_uint write_errors;
static atomic_uint read_errors;
static volatile int running;

/* Helper to build a manifest with array map definition */
static size_t build_manifest_with_array_map(uint8_t *buf, size_t cap) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"concurrency_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"arr\",\"type\":1,\"key_size\":4,\"value_size\":%d,\"max_entries\":%d,\"flags\":0}]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        VALUE_SIZE, ARRAY_SIZE);
    size_t len = strlen(json);
    if (len > cap) return 0;
    memcpy(buf, json, len);
    return len;
}

/* Helper to build a manifest with hash map definition */
static size_t build_manifest_with_hash_map(uint8_t *buf, size_t cap) {
    char json[2048];
    snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"hash_concurrency_test\","
        "\"program_version\":\"1.0.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":65536,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\",\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
        "\"maps\":[{\"name\":\"hash\",\"type\":2,\"key_size\":4,\"value_size\":%d,\"max_entries\":%d,\"flags\":0}]"
        "}",
        mbpf_runtime_word_size(), mbpf_runtime_endianness(),
        VALUE_SIZE, HASH_SIZE);
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

    uint32_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + (uint32_t)manifest_len;
    uint32_t total_size = bytecode_offset + (uint32_t)bc_len;

    if (total_size > cap) return 0;

    uint8_t *p = buf;

    /* Header */
    *p++ = 0x46; *p++ = 0x50; *p++ = 0x42; *p++ = 0x4D;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = header_size & 0xFF; *p++ = (header_size >> 8) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 0: MANIFEST */
    *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = manifest_offset & 0xFF; *p++ = (manifest_offset >> 8) & 0xFF;
    *p++ = (manifest_offset >> 16) & 0xFF; *p++ = (manifest_offset >> 24) & 0xFF;
    *p++ = manifest_len & 0xFF; *p++ = (manifest_len >> 8) & 0xFF;
    *p++ = (manifest_len >> 16) & 0xFF; *p++ = (manifest_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    /* Section 1: BYTECODE */
    *p++ = 0x02; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = bytecode_offset & 0xFF; *p++ = (bytecode_offset >> 8) & 0xFF;
    *p++ = (bytecode_offset >> 16) & 0xFF; *p++ = (bytecode_offset >> 24) & 0xFF;
    *p++ = bc_len & 0xFF; *p++ = (bc_len >> 8) & 0xFF;
    *p++ = (bc_len >> 16) & 0xFF; *p++ = (bc_len >> 24) & 0xFF;
    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;

    memcpy(p, manifest, manifest_len);
    p += manifest_len;
    memcpy(p, bytecode, bc_len);

    return total_size;
}

/* Compile JavaScript to bytecode */
static uint8_t *compile_js_to_bytecode(const char *js_code, size_t *out_len) {
    const char *js_file = "/tmp/test_concurrency.js";
    const char *bc_file = "/tmp/test_concurrency.qjbc";

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

static const char *simple_js = "function mbpf_prog(ctx) { return 0; }";

typedef struct {
    mbpf_program_t *prog;
    int map_idx;
    int thread_id;
    int iterations;
} writer_data_t;

/* Array map writer thread - writes unique values */
static void *array_writer_thread(void *arg) {
    writer_data_t *data = (writer_data_t *)arg;
    uint8_t value[VALUE_SIZE];

    for (int i = 0; i < data->iterations && running; i++) {
        uint32_t idx = (uint32_t)((data->thread_id * data->iterations + i) % ARRAY_SIZE);
        /* Write a consistent value: all bytes = thread_id + iteration */
        uint8_t fill = (uint8_t)((data->thread_id * 31 + i) & 0xFF);
        memset(value, fill, VALUE_SIZE);

        int rc = mbpf_array_map_update_locked(data->prog, data->map_idx,
                                               idx, value, VALUE_SIZE);
        if (rc == 0) {
            atomic_fetch_add(&total_writes, 1);
        } else {
            atomic_fetch_add(&write_errors, 1);
        }
    }
    return NULL;
}

/* Hash map writer thread - writes and updates entries */
static void *hash_writer_thread(void *arg) {
    writer_data_t *data = (writer_data_t *)arg;
    uint8_t value[VALUE_SIZE];

    for (int i = 0; i < data->iterations && running; i++) {
        uint32_t key = (uint32_t)((data->thread_id * data->iterations + i) % HASH_SIZE);
        uint8_t fill = (uint8_t)((data->thread_id * 31 + i) & 0xFF);
        memset(value, fill, VALUE_SIZE);

        int rc = mbpf_hash_map_update_locked(data->prog, data->map_idx,
                                              &key, sizeof(key), value, VALUE_SIZE);
        if (rc == 0) {
            atomic_fetch_add(&total_writes, 1);
        } else {
            atomic_fetch_add(&write_errors, 1);
        }
    }
    return NULL;
}

/* Hash map delete thread */
static void *hash_delete_thread(void *arg) {
    writer_data_t *data = (writer_data_t *)arg;

    for (int i = 0; i < data->iterations && running; i++) {
        uint32_t key = (uint32_t)((data->thread_id * data->iterations + i) % HASH_SIZE);
        mbpf_hash_map_delete_locked(data->prog, data->map_idx, &key, sizeof(key));
        atomic_fetch_add(&total_writes, 1);
    }
    return NULL;
}

/* Verifier thread - reads and checks value consistency */
typedef struct {
    mbpf_program_t *prog;
    int map_idx;
    int is_hash;
} verifier_data_t;

static void *verifier_thread(void *arg) {
    verifier_data_t *data = (verifier_data_t *)arg;
    uint8_t value[VALUE_SIZE];
    unsigned int local_errors = 0;

    while (running) {
        for (int i = 0; i < (data->is_hash ? HASH_SIZE : ARRAY_SIZE) && running; i++) {
            int rc;
            if (data->is_hash) {
                uint32_t key = (uint32_t)i;
                rc = mbpf_hash_map_lookup_lockfree(data->prog, data->map_idx,
                                                    &key, sizeof(key), value, VALUE_SIZE);
            } else {
                rc = mbpf_array_map_lookup_lockfree(data->prog, data->map_idx,
                                                     (uint32_t)i, value, VALUE_SIZE);
            }

            if (rc == 1) {
                /* Check value consistency - all bytes should be same */
                uint8_t first = value[0];
                for (int j = 1; j < VALUE_SIZE; j++) {
                    if (value[j] != first) {
                        local_errors++;
                        break;
                    }
                }
            }
        }
    }

    atomic_fetch_add(&read_errors, local_errors);
    return NULL;
}

/* Test 1: Concurrent array map writers */
static int test_concurrent_array_writers(void) {
    printf("Test 1: Concurrent array map writers...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_array_map(manifest, sizeof(manifest));

    uint8_t package[16384];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len, bytecode, bc_len);
    free(bytecode);

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);
    if (rc != MBPF_OK) {
        printf("  FAILED: Could not load program\n");
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

    atomic_store(&total_writes, 0);
    atomic_store(&write_errors, 0);
    atomic_store(&read_errors, 0);
    running = 1;

    pthread_t writers[NUM_WRITER_THREADS];
    pthread_t verifier;
    writer_data_t wdata[NUM_WRITER_THREADS];
    verifier_data_t vdata = { .prog = prog, .map_idx = map_idx, .is_hash = 0 };

    /* Start verifier thread */
    pthread_create(&verifier, NULL, verifier_thread, &vdata);

    /* Start writer threads */
    for (int i = 0; i < NUM_WRITER_THREADS; i++) {
        wdata[i].prog = prog;
        wdata[i].map_idx = map_idx;
        wdata[i].thread_id = i;
        wdata[i].iterations = NUM_OPERATIONS;
        pthread_create(&writers[i], NULL, array_writer_thread, &wdata[i]);
    }

    /* Wait for writers */
    for (int i = 0; i < NUM_WRITER_THREADS; i++) {
        pthread_join(writers[i], NULL);
    }

    /* Stop verifier */
    running = 0;
    pthread_join(verifier, NULL);

    unsigned int writes = atomic_load(&total_writes);
    unsigned int werrs = atomic_load(&write_errors);
    unsigned int rerrs = atomic_load(&read_errors);

    printf("  Total writes: %u, write errors: %u, read consistency errors: %u\n",
           writes, werrs, rerrs);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    if (werrs > 0 || rerrs > 0) {
        printf("  FAILED: Errors detected\n");
        return 1;
    }

    printf("  PASSED\n");
    return 0;
}

/* Test 2: Concurrent hash map writers */
static int test_concurrent_hash_writers(void) {
    printf("Test 2: Concurrent hash map writers...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash_map(manifest, sizeof(manifest));

    uint8_t package[16384];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len, bytecode, bc_len);
    free(bytecode);

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);
    if (rc != MBPF_OK) {
        printf("  FAILED: Could not load program\n");
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

    atomic_store(&total_writes, 0);
    atomic_store(&write_errors, 0);
    atomic_store(&read_errors, 0);
    running = 1;

    pthread_t writers[NUM_WRITER_THREADS];
    pthread_t verifier;
    writer_data_t wdata[NUM_WRITER_THREADS];
    verifier_data_t vdata = { .prog = prog, .map_idx = map_idx, .is_hash = 1 };

    pthread_create(&verifier, NULL, verifier_thread, &vdata);

    for (int i = 0; i < NUM_WRITER_THREADS; i++) {
        wdata[i].prog = prog;
        wdata[i].map_idx = map_idx;
        wdata[i].thread_id = i;
        wdata[i].iterations = NUM_OPERATIONS;
        pthread_create(&writers[i], NULL, hash_writer_thread, &wdata[i]);
    }

    for (int i = 0; i < NUM_WRITER_THREADS; i++) {
        pthread_join(writers[i], NULL);
    }

    running = 0;
    pthread_join(verifier, NULL);

    unsigned int writes = atomic_load(&total_writes);
    unsigned int werrs = atomic_load(&write_errors);
    unsigned int rerrs = atomic_load(&read_errors);

    printf("  Total writes: %u, write errors: %u, read consistency errors: %u\n",
           writes, werrs, rerrs);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    if (werrs > 0 || rerrs > 0) {
        printf("  FAILED: Errors detected\n");
        return 1;
    }

    printf("  PASSED\n");
    return 0;
}

/* Test 3: Concurrent hash writers and deleters */
static int test_concurrent_hash_write_delete(void) {
    printf("Test 3: Concurrent hash map write and delete...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash_map(manifest, sizeof(manifest));

    uint8_t package[16384];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len, bytecode, bc_len);
    free(bytecode);

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);
    if (rc != MBPF_OK) {
        printf("  FAILED: Could not load program\n");
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

    atomic_store(&total_writes, 0);
    atomic_store(&write_errors, 0);
    atomic_store(&read_errors, 0);
    running = 1;

    /* Use half writers and half deleters */
    pthread_t threads[NUM_WRITER_THREADS];
    pthread_t verifier;
    writer_data_t wdata[NUM_WRITER_THREADS];
    verifier_data_t vdata = { .prog = prog, .map_idx = map_idx, .is_hash = 1 };

    pthread_create(&verifier, NULL, verifier_thread, &vdata);

    for (int i = 0; i < NUM_WRITER_THREADS; i++) {
        wdata[i].prog = prog;
        wdata[i].map_idx = map_idx;
        wdata[i].thread_id = i;
        wdata[i].iterations = NUM_OPERATIONS / 2;
        if (i % 2 == 0) {
            pthread_create(&threads[i], NULL, hash_writer_thread, &wdata[i]);
        } else {
            pthread_create(&threads[i], NULL, hash_delete_thread, &wdata[i]);
        }
    }

    for (int i = 0; i < NUM_WRITER_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    running = 0;
    pthread_join(verifier, NULL);

    unsigned int writes = atomic_load(&total_writes);
    unsigned int rerrs = atomic_load(&read_errors);

    printf("  Total operations: %u, read consistency errors: %u\n", writes, rerrs);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    if (rerrs > 0) {
        printf("  FAILED: Read consistency errors detected\n");
        return 1;
    }

    printf("  PASSED\n");
    return 0;
}

/* Test 4: High contention - all writers hitting same key */
static int test_high_contention_same_key(void) {
    printf("Test 4: High contention - all writers updating same key...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_array_map(manifest, sizeof(manifest));

    uint8_t package[16384];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len, bytecode, bc_len);
    free(bytecode);

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);
    if (rc != MBPF_OK) {
        printf("  FAILED: Could not load program\n");
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

    atomic_store(&total_writes, 0);
    atomic_store(&write_errors, 0);
    atomic_store(&read_errors, 0);
    running = 1;

    /* All threads will update index 0 */
    pthread_t writers[NUM_WRITER_THREADS];
    pthread_t verifier;
    verifier_data_t vdata = { .prog = prog, .map_idx = map_idx, .is_hash = 0 };

    pthread_create(&verifier, NULL, verifier_thread, &vdata);

    /* Custom writer that always updates index 0 */
    typedef struct {
        mbpf_program_t *prog;
        int map_idx;
        int thread_id;
    } contention_data_t;

    void *contention_writer(void *arg) {
        contention_data_t *d = (contention_data_t *)arg;
        uint8_t value[VALUE_SIZE];

        for (int i = 0; i < NUM_OPERATIONS && running; i++) {
            uint8_t fill = (uint8_t)((d->thread_id * 31 + i) & 0xFF);
            memset(value, fill, VALUE_SIZE);

            int r = mbpf_array_map_update_locked(d->prog, d->map_idx, 0, value, VALUE_SIZE);
            if (r == 0) {
                atomic_fetch_add(&total_writes, 1);
            } else {
                atomic_fetch_add(&write_errors, 1);
            }
        }
        return NULL;
    }

    contention_data_t cdata[NUM_WRITER_THREADS];
    for (int i = 0; i < NUM_WRITER_THREADS; i++) {
        cdata[i].prog = prog;
        cdata[i].map_idx = map_idx;
        cdata[i].thread_id = i;
        pthread_create(&writers[i], NULL, contention_writer, &cdata[i]);
    }

    for (int i = 0; i < NUM_WRITER_THREADS; i++) {
        pthread_join(writers[i], NULL);
    }

    running = 0;
    pthread_join(verifier, NULL);

    unsigned int writes = atomic_load(&total_writes);
    unsigned int werrs = atomic_load(&write_errors);
    unsigned int rerrs = atomic_load(&read_errors);

    printf("  Total writes to key 0: %u, write errors: %u, read consistency errors: %u\n",
           writes, werrs, rerrs);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    if (werrs > 0 || rerrs > 0) {
        printf("  FAILED: Errors detected under high contention\n");
        return 1;
    }

    printf("  PASSED\n");
    return 0;
}

/* Test 5: Stress test - many threads, many operations */
static int test_stress(void) {
    printf("Test 5: Stress test - 8 writer threads...\n");

    size_t bc_len;
    uint8_t *bytecode = compile_js_to_bytecode(simple_js, &bc_len);
    if (!bytecode) {
        printf("  FAILED: Could not compile bytecode\n");
        return 1;
    }

    uint8_t manifest[2048];
    size_t manifest_len = build_manifest_with_hash_map(manifest, sizeof(manifest));

    uint8_t package[16384];
    size_t pkg_len = build_mbpf_package(package, sizeof(package),
                                         manifest, manifest_len, bytecode, bc_len);
    free(bytecode);

    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ | MBPF_CAP_MAP_WRITE,
        .instance_mode = MBPF_INSTANCE_SINGLE,
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    mbpf_program_t *prog = NULL;
    int rc = mbpf_program_load(rt, package, pkg_len, NULL, &prog);
    if (rc != MBPF_OK) {
        printf("  FAILED: Could not load program\n");
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

    atomic_store(&total_writes, 0);
    atomic_store(&write_errors, 0);
    atomic_store(&read_errors, 0);
    running = 1;

    #define STRESS_THREADS 8
    pthread_t writers[STRESS_THREADS];
    pthread_t verifiers[2];
    writer_data_t wdata[STRESS_THREADS];
    verifier_data_t vdata = { .prog = prog, .map_idx = map_idx, .is_hash = 1 };

    /* Start multiple verifiers */
    for (int i = 0; i < 2; i++) {
        pthread_create(&verifiers[i], NULL, verifier_thread, &vdata);
    }

    /* Start many writers */
    for (int i = 0; i < STRESS_THREADS; i++) {
        wdata[i].prog = prog;
        wdata[i].map_idx = map_idx;
        wdata[i].thread_id = i;
        wdata[i].iterations = NUM_OPERATIONS;
        pthread_create(&writers[i], NULL, hash_writer_thread, &wdata[i]);
    }

    for (int i = 0; i < STRESS_THREADS; i++) {
        pthread_join(writers[i], NULL);
    }

    running = 0;
    for (int i = 0; i < 2; i++) {
        pthread_join(verifiers[i], NULL);
    }

    unsigned int writes = atomic_load(&total_writes);
    unsigned int werrs = atomic_load(&write_errors);
    unsigned int rerrs = atomic_load(&read_errors);

    printf("  Total writes: %u, write errors: %u, read consistency errors: %u\n",
           writes, werrs, rerrs);

    mbpf_program_unload(rt, prog);
    mbpf_runtime_shutdown(rt);

    if (werrs > 0 || rerrs > 0) {
        printf("  FAILED: Errors detected under stress\n");
        return 1;
    }

    printf("  PASSED\n");
    return 0;
}

int main(void) {
    printf("=== Map Write Concurrency Tests ===\n\n");

    int failed = 0;

    failed += test_concurrent_array_writers();
    failed += test_concurrent_hash_writers();
    failed += test_concurrent_hash_write_delete();
    failed += test_high_contention_same_key();
    failed += test_stress();

    printf("\n=== Summary ===\n");
    if (failed == 0) {
        printf("All tests PASSED\n");
    } else {
        printf("%d test(s) FAILED\n", failed);
    }

    return failed;
}
