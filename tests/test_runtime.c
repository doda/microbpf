/*
 * microBPF Runtime Init/Shutdown Tests
 *
 * Tests for mbpf_runtime_init and mbpf_runtime_shutdown APIs.
 * This file is designed to be run with AddressSanitizer/LeakSanitizer
 * to verify no memory leaks on shutdown.
 */

#include "mbpf.h"
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

#define ASSERT(cond) do { if (!(cond)) return -1; } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_NULL(p) ASSERT((p) == NULL)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)

/* Test 1: Basic runtime init with NULL config */
TEST(init_null_config) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 2: Runtime init with valid config */
TEST(init_with_config) {
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 32768,
        .default_max_steps = 50000,
        .default_max_helpers = 500,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ,
        .require_signatures = false,
        .debug_mode = true,
        .log_fn = NULL
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 3: Runtime init with custom log function */
static int custom_log_called = 0;
static void custom_log_fn(int level, const char *msg) {
    (void)level;
    (void)msg;
    custom_log_called++;
}

TEST(init_with_custom_log) {
    custom_log_called = 0;
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 16384,
        .default_max_steps = 100000,
        .default_max_helpers = 1000,
        .allowed_capabilities = MBPF_CAP_LOG,
        .require_signatures = false,
        .debug_mode = false,
        .log_fn = custom_log_fn
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 4: Multiple init/shutdown cycles */
TEST(multiple_cycles) {
    for (int i = 0; i < 10; i++) {
        mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
        ASSERT_NOT_NULL(rt);
        mbpf_runtime_shutdown(rt);
    }
    return 0;
}

/* Test 5: Shutdown with NULL pointer (should be safe) */
TEST(shutdown_null_safe) {
    mbpf_runtime_shutdown(NULL);
    return 0;
}

/* Test 6: Init with minimal config */
TEST(init_minimal_config) {
    mbpf_runtime_config_t cfg = {0};
    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 7: Init with max capabilities */
TEST(init_max_capabilities) {
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 65536,
        .default_max_steps = 1000000,
        .default_max_helpers = 10000,
        .allowed_capabilities = MBPF_CAP_LOG | MBPF_CAP_MAP_READ |
                                MBPF_CAP_MAP_WRITE | MBPF_CAP_MAP_ITERATE |
                                MBPF_CAP_EMIT | MBPF_CAP_TIME | MBPF_CAP_STATS,
        .require_signatures = true,
        .debug_mode = true,
        .log_fn = NULL
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);
    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 8: Interleaved init/shutdown (create multiple before shutting down) */
TEST(interleaved_init_shutdown) {
    mbpf_runtime_t *rt1 = mbpf_runtime_init(NULL);
    mbpf_runtime_t *rt2 = mbpf_runtime_init(NULL);
    mbpf_runtime_t *rt3 = mbpf_runtime_init(NULL);

    ASSERT_NOT_NULL(rt1);
    ASSERT_NOT_NULL(rt2);
    ASSERT_NOT_NULL(rt3);

    /* They should be different objects */
    ASSERT_NE(rt1, rt2);
    ASSERT_NE(rt2, rt3);
    ASSERT_NE(rt1, rt3);

    mbpf_runtime_shutdown(rt2);
    mbpf_runtime_shutdown(rt1);
    mbpf_runtime_shutdown(rt3);
    return 0;
}

/* Test 9: API version is valid after init */
TEST(api_version_after_init) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    uint32_t api_ver = mbpf_api_version();
    ASSERT_NE(api_ver, 0);
    ASSERT_EQ(api_ver, MBPF_API_VERSION);

    const char *ver_str = mbpf_version_string();
    ASSERT_NOT_NULL(ver_str);
    ASSERT(strlen(ver_str) > 0);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test 10: Stress test - many init/shutdown cycles */
TEST(stress_cycles) {
    for (int i = 0; i < 100; i++) {
        mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
        ASSERT_NOT_NULL(rt);
        mbpf_runtime_shutdown(rt);
    }
    return 0;
}

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Runtime Init/Shutdown Tests\n");
    printf("=====================================\n");

    RUN_TEST(init_null_config);
    RUN_TEST(init_with_config);
    RUN_TEST(init_with_custom_log);
    RUN_TEST(multiple_cycles);
    RUN_TEST(shutdown_null_safe);
    RUN_TEST(init_minimal_config);
    RUN_TEST(init_max_capabilities);
    RUN_TEST(interleaved_init_shutdown);
    RUN_TEST(api_version_after_init);
    RUN_TEST(stress_cycles);

    printf("\n=====================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
