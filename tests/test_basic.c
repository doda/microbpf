/*
 * microBPF Basic Tests
 *
 * Simple smoke tests for the microBPF runtime.
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

/* Test runtime init/shutdown */
TEST(runtime_init_shutdown) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test runtime with config */
TEST(runtime_with_config) {
    mbpf_runtime_config_t cfg = {
        .default_heap_size = 32768,
        .default_max_steps = 50000,
        .default_max_helpers = 500,
        .allowed_capabilities = MBPF_CAP_LOG,
        .require_signatures = false,
        .debug_mode = true,
        .log_fn = NULL
    };

    mbpf_runtime_t *rt = mbpf_runtime_init(&cfg);
    ASSERT_NOT_NULL(rt);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test multiple init/shutdown cycles */
TEST(multiple_init_shutdown) {
    for (int i = 0; i < 5; i++) {
        mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
        ASSERT_NOT_NULL(rt);
        mbpf_runtime_shutdown(rt);
    }
    return 0;
}

/* Test version info */
TEST(version_info) {
    const char *version = mbpf_version_string();
    ASSERT_NOT_NULL(version);
    ASSERT(strlen(version) > 0);

    uint32_t api_ver = mbpf_api_version();
    ASSERT_NE(api_ver, 0);

    return 0;
}

/* Test invalid program load */
TEST(invalid_program_load) {
    mbpf_runtime_t *rt = mbpf_runtime_init(NULL);
    ASSERT_NOT_NULL(rt);

    mbpf_program_t *prog = NULL;
    int err;

    /* NULL package */
    err = mbpf_program_load(rt, NULL, 0, NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* Too small package */
    uint8_t small[10] = {0};
    err = mbpf_program_load(rt, small, sizeof(small), NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);

    /* Wrong magic */
    uint8_t bad_magic[64] = {0};
    bad_magic[0] = 'B'; bad_magic[1] = 'A'; bad_magic[2] = 'D'; bad_magic[3] = '!';
    err = mbpf_program_load(rt, bad_magic, sizeof(bad_magic), NULL, &prog);
    ASSERT_EQ(err, MBPF_ERR_INVALID_MAGIC);

    mbpf_runtime_shutdown(rt);
    return 0;
}

/* Test stats access with NULL */
TEST(stats_null_safety) {
    mbpf_stats_t stats;
    int err = mbpf_program_stats(NULL, &stats);
    ASSERT_EQ(err, MBPF_ERR_INVALID_ARG);
    return 0;
}

int main(void) {
    int passed = 0;
    int failed = 0;

    printf("microBPF Basic Tests\n");
    printf("====================\n");

    RUN_TEST(runtime_init_shutdown);
    RUN_TEST(runtime_with_config);
    RUN_TEST(multiple_init_shutdown);
    RUN_TEST(version_info);
    RUN_TEST(invalid_program_load);
    RUN_TEST(stats_null_safety);

    printf("\nResults: %d passed, %d failed\n", passed, failed);

    return failed > 0 ? 1 : 0;
}
