/*
 * microBPF Test Utilities
 *
 * Common helper functions for building test packages with correct
 * runtime-detected word size and endianness.
 */

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include "mbpf.h"
#include <string.h>
#include <stdio.h>

/*
 * Format string for target section in JSON manifests.
 * Uses printf-style format specifiers for word_size and endianness.
 */
#define TEST_TARGET_FMT "\"target\":{\"word_size\":%u,\"endianness\":%u}"

/*
 * Get a static target string for the current runtime.
 * Returns a string like: "target":{"word_size":64,"endianness":0}
 */
static inline const char *test_runtime_target_str(void) {
    static char buf[64];
    static int initialized = 0;
    if (!initialized) {
        snprintf(buf, sizeof(buf), TEST_TARGET_FMT,
                 mbpf_runtime_word_size(), mbpf_runtime_endianness());
        initialized = 1;
    }
    return buf;
}

/*
 * Build a JSON manifest with runtime-detected target.
 * This replaces hardcoded "word_size":64 with the actual runtime values.
 */
static inline size_t test_build_manifest(uint8_t *buf, size_t cap,
                                          const char *program_name,
                                          uint32_t hook_type,
                                          uint32_t heap_size,
                                          uint32_t max_steps,
                                          uint32_t max_helpers,
                                          uint32_t capabilities) {
    char json[1024];
    int len = snprintf(json, sizeof(json),
        "{"
        "\"program_name\":\"%s\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":%u,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":1,"
        "\"target\":{\"word_size\":%u,\"endianness\":%u},"
        "\"mbpf_api_version\":1,"
        "\"heap_size\":%u,"
        "\"budgets\":{\"max_steps\":%u,\"max_helpers\":%u},"
        "\"capabilities\":[%u]"
        "}",
        program_name,
        hook_type,
        mbpf_runtime_word_size(),
        mbpf_runtime_endianness(),
        heap_size,
        max_steps,
        max_helpers,
        capabilities);

    if (len < 0 || (size_t)len >= cap) return 0;
    memcpy(buf, json, len);
    return (size_t)len;
}

/*
 * Get the runtime word size for use in manifest strings.
 */
static inline unsigned test_word_size(void) {
    return mbpf_runtime_word_size();
}

/*
 * Get the runtime endianness for use in manifest strings.
 */
static inline unsigned test_endianness(void) {
    return mbpf_runtime_endianness();
}

#endif /* TEST_UTILS_H */
