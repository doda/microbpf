/*
 * Generate Fuzz Corpus for Package Parser
 *
 * This program generates a variety of valid and edge-case .mbpf packages
 * to seed the fuzzer with interesting test cases.
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define CORPUS_DIR "tests/fuzz_corpus"

static void write_le16(uint8_t *buf, uint16_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
}

static void write_le32(uint8_t *buf, uint32_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

static int write_corpus_file(const char *name, const uint8_t *data, size_t len) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", CORPUS_DIR, name);

    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Cannot create: %s\n", path);
        return -1;
    }
    fwrite(data, 1, len, f);
    fclose(f);
    printf("  Created: %s (%zu bytes)\n", name, len);
    return 0;
}

static void create_corpus_dir(void) {
    if (mkdir(CORPUS_DIR, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Warning: cannot create %s: %s\n", CORPUS_DIR, strerror(errno));
    }
}

/* Create a minimal valid package */
static int corpus_minimal_valid(void) {
    /* Minimal JSON manifest with all required fields */
    const char *manifest =
        "{"
        "\"program_name\":\"test\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":32769,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":65536,"
        "\"heap_size\":16384,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[]"
        "}";
    size_t manifest_len = strlen(manifest);

    /* Placeholder bytecode */
    uint8_t bytecode[] = {0x00, 0x00, 0x00, 0x00};
    size_t bytecode_len = 4;

    /* Calculate sizes */
    uint16_t header_size = 20 + 2 * 16; /* header + 2 sections */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + manifest_len;
    size_t total_len = bytecode_offset + bytecode_len;

    uint8_t *buf = malloc(total_len);
    if (!buf) return -1;
    memset(buf, 0, total_len);

    /* Header */
    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, MBPF_FORMAT_VERSION);
    write_le16(buf + 6, header_size);
    write_le32(buf + 8, 0); /* flags */
    write_le32(buf + 12, 2); /* section_count */
    write_le32(buf + 16, 0); /* file_crc32 */

    /* Section 0: MANIFEST */
    write_le32(buf + 20, MBPF_SEC_MANIFEST);
    write_le32(buf + 24, manifest_offset);
    write_le32(buf + 28, manifest_len);
    write_le32(buf + 32, 0);

    /* Section 1: BYTECODE */
    write_le32(buf + 36, MBPF_SEC_BYTECODE);
    write_le32(buf + 40, bytecode_offset);
    write_le32(buf + 44, bytecode_len);
    write_le32(buf + 48, 0);

    /* Data */
    memcpy(buf + manifest_offset, manifest, manifest_len);
    memcpy(buf + bytecode_offset, bytecode, bytecode_len);

    int ret = write_corpus_file("minimal_valid.mbpf", buf, total_len);
    free(buf);
    return ret;
}

/* Create a package with CBOR manifest */
static int corpus_cbor_manifest(void) {
    /*
     * CBOR-encoded manifest:
     * {
     *   "program_name": "test",
     *   "program_version": "1.0",
     *   "hook_type": 1,
     *   "hook_ctx_abi_version": 1,
     *   "mquickjs_bytecode_version": 32769,
     *   "target": {"word_size": 64, "endianness": 0},
     *   "mbpf_api_version": 65536,
     *   "heap_size": 16384,
     *   "budgets": {"max_steps": 100000, "max_helpers": 1000},
     *   "capabilities": []
     * }
     */
    uint8_t manifest[] = {
        0xAA, /* map with 10 items */

        /* program_name: "test" */
        0x6C, 'p', 'r', 'o', 'g', 'r', 'a', 'm', '_', 'n', 'a', 'm', 'e',
        0x64, 't', 'e', 's', 't',

        /* program_version: "1.0" */
        0x6F, 'p', 'r', 'o', 'g', 'r', 'a', 'm', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n',
        0x63, '1', '.', '0',

        /* hook_type: 1 */
        0x69, 'h', 'o', 'o', 'k', '_', 't', 'y', 'p', 'e',
        0x01,

        /* hook_ctx_abi_version: 1 */
        0x74, 'h', 'o', 'o', 'k', '_', 'c', 't', 'x', '_', 'a', 'b', 'i', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n',
        0x01,

        /* mquickjs_bytecode_version: 32769 (0x8001) */
        0x78, 0x18, 'm', 'q', 'u', 'i', 'c', 'k', 'j', 's', '_', 'b', 'y', 't', 'e', 'c', 'o', 'd', 'e', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n',
        0x19, 0x80, 0x01,

        /* target: {"word_size": 64, "endianness": 0} */
        0x66, 't', 'a', 'r', 'g', 'e', 't',
        0xA2,
        0x69, 'w', 'o', 'r', 'd', '_', 's', 'i', 'z', 'e',
        0x18, 0x40, /* 64 */
        0x6A, 'e', 'n', 'd', 'i', 'a', 'n', 'n', 'e', 's', 's',
        0x00,

        /* mbpf_api_version: 65536 (0x10000) */
        0x70, 'm', 'b', 'p', 'f', '_', 'a', 'p', 'i', '_', 'v', 'e', 'r', 's', 'i', 'o', 'n',
        0x1A, 0x00, 0x01, 0x00, 0x00,

        /* heap_size: 16384 */
        0x69, 'h', 'e', 'a', 'p', '_', 's', 'i', 'z', 'e',
        0x19, 0x40, 0x00,

        /* budgets: {"max_steps": 100000, "max_helpers": 1000} */
        0x67, 'b', 'u', 'd', 'g', 'e', 't', 's',
        0xA2,
        0x69, 'm', 'a', 'x', '_', 's', 't', 'e', 'p', 's',
        0x1A, 0x00, 0x01, 0x86, 0xA0, /* 100000 */
        0x6B, 'm', 'a', 'x', '_', 'h', 'e', 'l', 'p', 'e', 'r', 's',
        0x19, 0x03, 0xE8, /* 1000 */

        /* capabilities: [] */
        0x6C, 'c', 'a', 'p', 'a', 'b', 'i', 'l', 'i', 't', 'i', 'e', 's',
        0x80, /* empty array */
    };
    size_t manifest_len = sizeof(manifest);

    uint8_t bytecode[] = {0x00, 0x00, 0x00, 0x00};
    size_t bytecode_len = 4;

    uint16_t header_size = 20 + 2 * 16;
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + manifest_len;
    size_t total_len = bytecode_offset + bytecode_len;

    uint8_t *buf = malloc(total_len);
    if (!buf) return -1;
    memset(buf, 0, total_len);

    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, MBPF_FORMAT_VERSION);
    write_le16(buf + 6, header_size);
    write_le32(buf + 8, 0);
    write_le32(buf + 12, 2);
    write_le32(buf + 16, 0);

    write_le32(buf + 20, MBPF_SEC_MANIFEST);
    write_le32(buf + 24, manifest_offset);
    write_le32(buf + 28, manifest_len);
    write_le32(buf + 32, 0);

    write_le32(buf + 36, MBPF_SEC_BYTECODE);
    write_le32(buf + 40, bytecode_offset);
    write_le32(buf + 44, bytecode_len);
    write_le32(buf + 48, 0);

    memcpy(buf + manifest_offset, manifest, manifest_len);
    memcpy(buf + bytecode_offset, bytecode, bytecode_len);

    int ret = write_corpus_file("cbor_manifest.mbpf", buf, total_len);
    free(buf);
    return ret;
}

/* Create a package with all section types */
static int corpus_all_sections(void) {
    const char *manifest =
        "{"
        "\"program_name\":\"full\","
        "\"program_version\":\"1.0\","
        "\"hook_type\":1,"
        "\"hook_ctx_abi_version\":1,"
        "\"mquickjs_bytecode_version\":32769,"
        "\"target\":{\"word_size\":64,\"endianness\":0},"
        "\"mbpf_api_version\":65536,"
        "\"heap_size\":16384,"
        "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
        "\"capabilities\":[\"CAP_LOG\"],"
        "\"maps\":[{\"name\":\"stats\",\"type\":1,\"key_size\":4,\"value_size\":8,\"max_entries\":10}]"
        "}";
    size_t manifest_len = strlen(manifest);

    uint8_t bytecode[] = {0x00, 0x00, 0x00, 0x00};
    size_t bytecode_len = 4;

    /* Debug section: flags(4) + hash(32) + entry_len(4) + entry + hook_len(4) + hook + map_count(4) + map_name */
    uint8_t debug[128];
    size_t debug_offset = 0;
    memset(debug, 0, sizeof(debug));

    /* flags */
    write_le32(debug + debug_offset, 1); debug_offset += 4;
    /* source hash (32 bytes) */
    debug_offset += 32;
    /* entry symbol "mbpf_prog" */
    write_le32(debug + debug_offset, 9); debug_offset += 4;
    memcpy(debug + debug_offset, "mbpf_prog", 9); debug_offset += 9;
    /* hook name "net_rx" */
    write_le32(debug + debug_offset, 6); debug_offset += 4;
    memcpy(debug + debug_offset, "net_rx", 6); debug_offset += 6;
    /* map count = 1 */
    write_le32(debug + debug_offset, 1); debug_offset += 4;
    /* map name "stats" */
    write_le32(debug + debug_offset, 5); debug_offset += 4;
    memcpy(debug + debug_offset, "stats", 5); debug_offset += 5;
    size_t debug_len = debug_offset;

    /* Signature (64 bytes dummy) */
    uint8_t sig[64];
    memset(sig, 0xAA, sizeof(sig));
    size_t sig_len = 64;

    uint16_t header_size = 20 + 4 * 16; /* 4 sections */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + manifest_len;
    uint32_t debug_offset2 = bytecode_offset + bytecode_len;
    uint32_t sig_offset = debug_offset2 + debug_len;
    size_t total_len = sig_offset + sig_len;

    uint8_t *buf = malloc(total_len);
    if (!buf) return -1;
    memset(buf, 0, total_len);

    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, MBPF_FORMAT_VERSION);
    write_le16(buf + 6, header_size);
    write_le32(buf + 8, MBPF_FLAG_SIGNED | MBPF_FLAG_DEBUG);
    write_le32(buf + 12, 4);
    write_le32(buf + 16, 0);

    /* MANIFEST */
    write_le32(buf + 20, MBPF_SEC_MANIFEST);
    write_le32(buf + 24, manifest_offset);
    write_le32(buf + 28, manifest_len);
    write_le32(buf + 32, 0);

    /* BYTECODE */
    write_le32(buf + 36, MBPF_SEC_BYTECODE);
    write_le32(buf + 40, bytecode_offset);
    write_le32(buf + 44, bytecode_len);
    write_le32(buf + 48, 0);

    /* DEBUG */
    write_le32(buf + 52, MBPF_SEC_DEBUG);
    write_le32(buf + 56, debug_offset2);
    write_le32(buf + 60, debug_len);
    write_le32(buf + 64, 0);

    /* SIG */
    write_le32(buf + 68, MBPF_SEC_SIG);
    write_le32(buf + 72, sig_offset);
    write_le32(buf + 76, sig_len);
    write_le32(buf + 80, 0);

    memcpy(buf + manifest_offset, manifest, manifest_len);
    memcpy(buf + bytecode_offset, bytecode, bytecode_len);
    memcpy(buf + debug_offset2, debug, debug_len);
    memcpy(buf + sig_offset, sig, sig_len);

    int ret = write_corpus_file("all_sections.mbpf", buf, total_len);
    free(buf);
    return ret;
}

/* Create edge case packages */
static int corpus_edge_cases(void) {
    uint8_t buf[512];
    int created = 0;

    /* Empty sections */
    memset(buf, 0, sizeof(buf));
    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, MBPF_FORMAT_VERSION);
    write_le16(buf + 6, 52);
    write_le32(buf + 8, 0);
    write_le32(buf + 12, 2);
    write_le32(buf + 16, 0);
    write_le32(buf + 20, MBPF_SEC_MANIFEST);
    write_le32(buf + 24, 52);
    write_le32(buf + 28, 0); /* empty */
    write_le32(buf + 32, 0);
    write_le32(buf + 36, MBPF_SEC_BYTECODE);
    write_le32(buf + 40, 52);
    write_le32(buf + 44, 0); /* empty */
    write_le32(buf + 48, 0);
    write_corpus_file("empty_sections.mbpf", buf, 52);
    created++;

    /* Just header, no sections */
    memset(buf, 0, sizeof(buf));
    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, MBPF_FORMAT_VERSION);
    write_le16(buf + 6, 20);
    write_le32(buf + 8, 0);
    write_le32(buf + 12, 0);
    write_le32(buf + 16, 0);
    write_corpus_file("no_sections.mbpf", buf, 20);
    created++;

    /* Maximum section count hint (won't fit but parser should handle) */
    memset(buf, 0, sizeof(buf));
    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, MBPF_FORMAT_VERSION);
    write_le16(buf + 6, 36);
    write_le32(buf + 8, 0);
    write_le32(buf + 12, 1);
    write_le32(buf + 16, 0);
    write_le32(buf + 20, MBPF_SEC_MANIFEST);
    write_le32(buf + 24, 36);
    write_le32(buf + 28, 4);
    write_le32(buf + 32, 0);
    buf[36] = '{'; buf[37] = '}'; buf[38] = 0; buf[39] = 0;
    write_corpus_file("single_section.mbpf", buf, 40);
    created++;

    /* Invalid magic (for rejection testing) */
    memset(buf, 0, sizeof(buf));
    write_le32(buf + 0, 0x21444142); /* "BAD!" */
    write_le16(buf + 4, MBPF_FORMAT_VERSION);
    write_le16(buf + 6, 20);
    write_le32(buf + 8, 0);
    write_le32(buf + 12, 0);
    write_le32(buf + 16, 0);
    write_corpus_file("invalid_magic.mbpf", buf, 20);
    created++;

    /* Future version */
    memset(buf, 0, sizeof(buf));
    write_le32(buf + 0, MBPF_MAGIC);
    write_le16(buf + 4, 99);
    write_le16(buf + 6, 20);
    write_le32(buf + 8, 0);
    write_le32(buf + 12, 0);
    write_le32(buf + 16, 0);
    write_corpus_file("future_version.mbpf", buf, 20);
    created++;

    return created;
}

/* Create JSON manifest variations */
static int corpus_json_variations(void) {
    int created = 0;

    /* With maps array */
    {
        const char *manifest =
            "{"
            "\"program_name\":\"maps_test\","
            "\"program_version\":\"1.0\","
            "\"hook_type\":1,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":32769,"
            "\"target\":{\"word_size\":64,\"endianness\":0},"
            "\"mbpf_api_version\":65536,"
            "\"heap_size\":16384,"
            "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
            "\"capabilities\":[\"CAP_MAP_READ\",\"CAP_MAP_WRITE\"],"
            "\"maps\":["
            "{\"name\":\"hash1\",\"type\":2,\"key_size\":8,\"value_size\":16,\"max_entries\":100},"
            "{\"name\":\"array1\",\"type\":1,\"key_size\":4,\"value_size\":4,\"max_entries\":10}"
            "]"
            "}";
        size_t manifest_len = strlen(manifest);

        uint16_t header_size = 52;
        size_t total_len = header_size + manifest_len + 4;
        uint8_t *buf = malloc(total_len);
        memset(buf, 0, total_len);

        write_le32(buf + 0, MBPF_MAGIC);
        write_le16(buf + 4, MBPF_FORMAT_VERSION);
        write_le16(buf + 6, header_size);
        write_le32(buf + 8, 0);
        write_le32(buf + 12, 2);
        write_le32(buf + 16, 0);
        write_le32(buf + 20, MBPF_SEC_MANIFEST);
        write_le32(buf + 24, header_size);
        write_le32(buf + 28, manifest_len);
        write_le32(buf + 32, 0);
        write_le32(buf + 36, MBPF_SEC_BYTECODE);
        write_le32(buf + 40, header_size + manifest_len);
        write_le32(buf + 44, 4);
        write_le32(buf + 48, 0);
        memcpy(buf + header_size, manifest, manifest_len);

        write_corpus_file("json_with_maps.mbpf", buf, total_len);
        free(buf);
        created++;
    }

    /* With helper versions */
    {
        const char *manifest =
            "{"
            "\"program_name\":\"helper_ver\","
            "\"program_version\":\"1.0\","
            "\"hook_type\":1,"
            "\"hook_ctx_abi_version\":1,"
            "\"mquickjs_bytecode_version\":32769,"
            "\"target\":{\"word_size\":64,\"endianness\":0},"
            "\"mbpf_api_version\":65536,"
            "\"heap_size\":16384,"
            "\"budgets\":{\"max_steps\":100000,\"max_helpers\":1000},"
            "\"capabilities\":[\"CAP_TIME\",\"CAP_LOG\"],"
            "\"helper_versions\":{\"log\":65537,\"nowNs\":65536}"
            "}";
        size_t manifest_len = strlen(manifest);

        uint16_t header_size = 52;
        size_t total_len = header_size + manifest_len + 4;
        uint8_t *buf = malloc(total_len);
        memset(buf, 0, total_len);

        write_le32(buf + 0, MBPF_MAGIC);
        write_le16(buf + 4, MBPF_FORMAT_VERSION);
        write_le16(buf + 6, header_size);
        write_le32(buf + 8, 0);
        write_le32(buf + 12, 2);
        write_le32(buf + 16, 0);
        write_le32(buf + 20, MBPF_SEC_MANIFEST);
        write_le32(buf + 24, header_size);
        write_le32(buf + 28, manifest_len);
        write_le32(buf + 32, 0);
        write_le32(buf + 36, MBPF_SEC_BYTECODE);
        write_le32(buf + 40, header_size + manifest_len);
        write_le32(buf + 44, 4);
        write_le32(buf + 48, 0);
        memcpy(buf + header_size, manifest, manifest_len);

        write_corpus_file("json_helper_versions.mbpf", buf, total_len);
        free(buf);
        created++;
    }

    return created;
}

int main(void) {
    printf("Generating fuzz corpus for package parser...\n\n");

    create_corpus_dir();

    int total = 0;

    printf("Creating valid packages:\n");
    if (corpus_minimal_valid() == 0) total++;
    if (corpus_cbor_manifest() == 0) total++;
    if (corpus_all_sections() == 0) total++;

    printf("\nCreating edge case packages:\n");
    total += corpus_edge_cases();

    printf("\nCreating JSON variations:\n");
    total += corpus_json_variations();

    printf("\n==============================================\n");
    printf("Generated %d corpus files in %s/\n", total, CORPUS_DIR);
    printf("==============================================\n");

    return 0;
}
