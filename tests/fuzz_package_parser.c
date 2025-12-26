/*
 * Fuzz Test for microBPF Package Parser
 *
 * This is a libFuzzer harness that tests the .mbpf package parser
 * for security vulnerabilities (crashes, hangs, memory errors).
 *
 * Usage with libFuzzer:
 *   clang -fsanitize=fuzzer,address -o fuzz_package tests/fuzz_package_parser.c \
 *         -Iinclude -Ideps/mquickjs -Lbuild -lmbpf -lm
 *   ./fuzz_package corpus/
 *
 * Usage as standalone test (with corpus files):
 *   gcc -DFUZZ_STANDALONE -o fuzz_package_standalone tests/fuzz_package_parser.c \
 *       -Iinclude -Ideps/mquickjs -Lbuild -lmbpf -lm
 *   ./fuzz_package_standalone tests/fuzz_corpus/
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/*
 * Fuzz the package parser with arbitrary input.
 *
 * This function exercises all the parsing APIs:
 * - mbpf_package_parse_header
 * - mbpf_package_parse_section_table
 * - mbpf_package_get_section
 * - mbpf_package_parse_manifest
 * - mbpf_package_validate_crc
 * - mbpf_package_is_signed
 * - mbpf_debug_info_parse
 *
 * The parser must handle malformed input gracefully without:
 * - Crashing
 * - Hanging (infinite loops)
 * - Memory corruption
 * - Memory leaks
 */
static int fuzz_one_input(const uint8_t *data, size_t size) {
    mbpf_file_header_t header;
    mbpf_section_desc_t sections[16];
    uint32_t section_count;
    mbpf_manifest_t manifest;
    const void *section_data;
    size_t section_len;
    int result;
    int is_signed;
    int has_debug;
    mbpf_debug_info_t debug_info;

    /* Test header parsing */
    result = mbpf_package_parse_header(data, size, &header);
    if (result != MBPF_OK) {
        /* Invalid header is expected for random input */
        return 0;
    }

    /* Test section table parsing */
    result = mbpf_package_parse_section_table(data, size, sections, 16, &section_count);
    if (result != MBPF_OK) {
        /* Invalid sections are expected for random input */
        return 0;
    }

    /* Test CRC validation */
    result = mbpf_package_validate_crc(data, size);
    /* CRC failure is fine, just don't crash */

    /* Test signature check */
    result = mbpf_package_is_signed(data, size, &is_signed);
    /* Result doesn't matter, just don't crash */

    /* Test debug section check */
    result = mbpf_package_has_debug(data, size, &has_debug);
    /* Result doesn't matter, just don't crash */

    /* Test getting each section type */
    result = mbpf_package_get_section(data, size, MBPF_SEC_MANIFEST,
                                       &section_data, &section_len);
    if (result == MBPF_OK && section_len > 0) {
        /* Test manifest parsing */
        memset(&manifest, 0, sizeof(manifest));
        result = mbpf_package_parse_manifest(section_data, section_len, &manifest);
        if (result == MBPF_OK) {
            /* Free any allocated resources */
            mbpf_manifest_free(&manifest);
        }
    }

    result = mbpf_package_get_section(data, size, MBPF_SEC_BYTECODE,
                                       &section_data, &section_len);
    /* Just check we don't crash */

    result = mbpf_package_get_section(data, size, MBPF_SEC_MAPS,
                                       &section_data, &section_len);
    /* Just check we don't crash */

    result = mbpf_package_get_section(data, size, MBPF_SEC_DEBUG,
                                       &section_data, &section_len);
    if (result == MBPF_OK && section_len > 0) {
        /* Test debug info parsing */
        memset(&debug_info, 0, sizeof(debug_info));
        result = mbpf_debug_info_parse(section_data, section_len, &debug_info);
        if (result == MBPF_OK) {
            mbpf_debug_info_free(&debug_info);
        }
    }

    result = mbpf_package_get_section(data, size, MBPF_SEC_SIG,
                                       &section_data, &section_len);
    /* Just check we don't crash */

    /* Test with unknown section types */
    for (int type = 6; type < 10; type++) {
        result = mbpf_package_get_section(data, size, type,
                                           &section_data, &section_len);
        /* Just check we don't crash */
    }

    return 0;
}

#ifdef FUZZ_STANDALONE
/*
 * Standalone test mode: read files from command line and fuzz them.
 */
#include <stdio.h>

static int run_corpus_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Cannot open: %s\n", filename);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 1024 * 1024) {
        fclose(f);
        fprintf(stderr, "Invalid file size: %s (%ld)\n", filename, fsize);
        return 1;
    }

    uint8_t *data = malloc(fsize);
    if (!data) {
        fclose(f);
        return 1;
    }

    size_t read_size = fread(data, 1, fsize, f);
    fclose(f);

    if (read_size != (size_t)fsize) {
        free(data);
        return 1;
    }

    int result = fuzz_one_input(data, read_size);
    free(data);
    return result;
}

int main(int argc, char **argv) {
    printf("microBPF Package Parser Fuzz Test (Standalone)\n");
    printf("==============================================\n\n");

    if (argc < 2) {
        printf("Usage: %s <corpus_file> [corpus_file2 ...]\n", argv[0]);
        printf("\nNo corpus files provided. Running with synthetic inputs...\n\n");

        /* Generate some synthetic test cases */
        int passed = 0;
        int total = 0;

        /* Test 1: Empty input */
        printf("Test empty input... ");
        fuzz_one_input(NULL, 0);
        fuzz_one_input((const uint8_t *)"", 0);
        printf("PASS\n");
        passed++; total++;

        /* Test 2: Small random inputs */
        printf("Test small random inputs... ");
        for (int i = 0; i < 100; i++) {
            uint8_t buf[64];
            for (int j = 0; j < 64; j++) {
                buf[j] = (uint8_t)(i * 17 + j * 31);
            }
            fuzz_one_input(buf, i % 64 + 1);
        }
        printf("PASS\n");
        passed++; total++;

        /* Test 3: Valid magic but corrupt rest */
        printf("Test valid magic with corruption... ");
        {
            uint8_t buf[256];
            memset(buf, 0, sizeof(buf));
            buf[0] = 0x46; buf[1] = 0x50; buf[2] = 0x42; buf[3] = 0x4D; /* MBPF */
            for (int i = 0; i < 50; i++) {
                for (int j = 4; j < 256; j++) {
                    buf[j] = (uint8_t)(i + j * 7);
                }
                fuzz_one_input(buf, i + 20);
            }
        }
        printf("PASS\n");
        passed++; total++;

        /* Test 4: Extreme section counts */
        printf("Test extreme section counts... ");
        {
            uint8_t buf[256];
            memset(buf, 0, sizeof(buf));
            buf[0] = 0x46; buf[1] = 0x50; buf[2] = 0x42; buf[3] = 0x4D;
            buf[4] = 1; buf[5] = 0; /* format version = 1 */
            buf[6] = 36; buf[7] = 0; /* header size = 36 */
            /* Try extreme section counts */
            uint32_t counts[] = {0, 1, 255, 65535, 0x7FFFFFFF, 0xFFFFFFFF};
            for (int i = 0; i < 6; i++) {
                buf[12] = counts[i] & 0xFF;
                buf[13] = (counts[i] >> 8) & 0xFF;
                buf[14] = (counts[i] >> 16) & 0xFF;
                buf[15] = (counts[i] >> 24) & 0xFF;
                fuzz_one_input(buf, 256);
            }
        }
        printf("PASS\n");
        passed++; total++;

        /* Test 5: Extreme section offsets/lengths */
        printf("Test extreme section bounds... ");
        {
            uint8_t buf[512];
            memset(buf, 0, sizeof(buf));
            buf[0] = 0x46; buf[1] = 0x50; buf[2] = 0x42; buf[3] = 0x4D;
            buf[4] = 1; buf[5] = 0;
            buf[6] = 36; buf[7] = 0;
            buf[12] = 1; /* 1 section */

            /* Section type = MANIFEST (1) */
            buf[20] = 1;
            /* Offset and length pairs to test */
            struct { uint32_t offset; uint32_t length; } tests[] = {
                {0, 0},
                {36, 0},
                {36, 100},
                {0, 0xFFFFFFFF},
                {0xFFFFFFFF, 0},
                {0xFFFFFFFF, 0xFFFFFFFF},
                {0x7FFFFFFF, 0x7FFFFFFF},
                {100, 500},
                {500, 100},
            };
            for (int i = 0; i < 9; i++) {
                buf[24] = tests[i].offset & 0xFF;
                buf[25] = (tests[i].offset >> 8) & 0xFF;
                buf[26] = (tests[i].offset >> 16) & 0xFF;
                buf[27] = (tests[i].offset >> 24) & 0xFF;
                buf[28] = tests[i].length & 0xFF;
                buf[29] = (tests[i].length >> 8) & 0xFF;
                buf[30] = (tests[i].length >> 16) & 0xFF;
                buf[31] = (tests[i].length >> 24) & 0xFF;
                fuzz_one_input(buf, 512);
            }
        }
        printf("PASS\n");
        passed++; total++;

        /* Test 6: Manifest parsing edge cases */
        printf("Test manifest parsing edge cases... ");
        {
            /* CBOR: empty map */
            uint8_t cbor_empty[] = {0xA0};
            fuzz_one_input(cbor_empty, sizeof(cbor_empty));

            /* JSON: empty object */
            uint8_t json_empty[] = "{}";
            fuzz_one_input(json_empty, sizeof(json_empty) - 1);

            /* Truncated CBOR */
            uint8_t cbor_trunc[] = {0xA5, 0x6C};
            fuzz_one_input(cbor_trunc, sizeof(cbor_trunc));

            /* Truncated JSON */
            uint8_t json_trunc[] = "{\"program_name\":";
            fuzz_one_input(json_trunc, sizeof(json_trunc) - 1);

            /* Deeply nested CBOR */
            uint8_t cbor_deep[256];
            for (int i = 0; i < 256; i++) cbor_deep[i] = 0xA1;
            fuzz_one_input(cbor_deep, 256);

            /* Long strings in CBOR */
            uint8_t cbor_long[1024];
            cbor_long[0] = 0xA1;
            cbor_long[1] = 0x79; /* text string, 2-byte length */
            cbor_long[2] = 0x03; cbor_long[3] = 0xE8; /* 1000 bytes */
            memset(cbor_long + 4, 'A', 1000);
            fuzz_one_input(cbor_long, 1004);
        }
        printf("PASS\n");
        passed++; total++;

        /* Test 7: Debug section parsing */
        printf("Test debug section parsing... ");
        {
            /* Minimal valid debug section */
            uint8_t debug_min[48];
            memset(debug_min, 0, sizeof(debug_min));
            fuzz_one_input(debug_min, sizeof(debug_min));

            /* Truncated debug section */
            uint8_t debug_trunc[10];
            memset(debug_trunc, 0, sizeof(debug_trunc));
            fuzz_one_input(debug_trunc, sizeof(debug_trunc));

            /* Large map count */
            uint8_t debug_big[48];
            memset(debug_big, 0, sizeof(debug_big));
            debug_big[44] = 0xFF;
            debug_big[45] = 0xFF;
            debug_big[46] = 0xFF;
            debug_big[47] = 0xFF;
            fuzz_one_input(debug_big, sizeof(debug_big));
        }
        printf("PASS\n");
        passed++; total++;

        /* Test 8: Overlapping sections */
        printf("Test overlapping sections... ");
        {
            uint8_t buf[128];
            memset(buf, 0, sizeof(buf));
            buf[0] = 0x46; buf[1] = 0x50; buf[2] = 0x42; buf[3] = 0x4D;
            buf[4] = 1; buf[5] = 0;
            buf[6] = 52; buf[7] = 0; /* header + 2 sections = 52 bytes */
            buf[12] = 2; /* 2 sections */

            /* Section 1: offset 60, length 20 */
            buf[20] = 1; /* type = MANIFEST */
            buf[24] = 60; /* offset */
            buf[28] = 20; /* length */

            /* Section 2: overlaps with section 1 */
            buf[36] = 2; /* type = BYTECODE */
            buf[40] = 70; /* offset (overlaps) */
            buf[44] = 20; /* length */

            fuzz_one_input(buf, 128);
        }
        printf("PASS\n");
        passed++; total++;

        printf("\n=======================================\n");
        printf("Results: %d passed, %d failed\n", passed, total - passed);
        return passed == total ? 0 : 1;
    }

    /* Run corpus files */
    int failed = 0;
    for (int i = 1; i < argc; i++) {
        printf("Testing: %s... ", argv[i]);
        if (run_corpus_file(argv[i]) == 0) {
            printf("PASS\n");
        } else {
            printf("FAIL\n");
            failed++;
        }
    }

    printf("\n=======================================\n");
    printf("Results: %d passed, %d failed\n", argc - 1 - failed, failed);
    return failed > 0 ? 1 : 0;
}

#else
/*
 * libFuzzer entry point
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return fuzz_one_input(data, size);
}
#endif
