/*
 * test_parse_file - Test parsing .mbpf files from disk
 *
 * Usage: test_parse_file <file.mbpf>
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file.mbpf>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(size);
    if (!data) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    fread(data, 1, size, f);
    fclose(f);

    printf("Parsing %s (%ld bytes)...\n", argv[1], size);

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(data, size, &header);

    if (err == MBPF_OK) {
        printf("  Status: OK\n");
        printf("  Magic: 0x%08X (%s)\n", header.magic,
               header.magic == MBPF_MAGIC ? "valid" : "INVALID");
        printf("  Format version: %u\n", header.format_version);
        printf("  Header size: %u bytes\n", header.header_size);
        printf("  Flags: 0x%08X\n", header.flags);
        printf("  Section count: %u\n", header.section_count);
        printf("  File CRC32: 0x%08X\n", header.file_crc32);
    } else {
        printf("  Status: ERROR (%d)\n", err);
        switch (err) {
            case MBPF_ERR_INVALID_ARG:
                printf("  Error: Invalid argument\n");
                break;
            case MBPF_ERR_INVALID_MAGIC:
                printf("  Error: Invalid magic number\n");
                break;
            case MBPF_ERR_UNSUPPORTED_VER:
                printf("  Error: Unsupported format version\n");
                break;
            case MBPF_ERR_INVALID_PACKAGE:
                printf("  Error: Invalid package structure\n");
                break;
            default:
                printf("  Error: Unknown error code\n");
                break;
        }
    }

    free(data);
    return err == MBPF_OK ? 0 : 1;
}
