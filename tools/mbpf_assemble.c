/*
 * mbpf_assemble - Assemble .mbpf package from sections
 *
 * Usage: mbpf_assemble [options] -o output.mbpf
 *
 * Options:
 *   -m FILE      Manifest file (CBOR or JSON)
 *   -b FILE      Bytecode file (.qjbc)
 *   -d FILE      Debug info file (optional)
 *   -o FILE      Output .mbpf file
 *   --crc        Compute file and section CRCs
 *   --debug      Set DEBUG flag in header
 *   -h, --help   Show help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "mbpf.h"
#include "mbpf_package.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] -o output.mbpf\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -m FILE      Manifest file (CBOR or JSON)\n");
    fprintf(stderr, "  -b FILE      Bytecode file (.qjbc)\n");
    fprintf(stderr, "  -d FILE      Debug info file (optional)\n");
    fprintf(stderr, "  -o FILE      Output .mbpf file\n");
    fprintf(stderr, "  --crc        Compute file and section CRCs\n");
    fprintf(stderr, "  --debug      Set DEBUG flag in header\n");
    fprintf(stderr, "  -h, --help   Show help\n");
    exit(1);
}

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < 0) {
        perror("ftell");
        fclose(f);
        return NULL;
    }

    uint8_t *data = malloc((size_t)size);
    if (!data) {
        fprintf(stderr, "Failed to allocate %ld bytes\n", size);
        fclose(f);
        return NULL;
    }

    size_t read_len = fread(data, 1, (size_t)size, f);
    fclose(f);

    if (read_len != (size_t)size) {
        fprintf(stderr, "Failed to read %ld bytes from %s\n", size, path);
        free(data);
        return NULL;
    }

    *out_len = (size_t)size;
    return data;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return -1;
    }

    size_t written = fwrite(data, 1, len, f);
    fclose(f);

    if (written != len) {
        fprintf(stderr, "Failed to write %zu bytes to %s\n", len, path);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    const char *manifest_file = NULL;
    const char *bytecode_file = NULL;
    const char *debug_file = NULL;
    const char *output_file = NULL;
    int compute_crc = 0;
    int debug_flag = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            manifest_file = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bytecode_file = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            debug_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--crc") == 0) {
            compute_crc = 1;
        } else if (strcmp(argv[i], "--debug") == 0) {
            debug_flag = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
        }
    }

    if (!output_file) {
        fprintf(stderr, "Error: output file required (-o)\n");
        usage(argv[0]);
    }

    if (!manifest_file) {
        fprintf(stderr, "Error: manifest file required (-m)\n");
        usage(argv[0]);
    }

    if (!bytecode_file) {
        fprintf(stderr, "Error: bytecode file required (-b)\n");
        usage(argv[0]);
    }

    /* Read input files */
    uint8_t *manifest_data = NULL;
    size_t manifest_len = 0;
    uint8_t *bytecode_data = NULL;
    size_t bytecode_len = 0;
    uint8_t *debug_data = NULL;
    size_t debug_len = 0;

    manifest_data = read_file(manifest_file, &manifest_len);
    if (!manifest_data) {
        return 1;
    }

    bytecode_data = read_file(bytecode_file, &bytecode_len);
    if (!bytecode_data) {
        free(manifest_data);
        return 1;
    }

    if (debug_file) {
        debug_data = read_file(debug_file, &debug_len);
        if (!debug_data) {
            free(manifest_data);
            free(bytecode_data);
            return 1;
        }
    }

    /* Prepare sections */
    mbpf_section_input_t sections[3];
    uint32_t section_count = 0;

    sections[section_count].type = MBPF_SEC_MANIFEST;
    sections[section_count].data = manifest_data;
    sections[section_count].len = manifest_len;
    section_count++;

    sections[section_count].type = MBPF_SEC_BYTECODE;
    sections[section_count].data = bytecode_data;
    sections[section_count].len = bytecode_len;
    section_count++;

    if (debug_data) {
        sections[section_count].type = MBPF_SEC_DEBUG;
        sections[section_count].data = debug_data;
        sections[section_count].len = debug_len;
        section_count++;
    }

    /* Prepare options */
    mbpf_assemble_opts_t opts = {
        .compute_file_crc = compute_crc,
        .compute_section_crcs = compute_crc,
        .flags = debug_flag ? MBPF_FLAG_DEBUG : 0
    };

    /* Calculate required size */
    size_t pkg_size = mbpf_package_size(sections, section_count);
    if (pkg_size == 0) {
        fprintf(stderr, "Error: failed to calculate package size\n");
        free(manifest_data);
        free(bytecode_data);
        free(debug_data);
        return 1;
    }

    /* Allocate and assemble */
    uint8_t *pkg = malloc(pkg_size);
    if (!pkg) {
        fprintf(stderr, "Error: failed to allocate %zu bytes\n", pkg_size);
        free(manifest_data);
        free(bytecode_data);
        free(debug_data);
        return 1;
    }

    size_t out_len = pkg_size;
    int err = mbpf_package_assemble(sections, section_count, &opts, pkg, &out_len);
    if (err != MBPF_OK) {
        fprintf(stderr, "Error: assembly failed with code %d\n", err);
        free(pkg);
        free(manifest_data);
        free(bytecode_data);
        free(debug_data);
        return 1;
    }

    /* Write output file */
    if (write_file(output_file, pkg, out_len) != 0) {
        free(pkg);
        free(manifest_data);
        free(bytecode_data);
        free(debug_data);
        return 1;
    }

    printf("Created %s:\n", output_file);
    printf("  Sections: %u\n", section_count);
    printf("  Total size: %zu bytes\n", out_len);
    printf("  CRCs: %s\n", compute_crc ? "enabled" : "disabled");
    printf("  Flags: 0x%08x\n", opts.flags);

    free(pkg);
    free(manifest_data);
    free(bytecode_data);
    free(debug_data);

    return 0;
}
