/*
 * create_mbpf - Create test .mbpf package files
 *
 * Usage: create_mbpf [options] -o output.mbpf
 *
 * Options:
 *   -o FILE      Output file (required)
 *   -m MAGIC     Magic number (default: 0x4D425046)
 *   -v VERSION   Format version (default: 1)
 *   -f FLAGS     Header flags (default: 0)
 *   --invalid-magic   Use invalid magic for testing
 *   --help       Show this help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MBPF_MAGIC 0x4D425046
#define MBPF_FORMAT_VERSION 1

#define MBPF_FLAG_SIGNED (1 << 0)
#define MBPF_FLAG_DEBUG  (1 << 1)

#define MBPF_SEC_MANIFEST  1
#define MBPF_SEC_BYTECODE  2

static void write_le16(FILE *f, uint16_t val) {
    fputc(val & 0xFF, f);
    fputc((val >> 8) & 0xFF, f);
}

static void write_le32(FILE *f, uint32_t val) {
    fputc(val & 0xFF, f);
    fputc((val >> 8) & 0xFF, f);
    fputc((val >> 16) & 0xFF, f);
    fputc((val >> 24) & 0xFF, f);
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] -o output.mbpf\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -o FILE      Output file (required)\n");
    fprintf(stderr, "  -m MAGIC     Magic number (default: 0x4D425046)\n");
    fprintf(stderr, "  -v VERSION   Format version (default: 1)\n");
    fprintf(stderr, "  -f FLAGS     Header flags (default: 0)\n");
    fprintf(stderr, "  --invalid-magic   Use invalid magic for testing\n");
    fprintf(stderr, "  --help       Show this help\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    const char *output = NULL;
    uint32_t magic = MBPF_MAGIC;
    uint16_t version = MBPF_FORMAT_VERSION;
    uint32_t flags = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            magic = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
            version = (uint16_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            flags = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--invalid-magic") == 0) {
            magic = 0x21444142;  /* "BAD!" */
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
        }
    }

    if (!output) {
        fprintf(stderr, "Error: output file required (-o)\n");
        usage(argv[0]);
    }

    FILE *f = fopen(output, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Calculate header size: 20 bytes header + 2 * 16 bytes sections */
    uint32_t section_count = 2;
    uint16_t header_size = 20 + section_count * 16;

    /* Minimal manifest: just a JSON object with program_name */
    const char *manifest = "{\"program_name\":\"test\",\"hook_type\":1}";
    uint32_t manifest_len = (uint32_t)strlen(manifest);

    /* Minimal bytecode placeholder (empty) */
    uint32_t bytecode_len = 4;
    uint8_t bytecode[4] = {0, 0, 0, 0};

    /* Calculate section offsets */
    uint32_t manifest_offset = header_size;
    uint32_t bytecode_offset = manifest_offset + manifest_len;

    /* Write header */
    write_le32(f, magic);           /* magic */
    write_le16(f, version);         /* format_version */
    write_le16(f, header_size);     /* header_size */
    write_le32(f, flags);           /* flags */
    write_le32(f, section_count);   /* section_count */
    write_le32(f, 0);               /* file_crc32 (unused) */

    /* Write section descriptors */
    /* Section 0: MANIFEST */
    write_le32(f, MBPF_SEC_MANIFEST);
    write_le32(f, manifest_offset);
    write_le32(f, manifest_len);
    write_le32(f, 0);  /* crc32 */

    /* Section 1: BYTECODE */
    write_le32(f, MBPF_SEC_BYTECODE);
    write_le32(f, bytecode_offset);
    write_le32(f, bytecode_len);
    write_le32(f, 0);  /* crc32 */

    /* Write manifest section */
    fwrite(manifest, 1, manifest_len, f);

    /* Write bytecode section */
    fwrite(bytecode, 1, bytecode_len, f);

    fclose(f);

    printf("Created %s:\n", output);
    printf("  Magic: 0x%08X\n", magic);
    printf("  Format version: %u\n", version);
    printf("  Header size: %u bytes\n", header_size);
    printf("  Flags: 0x%08X\n", flags);
    printf("  Sections: %u\n", section_count);
    printf("  Total size: %u bytes\n",
           bytecode_offset + bytecode_len);

    return 0;
}
