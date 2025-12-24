/*
 * microBPF Package Parser
 *
 * Parses .mbpf binary packages.
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include <stdlib.h>
#include <string.h>

/* CRC32 lookup table */
static uint32_t crc32_table[256];
static bool crc32_table_initialized = false;

static void crc32_init_table(void) {
    if (crc32_table_initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            if (c & 1) {
                c = 0xEDB88320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        crc32_table[i] = c;
    }
    crc32_table_initialized = true;
}

uint32_t mbpf_crc32(const void *data, size_t len) {
    crc32_init_table();

    const uint8_t *buf = data;
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

/* Parse file header */
int mbpf_package_parse_header(const void *data, size_t len,
                               mbpf_file_header_t *out_header) {
    if (!data || len < sizeof(mbpf_file_header_t) || !out_header) {
        return MBPF_ERR_INVALID_ARG;
    }

    const uint8_t *buf = data;

    /* Read header fields (little-endian) */
    out_header->magic = (uint32_t)buf[0] |
                        ((uint32_t)buf[1] << 8) |
                        ((uint32_t)buf[2] << 16) |
                        ((uint32_t)buf[3] << 24);
    out_header->format_version = (uint16_t)buf[4] |
                                 ((uint16_t)buf[5] << 8);
    out_header->header_size = (uint16_t)buf[6] |
                              ((uint16_t)buf[7] << 8);
    out_header->flags = (uint32_t)buf[8] |
                        ((uint32_t)buf[9] << 8) |
                        ((uint32_t)buf[10] << 16) |
                        ((uint32_t)buf[11] << 24);
    out_header->section_count = (uint32_t)buf[12] |
                                ((uint32_t)buf[13] << 8) |
                                ((uint32_t)buf[14] << 16) |
                                ((uint32_t)buf[15] << 24);
    out_header->file_crc32 = (uint32_t)buf[16] |
                             ((uint32_t)buf[17] << 8) |
                             ((uint32_t)buf[18] << 16) |
                             ((uint32_t)buf[19] << 24);

    /* Validate magic */
    if (out_header->magic != MBPF_MAGIC) {
        return MBPF_ERR_INVALID_MAGIC;
    }

    /* Validate version */
    if (out_header->format_version < 1 ||
        out_header->format_version > MBPF_FORMAT_VERSION) {
        return MBPF_ERR_UNSUPPORTED_VER;
    }

    /* Validate header size */
    size_t expected_size = sizeof(mbpf_file_header_t) +
                           out_header->section_count * sizeof(mbpf_section_desc_t);
    if (out_header->header_size < expected_size || out_header->header_size > len) {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    return MBPF_OK;
}

/* Helper to read a section descriptor from buffer */
static void read_section_desc(const uint8_t *buf, mbpf_section_desc_t *desc) {
    desc->type = (uint32_t)buf[0] |
                 ((uint32_t)buf[1] << 8) |
                 ((uint32_t)buf[2] << 16) |
                 ((uint32_t)buf[3] << 24);
    desc->offset = (uint32_t)buf[4] |
                   ((uint32_t)buf[5] << 8) |
                   ((uint32_t)buf[6] << 16) |
                   ((uint32_t)buf[7] << 24);
    desc->length = (uint32_t)buf[8] |
                   ((uint32_t)buf[9] << 8) |
                   ((uint32_t)buf[10] << 16) |
                   ((uint32_t)buf[11] << 24);
    desc->crc32 = (uint32_t)buf[12] |
                  ((uint32_t)buf[13] << 8) |
                  ((uint32_t)buf[14] << 16) |
                  ((uint32_t)buf[15] << 24);
}

/* Check if two sections overlap */
static bool sections_overlap(const mbpf_section_desc_t *a,
                             const mbpf_section_desc_t *b) {
    /* Empty sections don't overlap */
    if (a->length == 0 || b->length == 0) {
        return false;
    }

    uint64_t a_start = a->offset;
    uint64_t a_end = (uint64_t)a->offset + a->length;
    uint64_t b_start = b->offset;
    uint64_t b_end = (uint64_t)b->offset + b->length;

    /* Check overlap: sections overlap if neither ends before the other starts */
    return (a_start < b_end) && (b_start < a_end);
}

/* Parse section table */
int mbpf_package_parse_section_table(const void *data, size_t len,
                                      mbpf_section_desc_t *out_sections,
                                      uint32_t max_sections,
                                      uint32_t *out_count) {
    if (!data || !out_count) {
        return MBPF_ERR_INVALID_ARG;
    }

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(data, len, &header);
    if (err != MBPF_OK) {
        return err;
    }

    *out_count = header.section_count;

    /* If caller just wants the count, we're done */
    if (!out_sections) {
        return MBPF_OK;
    }

    if (max_sections < header.section_count) {
        return MBPF_ERR_INVALID_ARG;
    }

    const uint8_t *buf = data;
    const uint8_t *section_table = buf + sizeof(mbpf_file_header_t);

    /* Read all section descriptors */
    for (uint32_t i = 0; i < header.section_count; i++) {
        const uint8_t *sec = section_table + i * sizeof(mbpf_section_desc_t);
        read_section_desc(sec, &out_sections[i]);

        /* Validate section bounds */
        uint64_t end = (uint64_t)out_sections[i].offset + out_sections[i].length;
        if (end > len) {
            return MBPF_ERR_SECTION_BOUNDS;
        }
    }

    /* Check for overlapping sections */
    for (uint32_t i = 0; i < header.section_count; i++) {
        for (uint32_t j = i + 1; j < header.section_count; j++) {
            if (sections_overlap(&out_sections[i], &out_sections[j])) {
                return MBPF_ERR_SECTION_OVERLAP;
            }
        }
    }

    return MBPF_OK;
}

/* Get a section by type */
int mbpf_package_get_section(const void *data, size_t len,
                              mbpf_section_type_t type,
                              const void **out_data, size_t *out_len) {
    if (!data || !out_data || !out_len) {
        return MBPF_ERR_INVALID_ARG;
    }

    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(data, len, &header);
    if (err != MBPF_OK) {
        return err;
    }

    const uint8_t *buf = data;
    const uint8_t *section_table = buf + sizeof(mbpf_file_header_t);

    for (uint32_t i = 0; i < header.section_count; i++) {
        const uint8_t *sec = section_table + i * sizeof(mbpf_section_desc_t);

        uint32_t sec_type = (uint32_t)sec[0] |
                            ((uint32_t)sec[1] << 8) |
                            ((uint32_t)sec[2] << 16) |
                            ((uint32_t)sec[3] << 24);
        uint32_t sec_offset = (uint32_t)sec[4] |
                              ((uint32_t)sec[5] << 8) |
                              ((uint32_t)sec[6] << 16) |
                              ((uint32_t)sec[7] << 24);
        uint32_t sec_length = (uint32_t)sec[8] |
                              ((uint32_t)sec[9] << 8) |
                              ((uint32_t)sec[10] << 16) |
                              ((uint32_t)sec[11] << 24);

        if (sec_type == type) {
            /* Validate bounds */
            if (sec_offset + sec_length > len) {
                return MBPF_ERR_INVALID_PACKAGE;
            }

            *out_data = buf + sec_offset;
            *out_len = sec_length;
            return MBPF_OK;
        }
    }

    return MBPF_ERR_MISSING_SECTION;
}

/* Parse manifest (minimal JSON parser for required fields) */
int mbpf_package_parse_manifest(const void *manifest_data, size_t len,
                                 mbpf_manifest_t *out_manifest) {
    if (!manifest_data || !out_manifest) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Initialize with defaults */
    memset(out_manifest, 0, sizeof(mbpf_manifest_t));
    strcpy(out_manifest->entry_symbol, "mbpf_prog");
    out_manifest->heap_size = 16384;
    out_manifest->budgets.max_steps = 100000;
    out_manifest->budgets.max_helpers = 1000;
    out_manifest->target.word_size = sizeof(void*) == 8 ? 64 : 32;
    out_manifest->target.endianness = 0; /* little */

    /* TODO: Implement proper CBOR/JSON parsing */
    /* For now, just validate it's not empty */
    if (len == 0) {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    return MBPF_OK;
}

/* Free manifest resources */
void mbpf_manifest_free(mbpf_manifest_t *manifest) {
    if (!manifest) return;

    if (manifest->maps) {
        free(manifest->maps);
        manifest->maps = NULL;
    }
    manifest->map_count = 0;
}

/* Validate CRCs */
int mbpf_package_validate_crc(const void *data, size_t len) {
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(data, len, &header);
    if (err != MBPF_OK) {
        return err;
    }

    /* Validate file CRC if present */
    if (header.file_crc32 != 0) {
        /* CRC is calculated over the entire file except the file_crc32 field */
        uint32_t computed = mbpf_crc32(data, 16); /* Header before crc */
        const uint8_t *rest = (const uint8_t *)data + 20;
        size_t rest_len = len - 20;

        /* Continue CRC over rest of file */
        crc32_init_table();
        uint32_t crc = computed ^ 0xFFFFFFFF;
        for (size_t i = 0; i < rest_len; i++) {
            crc = crc32_table[(crc ^ rest[i]) & 0xFF] ^ (crc >> 8);
        }
        computed = crc ^ 0xFFFFFFFF;

        if (computed != header.file_crc32) {
            return MBPF_ERR_INVALID_PACKAGE;
        }
    }

    return MBPF_OK;
}
