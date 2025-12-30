/*
 * microBPF Package Parser
 *
 * Parses .mbpf binary packages.
 */

#include "mbpf.h"
#include "mbpf_package.h"
#include "mquickjs.h"
#include "ed25519.h"
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

    /*
     * Validate header size with overflow-safe checks.
     * The section table size is section_count * sizeof(mbpf_section_desc_t).
     * To prevent overflow, check that section_count doesn't exceed a safe maximum.
     */
    size_t max_sections = (SIZE_MAX - sizeof(mbpf_file_header_t)) / sizeof(mbpf_section_desc_t);
    if (out_header->section_count > max_sections) {
        return MBPF_ERR_INVALID_PACKAGE;
    }
    size_t expected_size = sizeof(mbpf_file_header_t) +
                           (size_t)out_header->section_count * sizeof(mbpf_section_desc_t);
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

        /*
         * Validate section bounds with overflow-safe checks.
         * We check: sec_offset + sec_length <= len
         * Rewritten as two checks to avoid integer overflow:
         * 1. sec_offset must not exceed len
         * 2. sec_length must not exceed len - sec_offset
         */
        if ((size_t)out_sections[i].offset > len) {
            return MBPF_ERR_SECTION_BOUNDS;
        }
        if ((size_t)out_sections[i].length > len - (size_t)out_sections[i].offset) {
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
            /*
             * Validate bounds using overflow-safe checks.
             * We check: sec_offset + sec_length <= len
             * Rewritten as two checks to avoid integer overflow:
             * 1. sec_offset must not exceed len
             * 2. sec_length must not exceed len - sec_offset
             */
            if ((size_t)sec_offset > len) {
                return MBPF_ERR_SECTION_BOUNDS;
            }
            if ((size_t)sec_length > len - (size_t)sec_offset) {
                return MBPF_ERR_SECTION_BOUNDS;
            }

            *out_data = buf + sec_offset;
            *out_len = sec_length;
            return MBPF_OK;
        }
    }

    return MBPF_ERR_MISSING_SECTION;
}

/* ============================================================================
 * Minimal CBOR Parser for Manifest
 * ============================================================================
 * CBOR types relevant to manifest parsing:
 * - Unsigned int: major 0 (0x00-0x1B)
 * - Text string: major 3 (0x60-0x7B)
 * - Array: major 4 (0x80-0x9B)
 * - Map: major 5 (0xA0-0xBB)
 */

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} cbor_reader_t;

static bool cbor_has_bytes(cbor_reader_t *r, size_t n) {
    return r->pos + n <= r->len;
}

static int cbor_read_initial_byte(cbor_reader_t *r, uint8_t *major, uint8_t *info) {
    if (!cbor_has_bytes(r, 1)) return -1;
    uint8_t b = r->data[r->pos++];
    *major = b >> 5;
    *info = b & 0x1F;
    return 0;
}

static int cbor_read_uint(cbor_reader_t *r, uint8_t info, uint64_t *out) {
    if (info < 24) {
        *out = info;
        return 0;
    } else if (info == 24) {
        if (!cbor_has_bytes(r, 1)) return -1;
        *out = r->data[r->pos++];
        return 0;
    } else if (info == 25) {
        if (!cbor_has_bytes(r, 2)) return -1;
        *out = ((uint64_t)r->data[r->pos] << 8) | r->data[r->pos + 1];
        r->pos += 2;
        return 0;
    } else if (info == 26) {
        if (!cbor_has_bytes(r, 4)) return -1;
        *out = ((uint64_t)r->data[r->pos] << 24) |
               ((uint64_t)r->data[r->pos + 1] << 16) |
               ((uint64_t)r->data[r->pos + 2] << 8) |
               r->data[r->pos + 3];
        r->pos += 4;
        return 0;
    } else if (info == 27) {
        if (!cbor_has_bytes(r, 8)) return -1;
        *out = ((uint64_t)r->data[r->pos] << 56) |
               ((uint64_t)r->data[r->pos + 1] << 48) |
               ((uint64_t)r->data[r->pos + 2] << 40) |
               ((uint64_t)r->data[r->pos + 3] << 32) |
               ((uint64_t)r->data[r->pos + 4] << 24) |
               ((uint64_t)r->data[r->pos + 5] << 16) |
               ((uint64_t)r->data[r->pos + 6] << 8) |
               r->data[r->pos + 7];
        r->pos += 8;
        return 0;
    }
    return -1; /* indefinite length not supported */
}

static int cbor_read_text_string(cbor_reader_t *r, char *buf, size_t buflen) {
    uint8_t major, info;
    if (cbor_read_initial_byte(r, &major, &info) != 0) return -1;
    if (major != 3) return -1;  /* Not a text string */

    uint64_t slen;
    if (cbor_read_uint(r, info, &slen) != 0) return -1;
    if (!cbor_has_bytes(r, (size_t)slen)) return -1;

    size_t copy_len = (size_t)slen < buflen - 1 ? (size_t)slen : buflen - 1;
    memcpy(buf, r->data + r->pos, copy_len);
    buf[copy_len] = '\0';
    r->pos += (size_t)slen;
    return 0;
}

static int cbor_read_unsigned(cbor_reader_t *r, uint64_t *out) {
    uint8_t major, info;
    if (cbor_read_initial_byte(r, &major, &info) != 0) return -1;
    if (major != 0) return -1;  /* Not an unsigned int */
    return cbor_read_uint(r, info, out);
}

static int cbor_peek_type(cbor_reader_t *r, uint8_t *major) {
    if (!cbor_has_bytes(r, 1)) return -1;
    *major = r->data[r->pos] >> 5;
    return 0;
}

static int cbor_skip_value(cbor_reader_t *r) {
    uint8_t major, info;
    if (cbor_read_initial_byte(r, &major, &info) != 0) return -1;

    uint64_t arg;
    if (cbor_read_uint(r, info, &arg) != 0) return -1;

    switch (major) {
        case 0: /* unsigned int */
        case 1: /* negative int */
            return 0;
        case 2: /* byte string */
        case 3: /* text string */
            if (!cbor_has_bytes(r, (size_t)arg)) return -1;
            r->pos += (size_t)arg;
            return 0;
        case 4: /* array */
            for (uint64_t i = 0; i < arg; i++) {
                if (cbor_skip_value(r) != 0) return -1;
            }
            return 0;
        case 5: /* map */
            for (uint64_t i = 0; i < arg; i++) {
                if (cbor_skip_value(r) != 0) return -1;
                if (cbor_skip_value(r) != 0) return -1;
            }
            return 0;
        case 7: /* simple/float */
            return 0;
        default:
            return -1;
    }
}

static int cbor_read_map_length(cbor_reader_t *r, uint64_t *out) {
    uint8_t major, info;
    if (cbor_read_initial_byte(r, &major, &info) != 0) return -1;
    if (major != 5) return -1;  /* Not a map */
    return cbor_read_uint(r, info, out);
}

static int cbor_read_array_length(cbor_reader_t *r, uint64_t *out) {
    uint8_t major, info;
    if (cbor_read_initial_byte(r, &major, &info) != 0) return -1;
    if (major != 4) return -1;  /* Not an array */
    return cbor_read_uint(r, info, out);
}

static int parse_target(cbor_reader_t *r, mbpf_target_t *target) {
    uint64_t map_len;
    if (cbor_read_map_length(r, &map_len) != 0) return -1;

    for (uint64_t i = 0; i < map_len; i++) {
        char key[32];
        if (cbor_read_text_string(r, key, sizeof(key)) != 0) return -1;

        if (strcmp(key, "word_size") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(r, &val) != 0) return -1;
            target->word_size = (uint8_t)val;
        } else if (strcmp(key, "endianness") == 0) {
            uint8_t major;
            if (cbor_peek_type(r, &major) != 0) return -1;
            if (major == 3) { /* text string */
                char val[16];
                if (cbor_read_text_string(r, val, sizeof(val)) != 0) return -1;
                target->endianness = (strcmp(val, "big") == 0) ? 1 : 0;
            } else {
                uint64_t val;
                if (cbor_read_unsigned(r, &val) != 0) return -1;
                target->endianness = (uint8_t)val;
            }
        } else {
            if (cbor_skip_value(r) != 0) return -1;
        }
    }
    return 0;
}

static int parse_budgets(cbor_reader_t *r, mbpf_budgets_t *budgets) {
    uint64_t map_len;
    if (cbor_read_map_length(r, &map_len) != 0) return -1;
    bool has_max_steps = false;
    bool has_max_helpers = false;

    for (uint64_t i = 0; i < map_len; i++) {
        char key[32];
        if (cbor_read_text_string(r, key, sizeof(key)) != 0) return -1;

        if (strcmp(key, "max_steps") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(r, &val) != 0) return -1;
            budgets->max_steps = (uint32_t)val;
            has_max_steps = true;
        } else if (strcmp(key, "max_helpers") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(r, &val) != 0) return -1;
            budgets->max_helpers = (uint32_t)val;
            has_max_helpers = true;
        } else if (strcmp(key, "max_wall_time_us") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(r, &val) != 0) return -1;
            budgets->max_wall_time_us = (uint32_t)val;
        } else {
            if (cbor_skip_value(r) != 0) return -1;
        }
    }
    if (!has_max_steps || !has_max_helpers) return -1;
    return 0;
}

static int parse_capabilities(cbor_reader_t *r, uint32_t *caps) {
    uint64_t arr_len;
    if (cbor_read_array_length(r, &arr_len) != 0) return -1;

    *caps = 0;
    for (uint64_t i = 0; i < arr_len; i++) {
        char cap[32];
        if (cbor_read_text_string(r, cap, sizeof(cap)) != 0) return -1;

        if (strcmp(cap, "CAP_LOG") == 0) *caps |= MBPF_CAP_LOG;
        else if (strcmp(cap, "CAP_MAP_READ") == 0) *caps |= MBPF_CAP_MAP_READ;
        else if (strcmp(cap, "CAP_MAP_WRITE") == 0) *caps |= MBPF_CAP_MAP_WRITE;
        else if (strcmp(cap, "CAP_MAP_ITERATE") == 0) *caps |= MBPF_CAP_MAP_ITERATE;
        else if (strcmp(cap, "CAP_EMIT") == 0) *caps |= MBPF_CAP_EMIT;
        else if (strcmp(cap, "CAP_TIME") == 0) *caps |= MBPF_CAP_TIME;
        else if (strcmp(cap, "CAP_STATS") == 0) *caps |= MBPF_CAP_STATS;
    }
    return 0;
}

/*
 * Validate a map name.
 * Valid map names must:
 * - Be non-empty
 * - Contain only printable ASCII characters (0x20-0x7E)
 * - Not contain control characters, quotes, or backslashes
 *   (these would cause issues in generated JS code)
 *
 * Returns 0 if valid, -1 if invalid.
 */
static int validate_map_name(const char *name) {
    if (!name || name[0] == '\0') {
        return -1;  /* Empty name */
    }

    for (const char *p = name; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;

        /* Reject control characters (0x00-0x1F) and DEL (0x7F) */
        if (c < 0x20 || c == 0x7F) {
            return -1;
        }

        /* Reject characters that are problematic in JS string contexts:
         * - Single quote ('), double quote ("), backslash (\)
         * These could be used for JS injection if escaping is somehow bypassed.
         * It's safer to reject them at parse time.
         */
        if (c == '\'' || c == '"' || c == '\\') {
            return -1;
        }

        /* Reject characters above 0x7E (extended ASCII / non-ASCII) */
        if (c > 0x7E) {
            return -1;
        }
    }

    return 0;
}

static int parse_map_def(cbor_reader_t *r, mbpf_map_def_t *map) {
    uint64_t map_len;
    if (cbor_read_map_length(r, &map_len) != 0) return -1;

    memset(map, 0, sizeof(*map));
    for (uint64_t i = 0; i < map_len; i++) {
        char key[32];
        if (cbor_read_text_string(r, key, sizeof(key)) != 0) return -1;

        if (strcmp(key, "name") == 0) {
            if (cbor_read_text_string(r, map->name, sizeof(map->name)) != 0) return -1;
            /* Validate map name to prevent JS injection */
            if (validate_map_name(map->name) != 0) return -1;
        } else if (strcmp(key, "type") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(r, &val) != 0) return -1;
            map->type = (uint32_t)val;
        } else if (strcmp(key, "key_size") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(r, &val) != 0) return -1;
            map->key_size = (uint32_t)val;
        } else if (strcmp(key, "value_size") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(r, &val) != 0) return -1;
            map->value_size = (uint32_t)val;
        } else if (strcmp(key, "max_entries") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(r, &val) != 0) return -1;
            map->max_entries = (uint32_t)val;
        } else if (strcmp(key, "flags") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(r, &val) != 0) return -1;
            map->flags = (uint32_t)val;
        } else {
            if (cbor_skip_value(r) != 0) return -1;
        }
    }
    return 0;
}

static int parse_maps_array(cbor_reader_t *r, mbpf_manifest_t *manifest) {
    uint64_t arr_len;
    if (cbor_read_array_length(r, &arr_len) != 0) return -1;

    if (arr_len == 0) return 0;

    manifest->maps = calloc(arr_len, sizeof(mbpf_map_def_t));
    if (!manifest->maps) return -1;
    manifest->map_count = (uint32_t)arr_len;

    for (uint64_t i = 0; i < arr_len; i++) {
        if (parse_map_def(r, &manifest->maps[i]) != 0) return -1;
    }
    return 0;
}

static int parse_helper_versions(cbor_reader_t *r, mbpf_manifest_t *manifest) {
    uint64_t map_len;
    if (cbor_read_map_length(r, &map_len) != 0) return -1;

    if (map_len == 0) return 0;

    manifest->helper_versions = calloc(map_len, sizeof(mbpf_helper_version_t));
    if (!manifest->helper_versions) return -1;
    manifest->helper_version_count = (uint32_t)map_len;

    for (uint64_t i = 0; i < map_len; i++) {
        if (cbor_read_text_string(r, manifest->helper_versions[i].name,
                                   sizeof(manifest->helper_versions[i].name)) != 0) {
            return -1;
        }
        uint64_t val;
        if (cbor_read_unsigned(r, &val) != 0) return -1;
        manifest->helper_versions[i].version = (uint32_t)val;
    }
    return 0;
}

/* Forward declaration for JSON parser */
static int parse_manifest_json(const void *manifest_data, size_t len,
                                mbpf_manifest_t *out_manifest);

/* Parse CBOR manifest */
static int parse_manifest_cbor(const void *manifest_data, size_t len,
                                mbpf_manifest_t *out_manifest) {
    cbor_reader_t r = { .data = manifest_data, .len = len, .pos = 0 };

    /* Expect top-level map */
    uint64_t top_map_len;
    if (cbor_read_map_length(&r, &top_map_len) != 0) {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    bool has_program_name = false;
    bool has_program_version = false;
    bool has_hook_type = false;
    bool has_hook_ctx_abi_version = false;
    bool has_mquickjs_bytecode_version = false;
    bool has_target = false;
    bool has_mbpf_api_version = false;
    bool has_heap_size = false;
    bool has_budgets = false;
    bool has_capabilities = false;

    for (uint64_t i = 0; i < top_map_len; i++) {
        char key[64];
        if (cbor_read_text_string(&r, key, sizeof(key)) != 0) {
            mbpf_manifest_free(out_manifest);
            return MBPF_ERR_INVALID_PACKAGE;
        }

        if (strcmp(key, "program_name") == 0) {
            if (cbor_read_text_string(&r, out_manifest->program_name,
                                       sizeof(out_manifest->program_name)) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            has_program_name = true;
        } else if (strcmp(key, "program_version") == 0) {
            if (cbor_read_text_string(&r, out_manifest->program_version,
                                       sizeof(out_manifest->program_version)) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            has_program_version = true;
        } else if (strcmp(key, "hook_type") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(&r, &val) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            out_manifest->hook_type = (uint32_t)val;
            has_hook_type = true;
        } else if (strcmp(key, "hook_ctx_abi_version") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(&r, &val) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            out_manifest->hook_ctx_abi_version = (uint32_t)val;
            has_hook_ctx_abi_version = true;
        } else if (strcmp(key, "entry_symbol") == 0) {
            if (cbor_read_text_string(&r, out_manifest->entry_symbol,
                                       sizeof(out_manifest->entry_symbol)) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
        } else if (strcmp(key, "mquickjs_bytecode_version") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(&r, &val) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            out_manifest->mquickjs_bytecode_version = (uint32_t)val;
            has_mquickjs_bytecode_version = true;
        } else if (strcmp(key, "target") == 0) {
            if (parse_target(&r, &out_manifest->target) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            has_target = true;
        } else if (strcmp(key, "mbpf_api_version") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(&r, &val) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            out_manifest->mbpf_api_version = (uint32_t)val;
            has_mbpf_api_version = true;
        } else if (strcmp(key, "heap_size") == 0) {
            uint64_t val;
            if (cbor_read_unsigned(&r, &val) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            out_manifest->heap_size = (uint32_t)val;
            has_heap_size = true;
        } else if (strcmp(key, "budgets") == 0) {
            if (parse_budgets(&r, &out_manifest->budgets) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            has_budgets = true;
        } else if (strcmp(key, "capabilities") == 0) {
            if (parse_capabilities(&r, &out_manifest->capabilities) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
            has_capabilities = true;
        } else if (strcmp(key, "helper_versions") == 0) {
            if (parse_helper_versions(&r, out_manifest) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
        } else if (strcmp(key, "maps") == 0) {
            if (parse_maps_array(&r, out_manifest) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
        } else {
            if (cbor_skip_value(&r) != 0) {
                mbpf_manifest_free(out_manifest);
                return MBPF_ERR_INVALID_PACKAGE;
            }
        }
    }

    /* Check required fields */
    if (!has_program_name || !has_program_version || !has_hook_type ||
        !has_hook_ctx_abi_version || !has_mquickjs_bytecode_version ||
        !has_target || !has_mbpf_api_version || !has_heap_size ||
        !has_budgets || !has_capabilities) {
        mbpf_manifest_free(out_manifest);
        return MBPF_ERR_INVALID_PACKAGE;
    }

    return MBPF_OK;
}

/* ============================================================================
 * Minimal JSON Parser for Manifest
 * ============================================================================
 * A simple JSON parser for manifest data. Supports the subset needed for
 * manifest parsing: objects, arrays, strings, and numbers.
 */

typedef struct {
    const char *data;
    size_t len;
    size_t pos;
} json_reader_t;

static void json_skip_whitespace(json_reader_t *r) {
    while (r->pos < r->len) {
        char c = r->data[r->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            r->pos++;
        } else {
            break;
        }
    }
}

static bool json_match_char(json_reader_t *r, char expected) {
    json_skip_whitespace(r);
    if (r->pos < r->len && r->data[r->pos] == expected) {
        r->pos++;
        return true;
    }
    return false;
}

static int json_read_string(json_reader_t *r, char *buf, size_t buflen) {
    json_skip_whitespace(r);
    if (r->pos >= r->len || r->data[r->pos] != '"') return -1;
    r->pos++;

    size_t out_pos = 0;
    while (r->pos < r->len && r->data[r->pos] != '"') {
        char c = r->data[r->pos++];
        if (c == '\\' && r->pos < r->len) {
            c = r->data[r->pos++];
            switch (c) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                default: break;
            }
        }
        if (out_pos < buflen - 1) {
            buf[out_pos++] = c;
        }
    }
    if (r->pos >= r->len) return -1;
    r->pos++;  /* skip closing quote */
    buf[out_pos] = '\0';
    return 0;
}

static int json_read_number(json_reader_t *r, uint64_t *out) {
    json_skip_whitespace(r);
    if (r->pos >= r->len) return -1;

    uint64_t val = 0;
    bool found = false;
    while (r->pos < r->len) {
        char c = r->data[r->pos];
        if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            r->pos++;
            found = true;
        } else {
            break;
        }
    }
    if (!found) return -1;
    *out = val;
    return 0;
}

static int json_skip_value(json_reader_t *r);

static int json_skip_string(json_reader_t *r) {
    char buf[256];
    return json_read_string(r, buf, sizeof(buf));
}

static int json_skip_number(json_reader_t *r) {
    json_skip_whitespace(r);
    bool found = false;
    while (r->pos < r->len) {
        char c = r->data[r->pos];
        if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
            r->pos++;
            found = true;
        } else {
            break;
        }
    }
    return found ? 0 : -1;
}

static int json_skip_array(json_reader_t *r) {
    if (!json_match_char(r, '[')) return -1;
    json_skip_whitespace(r);
    if (r->pos < r->len && r->data[r->pos] == ']') {
        r->pos++;
        return 0;
    }
    while (1) {
        if (json_skip_value(r) != 0) return -1;
        json_skip_whitespace(r);
        if (r->pos < r->len && r->data[r->pos] == ',') {
            r->pos++;
        } else if (r->pos < r->len && r->data[r->pos] == ']') {
            r->pos++;
            return 0;
        } else {
            return -1;
        }
    }
}

static int json_skip_object(json_reader_t *r) {
    if (!json_match_char(r, '{')) return -1;
    json_skip_whitespace(r);
    if (r->pos < r->len && r->data[r->pos] == '}') {
        r->pos++;
        return 0;
    }
    while (1) {
        if (json_skip_string(r) != 0) return -1;
        if (!json_match_char(r, ':')) return -1;
        if (json_skip_value(r) != 0) return -1;
        json_skip_whitespace(r);
        if (r->pos < r->len && r->data[r->pos] == ',') {
            r->pos++;
        } else if (r->pos < r->len && r->data[r->pos] == '}') {
            r->pos++;
            return 0;
        } else {
            return -1;
        }
    }
}

static int json_skip_value(json_reader_t *r) {
    json_skip_whitespace(r);
    if (r->pos >= r->len) return -1;
    char c = r->data[r->pos];
    if (c == '"') return json_skip_string(r);
    if (c == '{') return json_skip_object(r);
    if (c == '[') return json_skip_array(r);
    if ((c >= '0' && c <= '9') || c == '-') return json_skip_number(r);
    /* Handle true, false, null */
    if (r->pos + 4 <= r->len && strncmp(&r->data[r->pos], "true", 4) == 0) {
        r->pos += 4; return 0;
    }
    if (r->pos + 5 <= r->len && strncmp(&r->data[r->pos], "false", 5) == 0) {
        r->pos += 5; return 0;
    }
    if (r->pos + 4 <= r->len && strncmp(&r->data[r->pos], "null", 4) == 0) {
        r->pos += 4; return 0;
    }
    return -1;
}

static int json_parse_target(json_reader_t *r, mbpf_target_t *target) {
    if (!json_match_char(r, '{')) return -1;
    json_skip_whitespace(r);
    if (r->pos < r->len && r->data[r->pos] == '}') {
        r->pos++;
        return 0;
    }
    while (1) {
        char key[32];
        if (json_read_string(r, key, sizeof(key)) != 0) return -1;
        if (!json_match_char(r, ':')) return -1;

        if (strcmp(key, "word_size") == 0) {
            uint64_t val;
            if (json_read_number(r, &val) != 0) return -1;
            target->word_size = (uint8_t)val;
        } else if (strcmp(key, "endianness") == 0) {
            json_skip_whitespace(r);
            if (r->pos < r->len && r->data[r->pos] == '"') {
                char val[16];
                if (json_read_string(r, val, sizeof(val)) != 0) return -1;
                target->endianness = (strcmp(val, "big") == 0) ? 1 : 0;
            } else {
                uint64_t val;
                if (json_read_number(r, &val) != 0) return -1;
                target->endianness = (uint8_t)val;
            }
        } else {
            if (json_skip_value(r) != 0) return -1;
        }

        json_skip_whitespace(r);
        if (r->pos < r->len && r->data[r->pos] == ',') {
            r->pos++;
        } else if (r->pos < r->len && r->data[r->pos] == '}') {
            r->pos++;
            return 0;
        } else {
            return -1;
        }
    }
}

static int json_parse_budgets(json_reader_t *r, mbpf_budgets_t *budgets) {
    if (!json_match_char(r, '{')) return -1;
    json_skip_whitespace(r);
    if (r->pos < r->len && r->data[r->pos] == '}') {
        r->pos++;
        return -1;
    }
    bool has_max_steps = false;
    bool has_max_helpers = false;
    while (1) {
        char key[32];
        if (json_read_string(r, key, sizeof(key)) != 0) return -1;
        if (!json_match_char(r, ':')) return -1;

        if (strcmp(key, "max_steps") == 0) {
            uint64_t val;
            if (json_read_number(r, &val) != 0) return -1;
            budgets->max_steps = (uint32_t)val;
            has_max_steps = true;
        } else if (strcmp(key, "max_helpers") == 0) {
            uint64_t val;
            if (json_read_number(r, &val) != 0) return -1;
            budgets->max_helpers = (uint32_t)val;
            has_max_helpers = true;
        } else if (strcmp(key, "max_wall_time_us") == 0) {
            uint64_t val;
            if (json_read_number(r, &val) != 0) return -1;
            budgets->max_wall_time_us = (uint32_t)val;
        } else {
            if (json_skip_value(r) != 0) return -1;
        }

        json_skip_whitespace(r);
        if (r->pos < r->len && r->data[r->pos] == ',') {
            r->pos++;
        } else if (r->pos < r->len && r->data[r->pos] == '}') {
            r->pos++;
            if (!has_max_steps || !has_max_helpers) return -1;
            return 0;
        } else {
            return -1;
        }
    }
}

static int json_parse_capabilities(json_reader_t *r, uint32_t *caps) {
    if (!json_match_char(r, '[')) return -1;
    *caps = 0;
    json_skip_whitespace(r);
    if (r->pos < r->len && r->data[r->pos] == ']') {
        r->pos++;
        return 0;
    }
    while (1) {
        char cap[32];
        if (json_read_string(r, cap, sizeof(cap)) != 0) return -1;

        if (strcmp(cap, "CAP_LOG") == 0) *caps |= MBPF_CAP_LOG;
        else if (strcmp(cap, "CAP_MAP_READ") == 0) *caps |= MBPF_CAP_MAP_READ;
        else if (strcmp(cap, "CAP_MAP_WRITE") == 0) *caps |= MBPF_CAP_MAP_WRITE;
        else if (strcmp(cap, "CAP_MAP_ITERATE") == 0) *caps |= MBPF_CAP_MAP_ITERATE;
        else if (strcmp(cap, "CAP_EMIT") == 0) *caps |= MBPF_CAP_EMIT;
        else if (strcmp(cap, "CAP_TIME") == 0) *caps |= MBPF_CAP_TIME;
        else if (strcmp(cap, "CAP_STATS") == 0) *caps |= MBPF_CAP_STATS;

        json_skip_whitespace(r);
        if (r->pos < r->len && r->data[r->pos] == ',') {
            r->pos++;
        } else if (r->pos < r->len && r->data[r->pos] == ']') {
            r->pos++;
            return 0;
        } else {
            return -1;
        }
    }
}

static int json_parse_map_def(json_reader_t *r, mbpf_map_def_t *map) {
    memset(map, 0, sizeof(*map));
    if (!json_match_char(r, '{')) return -1;
    json_skip_whitespace(r);
    if (r->pos < r->len && r->data[r->pos] == '}') {
        r->pos++;
        return 0;
    }
    while (1) {
        char key[32];
        if (json_read_string(r, key, sizeof(key)) != 0) return -1;
        if (!json_match_char(r, ':')) return -1;

        if (strcmp(key, "name") == 0) {
            if (json_read_string(r, map->name, sizeof(map->name)) != 0) return -1;
            /* Validate map name to prevent JS injection */
            if (validate_map_name(map->name) != 0) return -1;
        } else if (strcmp(key, "type") == 0) {
            uint64_t val;
            if (json_read_number(r, &val) != 0) return -1;
            map->type = (uint32_t)val;
        } else if (strcmp(key, "key_size") == 0) {
            uint64_t val;
            if (json_read_number(r, &val) != 0) return -1;
            map->key_size = (uint32_t)val;
        } else if (strcmp(key, "value_size") == 0) {
            uint64_t val;
            if (json_read_number(r, &val) != 0) return -1;
            map->value_size = (uint32_t)val;
        } else if (strcmp(key, "max_entries") == 0) {
            uint64_t val;
            if (json_read_number(r, &val) != 0) return -1;
            map->max_entries = (uint32_t)val;
        } else if (strcmp(key, "flags") == 0) {
            uint64_t val;
            if (json_read_number(r, &val) != 0) return -1;
            map->flags = (uint32_t)val;
        } else {
            if (json_skip_value(r) != 0) return -1;
        }

        json_skip_whitespace(r);
        if (r->pos < r->len && r->data[r->pos] == ',') {
            r->pos++;
        } else if (r->pos < r->len && r->data[r->pos] == '}') {
            r->pos++;
            return 0;
        } else {
            return -1;
        }
    }
}

static int json_parse_maps_array(json_reader_t *r, mbpf_manifest_t *manifest) {
    if (!json_match_char(r, '[')) return -1;
    json_skip_whitespace(r);
    if (r->pos < r->len && r->data[r->pos] == ']') {
        r->pos++;
        return 0;
    }

    /* Count items first */
    size_t start = r->pos;
    uint32_t count = 0;
    int depth = 0;
    while (r->pos < r->len) {
        char c = r->data[r->pos];
        if (c == '{') depth++;
        else if (c == '}') {
            depth--;
            if (depth == 0) count++;
        }
        else if (c == ']' && depth == 0) break;
        r->pos++;
    }
    r->pos = start;

    if (count == 0) {
        if (!json_match_char(r, ']')) return -1;
        return 0;
    }

    manifest->maps = calloc(count, sizeof(mbpf_map_def_t));
    if (!manifest->maps) return -1;
    manifest->map_count = count;

    for (uint32_t i = 0; i < count; i++) {
        if (json_parse_map_def(r, &manifest->maps[i]) != 0) return -1;
        json_skip_whitespace(r);
        if (i < count - 1) {
            if (!json_match_char(r, ',')) return -1;
        }
    }

    if (!json_match_char(r, ']')) return -1;
    return 0;
}

static int json_parse_helper_versions(json_reader_t *r, mbpf_manifest_t *manifest) {
    if (!json_match_char(r, '{')) return -1;
    json_skip_whitespace(r);
    if (r->pos < r->len && r->data[r->pos] == '}') {
        r->pos++;
        return 0;
    }

    /* Count entries first */
    size_t start = r->pos;
    uint32_t count = 0;
    int depth = 0;
    while (r->pos < r->len) {
        char c = r->data[r->pos];
        if (c == '"' && depth == 0) count++;
        else if (c == '{') depth++;
        else if (c == '}') {
            if (depth == 0) break;
            depth--;
        }
        r->pos++;
    }
    count = count / 2;  /* pairs of key/value strings */
    r->pos = start;

    if (count == 0) {
        if (!json_match_char(r, '}')) return -1;
        return 0;
    }

    manifest->helper_versions = calloc(count, sizeof(mbpf_helper_version_t));
    if (!manifest->helper_versions) return -1;
    manifest->helper_version_count = count;

    for (uint32_t i = 0; i < count; i++) {
        if (json_read_string(r, manifest->helper_versions[i].name,
                              sizeof(manifest->helper_versions[i].name)) != 0) return -1;
        if (!json_match_char(r, ':')) return -1;
        uint64_t val;
        if (json_read_number(r, &val) != 0) return -1;
        manifest->helper_versions[i].version = (uint32_t)val;

        json_skip_whitespace(r);
        if (r->pos < r->len && r->data[r->pos] == ',') {
            r->pos++;
        } else if (r->pos < r->len && r->data[r->pos] == '}') {
            r->pos++;
            return 0;
        } else {
            return -1;
        }
    }
    return 0;
}

static int parse_manifest_json(const void *manifest_data, size_t len,
                                mbpf_manifest_t *out_manifest) {
    json_reader_t r = { .data = manifest_data, .len = len, .pos = 0 };

    if (!json_match_char(&r, '{')) return -1;

    bool has_program_name = false;
    bool has_program_version = false;
    bool has_hook_type = false;
    bool has_hook_ctx_abi_version = false;
    bool has_mquickjs_bytecode_version = false;
    bool has_target = false;
    bool has_mbpf_api_version = false;
    bool has_heap_size = false;
    bool has_budgets = false;
    bool has_capabilities = false;

    json_skip_whitespace(&r);
    if (r.pos < r.len && r.data[r.pos] == '}') {
        return -1;  /* Empty object missing required fields */
    }

    while (1) {
        char key[64];
        if (json_read_string(&r, key, sizeof(key)) != 0) return -1;
        if (!json_match_char(&r, ':')) return -1;

        if (strcmp(key, "program_name") == 0) {
            if (json_read_string(&r, out_manifest->program_name,
                                  sizeof(out_manifest->program_name)) != 0) return -1;
            has_program_name = true;
        } else if (strcmp(key, "program_version") == 0) {
            if (json_read_string(&r, out_manifest->program_version,
                                  sizeof(out_manifest->program_version)) != 0) return -1;
            has_program_version = true;
        } else if (strcmp(key, "hook_type") == 0) {
            uint64_t val;
            if (json_read_number(&r, &val) != 0) return -1;
            out_manifest->hook_type = (uint32_t)val;
            has_hook_type = true;
        } else if (strcmp(key, "hook_ctx_abi_version") == 0) {
            uint64_t val;
            if (json_read_number(&r, &val) != 0) return -1;
            out_manifest->hook_ctx_abi_version = (uint32_t)val;
            has_hook_ctx_abi_version = true;
        } else if (strcmp(key, "entry_symbol") == 0) {
            if (json_read_string(&r, out_manifest->entry_symbol,
                                  sizeof(out_manifest->entry_symbol)) != 0) return -1;
        } else if (strcmp(key, "mquickjs_bytecode_version") == 0) {
            uint64_t val;
            if (json_read_number(&r, &val) != 0) return -1;
            out_manifest->mquickjs_bytecode_version = (uint32_t)val;
            has_mquickjs_bytecode_version = true;
        } else if (strcmp(key, "target") == 0) {
            if (json_parse_target(&r, &out_manifest->target) != 0) return -1;
            has_target = true;
        } else if (strcmp(key, "mbpf_api_version") == 0) {
            uint64_t val;
            if (json_read_number(&r, &val) != 0) return -1;
            out_manifest->mbpf_api_version = (uint32_t)val;
            has_mbpf_api_version = true;
        } else if (strcmp(key, "heap_size") == 0) {
            uint64_t val;
            if (json_read_number(&r, &val) != 0) return -1;
            out_manifest->heap_size = (uint32_t)val;
            has_heap_size = true;
        } else if (strcmp(key, "budgets") == 0) {
            if (json_parse_budgets(&r, &out_manifest->budgets) != 0) return -1;
            has_budgets = true;
        } else if (strcmp(key, "capabilities") == 0) {
            if (json_parse_capabilities(&r, &out_manifest->capabilities) != 0) return -1;
            has_capabilities = true;
        } else if (strcmp(key, "helper_versions") == 0) {
            if (json_parse_helper_versions(&r, out_manifest) != 0) return -1;
        } else if (strcmp(key, "maps") == 0) {
            if (json_parse_maps_array(&r, out_manifest) != 0) return -1;
        } else {
            if (json_skip_value(&r) != 0) return -1;
        }

        json_skip_whitespace(&r);
        if (r.pos < r.len && r.data[r.pos] == ',') {
            r.pos++;
        } else if (r.pos < r.len && r.data[r.pos] == '}') {
            r.pos++;
            break;
        } else {
            return -1;
        }
    }

    /* Check required fields */
    if (!has_program_name || !has_program_version || !has_hook_type ||
        !has_hook_ctx_abi_version || !has_mquickjs_bytecode_version ||
        !has_target || !has_mbpf_api_version || !has_heap_size ||
        !has_budgets || !has_capabilities) {
        return -1;
    }

    return 0;
}

/* Parse manifest - supports both CBOR and JSON formats */
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

    if (len == 0) {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    const uint8_t *data = manifest_data;

    /* Detect format: CBOR maps start with 0xA0-0xBB or 0xBF, JSON starts with '{' */
    uint8_t first_byte = data[0];
    bool is_cbor = (first_byte >= 0xA0 && first_byte <= 0xBB) || first_byte == 0xBF;

    int err;
    if (is_cbor) {
        err = parse_manifest_cbor(manifest_data, len, out_manifest);
    } else if (first_byte == '{' || first_byte == ' ' || first_byte == '\t' ||
               first_byte == '\n' || first_byte == '\r') {
        /* Try JSON (may start with whitespace before '{') */
        err = parse_manifest_json(manifest_data, len, out_manifest);
        if (err != 0) {
            mbpf_manifest_free(out_manifest);
            return MBPF_ERR_INVALID_PACKAGE;
        }
    } else {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    return err;
}

/* Free manifest resources */
void mbpf_manifest_free(mbpf_manifest_t *manifest) {
    if (!manifest) return;

    if (manifest->maps) {
        free(manifest->maps);
        manifest->maps = NULL;
    }
    manifest->map_count = 0;

    if (manifest->helper_versions) {
        free(manifest->helper_versions);
        manifest->helper_versions = NULL;
    }
    manifest->helper_version_count = 0;
}

/*
 * Compute CRC32 over file data, skipping the file_crc32 field (bytes 16-19).
 * This allows the CRC to be computed over the entire file except the CRC field itself.
 */
static uint32_t mbpf_file_crc32(const void *data, size_t len) {
    crc32_init_table();

    const uint8_t *buf = data;
    uint32_t crc = 0xFFFFFFFF;

    /* Process bytes before file_crc32 field (bytes 0-15) */
    for (size_t i = 0; i < 16 && i < len; i++) {
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }

    /* Skip the file_crc32 field (bytes 16-19) */

    /* Process bytes after file_crc32 field (bytes 20 onwards) */
    for (size_t i = 20; i < len; i++) {
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

/* Validate file-level CRC */
int mbpf_package_validate_crc(const void *data, size_t len) {
    mbpf_file_header_t header;
    int err = mbpf_package_parse_header(data, len, &header);
    if (err != MBPF_OK) {
        return err;
    }

    /* Validate file CRC if present (non-zero) */
    if (header.file_crc32 != 0) {
        uint32_t computed = mbpf_file_crc32(data, len);
        if (computed != header.file_crc32) {
            return MBPF_ERR_CRC_MISMATCH;
        }
    }

    return MBPF_OK;
}

/* Validate per-section CRC */
int mbpf_package_validate_section_crc(const void *data, size_t len,
                                       const mbpf_section_desc_t *section) {
    if (!data || !section) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Skip validation if CRC is zero (not present) */
    if (section->crc32 == 0) {
        return MBPF_OK;
    }

    /* Validate section bounds */
    uint64_t end = (uint64_t)section->offset + section->length;
    if (end > len) {
        return MBPF_ERR_SECTION_BOUNDS;
    }

    /* Compute CRC over section data */
    const uint8_t *section_data = (const uint8_t *)data + section->offset;
    uint32_t computed = mbpf_crc32(section_data, section->length);

    if (computed != section->crc32) {
        return MBPF_ERR_CRC_MISMATCH;
    }

    return MBPF_OK;
}

/* ============================================================================
 * Bytecode Loading API
 * ============================================================================ */

/*
 * MQuickJS bytecode version calculation (mirrors mquickjs.c):
 *   - JS_BYTECODE_VERSION_32 = 0x0001 (base version)
 *   - For 64-bit (JSW=8): version = 0x0001 | ((8 & 8) << 12) = 0x8001
 *   - For 32-bit (JSW=4): version = 0x0001 | ((4 & 8) << 12) = 0x0001
 *
 * We use sizeof(void*) to detect word size since JSW is not exposed in the header.
 */
#define MBPF_JS_BYTECODE_VERSION_32 0x0001
#define MBPF_JSW (sizeof(void*))
#define MBPF_JS_BYTECODE_VERSION \
    (MBPF_JS_BYTECODE_VERSION_32 | ((MBPF_JSW & 8) << 12))

/* Get the expected bytecode version for this runtime */
uint16_t mbpf_bytecode_version(void) {
    /*
     * Return the bytecode version expected by this runtime.
     * This is computed using the same formula as MQuickJS to ensure
     * compatibility. The version encodes both the format version and
     * the word size (32-bit vs 64-bit).
     */
    return MBPF_JS_BYTECODE_VERSION;
}

/* Check if bytecode is valid MQuickJS bytecode (no context required) */
int mbpf_bytecode_check(const uint8_t *bytecode, size_t bytecode_len,
                        mbpf_bytecode_info_t *out_info) {
    if (!bytecode || bytecode_len < sizeof(JSBytecodeHeader)) {
        if (out_info) {
            out_info->is_valid = 0;
            out_info->bytecode_version = 0;
            out_info->relocation_result = -1;
        }
        return MBPF_ERR_INVALID_BYTECODE;
    }

    /* Check using JS_IsBytecode */
    int is_valid = JS_IsBytecode(bytecode, bytecode_len);

    if (out_info) {
        out_info->is_valid = is_valid;
        out_info->relocation_result = -1;  /* Not relocated yet */

        /* Extract version from header */
        const JSBytecodeHeader *hdr = (const JSBytecodeHeader *)bytecode;
        out_info->bytecode_version = hdr->version;
    }

    if (!is_valid) {
        return MBPF_ERR_INVALID_BYTECODE;
    }

    return MBPF_OK;
}

/*
 * Validate and load bytecode from a writable buffer.
 *
 * This function:
 * 1. Checks if bytecode is valid using JS_IsBytecode
 * 2. Validates bytecode version matches runtime expectations
 * 3. Calls JS_RelocateBytecode to prepare for execution
 * 4. Calls JS_LoadBytecode to get main_func
 */
int mbpf_bytecode_load(JSContext *ctx,
                       uint8_t *bytecode, size_t bytecode_len,
                       mbpf_bytecode_info_t *out_info,
                       void *out_main_func) {
    if (!ctx || !bytecode || bytecode_len < sizeof(JSBytecodeHeader)) {
        if (out_info) {
            out_info->is_valid = 0;
            out_info->bytecode_version = 0;
            out_info->relocation_result = -1;
        }
        return MBPF_ERR_INVALID_ARG;
    }

    /* Initialize output info */
    mbpf_bytecode_info_t info = {0};

    /* Step 1: Check if valid bytecode using JS_IsBytecode */
    if (!JS_IsBytecode(bytecode, bytecode_len)) {
        info.is_valid = 0;
        if (out_info) *out_info = info;
        return MBPF_ERR_INVALID_BYTECODE;
    }
    info.is_valid = 1;

    /* Step 2: Extract and verify bytecode version */
    const JSBytecodeHeader *hdr = (const JSBytecodeHeader *)bytecode;
    info.bytecode_version = hdr->version;

    /*
     * Check bytecode version matches runtime expectations.
     * The high bit (0x8000) indicates 64-bit vs 32-bit word size.
     * The low bits indicate the bytecode format version.
     * Both must match for the bytecode to be compatible.
     */
    uint16_t expected_version = mbpf_bytecode_version();
    if (info.bytecode_version != expected_version) {
        if (out_info) *out_info = info;
        return MBPF_ERR_UNSUPPORTED_VER;
    }

    /* Step 3: Relocate bytecode (modifies buffer in place) */
    int reloc_result = JS_RelocateBytecode(ctx, bytecode, (uint32_t)bytecode_len);
    info.relocation_result = reloc_result;

    if (reloc_result != 0) {
        if (out_info) *out_info = info;
        return MBPF_ERR_INVALID_BYTECODE;
    }

    /* Step 4: Load bytecode and get module */
    JSValue module_val = JS_LoadBytecode(ctx, bytecode);

    if (JS_IsException(module_val)) {
        if (out_info) *out_info = info;
        return MBPF_ERR_INVALID_BYTECODE;
    }

    /* Step 5: Run the module to define global functions (mbpf_prog, etc.) */
    JSValue run_result = JS_Run(ctx, module_val);

    if (JS_IsException(run_result)) {
        JS_GetException(ctx);  /* Clear exception */
        if (out_info) *out_info = info;
        return MBPF_ERR_INVALID_BYTECODE;
    }

    /* Return the run result (typically undefined for module-level code) */
    if (out_main_func) {
        *(JSValue *)out_main_func = run_result;
    }

    if (out_info) *out_info = info;
    return MBPF_OK;
}

/* ============================================================================
 * Ed25519 Signature Verification
 * ============================================================================ */

/*
 * Check if a package has a signature section.
 */
int mbpf_package_is_signed(const void *data, size_t len, int *out_signed) {
    if (!data || !out_signed) {
        return MBPF_ERR_INVALID_ARG;
    }

    *out_signed = 0;

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

        if (sec_type == MBPF_SEC_SIG) {
            *out_signed = 1;
            return MBPF_OK;
        }
    }

    return MBPF_OK;
}

/*
 * Get the signature section and the length of data it covers.
 *
 * The signature covers all bytes from file start up to (but excluding)
 * the signature section offset. The signature section MUST be the last
 * section in the file (i.e., sig_offset + 64 == file_length) to prevent
 * unsigned data from being appended after the signature.
 */
int mbpf_package_get_signature(const void *data, size_t len,
                                const uint8_t **out_sig,
                                size_t *out_data_len) {
    if (!data || !out_sig || !out_data_len) {
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

        if (sec_type == MBPF_SEC_SIG) {
            uint32_t sec_offset = (uint32_t)sec[4] |
                                  ((uint32_t)sec[5] << 8) |
                                  ((uint32_t)sec[6] << 16) |
                                  ((uint32_t)sec[7] << 24);
            uint32_t sec_length = (uint32_t)sec[8] |
                                  ((uint32_t)sec[9] << 8) |
                                  ((uint32_t)sec[10] << 16) |
                                  ((uint32_t)sec[11] << 24);

            /* Signature section must be exactly 64 bytes */
            if (sec_length != MBPF_ED25519_SIGNATURE_SIZE) {
                return MBPF_ERR_INVALID_PACKAGE;
            }

            /*
             * Validate section bounds using overflow-safe checks.
             * We check: sec_offset + sec_length <= len
             * Rewritten as: sec_length <= len - sec_offset (after checking sec_offset <= len)
             */
            if ((size_t)sec_offset > len) {
                return MBPF_ERR_SECTION_BOUNDS;
            }
            if ((size_t)sec_length > len - (size_t)sec_offset) {
                return MBPF_ERR_SECTION_BOUNDS;
            }

            /*
             * Security: Signature section must be the LAST section in the file.
             * This prevents unsigned data from being appended after the signature.
             * The signature must cover all bytes before it and end at the file boundary.
             * Since we already validated sec_offset + sec_length <= len above,
             * we just need to check equality: sec_offset + sec_length == len
             * Rewritten overflow-safe: len - sec_offset == sec_length
             */
            if (len - (size_t)sec_offset != (size_t)sec_length) {
                return MBPF_ERR_INVALID_PACKAGE;
            }

            *out_sig = buf + sec_offset;
            *out_data_len = sec_offset;  /* Signature covers bytes 0 to sec_offset */
            return MBPF_OK;
        }
    }

    return MBPF_ERR_MISSING_SECTION;
}

/*
 * Validate Ed25519 signature on a package.
 *
 * Behavior depends on opts settings:
 * - If package is signed and public_key is provided: verify signature
 * - If package is signed and public_key is NULL: return error
 * - If package is unsigned and production_mode: return error
 * - If package is unsigned and allow_unsigned: return OK
 */
int mbpf_package_verify_signature(const void *data, size_t len,
                                   const mbpf_sig_verify_opts_t *opts) {
    if (!data || !opts) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Check if package is signed */
    int is_signed = 0;
    int err = mbpf_package_is_signed(data, len, &is_signed);
    if (err != MBPF_OK) {
        return err;
    }

    if (!is_signed) {
        /* Package is unsigned */
        if (opts->production_mode) {
            /* Production mode requires signatures */
            return MBPF_ERR_MISSING_SECTION;
        }
        if (opts->allow_unsigned) {
            /* Development mode allows unsigned packages */
            return MBPF_OK;
        }
        /* Default: require signature */
        return MBPF_ERR_MISSING_SECTION;
    }

    /* Package is signed - need a public key to verify */
    if (!opts->public_key) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Get signature and data length */
    const uint8_t *sig;
    size_t data_len;
    err = mbpf_package_get_signature(data, len, &sig, &data_len);
    if (err != MBPF_OK) {
        return err;
    }

    /* Verify Ed25519 signature */
    int verify_result = ed25519_verify(sig, data, data_len, opts->public_key);
    if (verify_result != 0) {
        return MBPF_ERR_SIGNATURE;
    }

    return MBPF_OK;
}

/* ============================================================================
 * Package Assembly API
 * ============================================================================ */

/*
 * Write a 16-bit little-endian value to a buffer.
 */
static void write_le16(uint8_t *buf, uint16_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
}

/*
 * Write a 32-bit little-endian value to a buffer.
 */
static void write_le32(uint8_t *buf, uint32_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

/*
 * Calculate the size of an assembled package.
 */
size_t mbpf_package_size(const mbpf_section_input_t *sections,
                          uint32_t section_count) {
    if (!sections || section_count == 0 || section_count > MBPF_MAX_SECTIONS) {
        return 0;
    }

    /* Header: 20 bytes */
    size_t total = sizeof(mbpf_file_header_t);

    /* Section table: 16 bytes per section */
    total += section_count * sizeof(mbpf_section_desc_t);

    /* Section data */
    for (uint32_t i = 0; i < section_count; i++) {
        if (sections[i].len > 0 && !sections[i].data) {
            return 0;
        }
        total += sections[i].len;
    }

    return total;
}

/*
 * Assemble a .mbpf package from sections.
 */
int mbpf_package_assemble(const mbpf_section_input_t *sections,
                           uint32_t section_count,
                           const mbpf_assemble_opts_t *opts,
                           uint8_t *out_data, size_t *out_len) {
    if (!sections || section_count == 0 || !out_len) {
        return MBPF_ERR_INVALID_ARG;
    }

    if (section_count > MBPF_MAX_SECTIONS) {
        return MBPF_ERR_INVALID_ARG;
    }

    for (uint32_t i = 0; i < section_count; i++) {
        if (sections[i].len > 0 && !sections[i].data) {
            return MBPF_ERR_INVALID_ARG;
        }
    }

    /* Calculate required size */
    size_t required = mbpf_package_size(sections, section_count);
    if (required == 0) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Check buffer size */
    if (!out_data || *out_len < required) {
        *out_len = required;
        return MBPF_ERR_NO_MEM;
    }

    /* Use default options if not provided */
    mbpf_assemble_opts_t default_opts = {0};
    if (!opts) {
        opts = &default_opts;
    }

    /* Calculate header size (header + section table) */
    uint16_t header_size = (uint16_t)(sizeof(mbpf_file_header_t) +
                                       section_count * sizeof(mbpf_section_desc_t));

    /* Calculate section offsets */
    uint32_t offsets[MBPF_MAX_SECTIONS];
    uint32_t current_offset = header_size;
    for (uint32_t i = 0; i < section_count; i++) {
        offsets[i] = current_offset;
        current_offset += (uint32_t)sections[i].len;
    }

    /* Write file header */
    uint8_t *ptr = out_data;
    write_le32(ptr, MBPF_MAGIC);             ptr += 4;
    write_le16(ptr, MBPF_FORMAT_VERSION);    ptr += 2;
    write_le16(ptr, header_size);            ptr += 2;
    write_le32(ptr, opts->flags);            ptr += 4;
    write_le32(ptr, section_count);          ptr += 4;
    write_le32(ptr, 0);  /* file_crc32 placeholder, filled later if needed */
    ptr += 4;

    /* Write section table */
    for (uint32_t i = 0; i < section_count; i++) {
        uint32_t section_crc = 0;
        if (opts->compute_section_crcs && sections[i].len > 0) {
            section_crc = mbpf_crc32(sections[i].data, sections[i].len);
        }

        write_le32(ptr, (uint32_t)sections[i].type);  ptr += 4;
        write_le32(ptr, offsets[i]);                  ptr += 4;
        write_le32(ptr, (uint32_t)sections[i].len);   ptr += 4;
        write_le32(ptr, section_crc);                 ptr += 4;
    }

    /* Write section data */
    for (uint32_t i = 0; i < section_count; i++) {
        if (sections[i].len > 0 && sections[i].data) {
            memcpy(ptr, sections[i].data, sections[i].len);
            ptr += sections[i].len;
        }
    }

    /* Compute file CRC if requested (using mbpf_file_crc32 which skips the CRC field) */
    if (opts->compute_file_crc) {
        uint32_t file_crc = mbpf_file_crc32(out_data, required);
        /* file_crc32 is at offset 16 in header */
        write_le32(out_data + 16, file_crc);
    }

    *out_len = required;
    return MBPF_OK;
}

/* ============================================================================
 * Debug Section (MBPF_SEC_DEBUG) Parsing
 * ============================================================================ */

/*
 * Read a 32-bit little-endian value from a buffer.
 */
static uint32_t read_debug_le32(const uint8_t *buf) {
    return (uint32_t)buf[0] |
           ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

/* Helper to read a u32 from buffer with bounds check */
static int read_debug_u32(const uint8_t *buf, size_t len, size_t *offset, uint32_t *out) {
    if (*offset + 4 > len) return -1;
    *out = read_debug_le32(buf + *offset);
    *offset += 4;
    return 0;
}

/* Helper to read a string from buffer with bounds check */
static int read_debug_string(const uint8_t *buf, size_t len, size_t *offset,
                             char *out, size_t out_max) {
    uint32_t str_len;
    if (read_debug_u32(buf, len, offset, &str_len) < 0) return -1;

    if (str_len == 0) {
        out[0] = '\0';
        return 0;
    }

    if (*offset + str_len > len) return -1;
    uint32_t copy_len = str_len;
    if (copy_len > out_max - 1) copy_len = out_max - 1;

    memcpy(out, buf + *offset, copy_len);
    out[copy_len] = '\0';
    *offset += str_len;

    return 0;
}

int mbpf_debug_info_parse(const void *debug_data, size_t debug_len,
                          mbpf_debug_info_t *out_debug) {
    if (!debug_data || !out_debug) {
        return MBPF_ERR_INVALID_ARG;
    }

    memset(out_debug, 0, sizeof(*out_debug));

    const uint8_t *buf = debug_data;
    size_t offset = 0;

    /* Minimum size: flags(4) + source_hash(32) + entry_len(4) + hook_len(4) + map_count(4) */
    if (debug_len < 48) {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    /* Read flags */
    if (read_debug_u32(buf, debug_len, &offset, &out_debug->flags) < 0) {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    /* Read source hash */
    if (offset + 32 > debug_len) {
        return MBPF_ERR_INVALID_PACKAGE;
    }
    memcpy(out_debug->source_hash, buf + offset, 32);
    offset += 32;

    /* Read entry symbol */
    if (read_debug_string(buf, debug_len, &offset, out_debug->entry_symbol,
                          MBPF_DEBUG_MAX_SYMBOL_LEN) < 0) {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    /* Read hook name */
    if (read_debug_string(buf, debug_len, &offset, out_debug->hook_name,
                          MBPF_DEBUG_MAX_SYMBOL_LEN) < 0) {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    /* Read map count */
    if (read_debug_u32(buf, debug_len, &offset, &out_debug->map_count) < 0) {
        return MBPF_ERR_INVALID_PACKAGE;
    }

    /* Allocate and read map names */
    if (out_debug->map_count > 0) {
        /* Sanity check on map count */
        if (out_debug->map_count > 256) {
            return MBPF_ERR_INVALID_PACKAGE;
        }

        out_debug->map_names = calloc(out_debug->map_count,
                                       MBPF_DEBUG_MAX_SYMBOL_LEN);
        if (!out_debug->map_names) {
            return MBPF_ERR_NO_MEM;
        }

        for (uint32_t i = 0; i < out_debug->map_count; i++) {
            if (read_debug_string(buf, debug_len, &offset,
                                  out_debug->map_names[i],
                                  MBPF_DEBUG_MAX_SYMBOL_LEN) < 0) {
                mbpf_debug_info_free(out_debug);
                return MBPF_ERR_INVALID_PACKAGE;
            }
        }
    }

    return MBPF_OK;
}

void mbpf_debug_info_free(mbpf_debug_info_t *debug) {
    if (!debug) return;

    if (debug->map_names) {
        free(debug->map_names);
        debug->map_names = NULL;
    }
    debug->map_count = 0;
}

int mbpf_package_has_debug(const void *data, size_t len, int *out_has_debug) {
    if (!data || !out_has_debug) {
        return MBPF_ERR_INVALID_ARG;
    }

    const void *debug_data;
    size_t debug_len;
    int err = mbpf_package_get_section(data, len, MBPF_SEC_DEBUG,
                                        &debug_data, &debug_len);

    if (err == MBPF_OK) {
        *out_has_debug = 1;
    } else if (err == MBPF_ERR_MISSING_SECTION) {
        *out_has_debug = 0;
        return MBPF_OK;
    } else {
        return err;
    }

    return MBPF_OK;
}

int mbpf_package_get_debug_info(const void *data, size_t len,
                                 mbpf_debug_info_t *out_debug) {
    if (!data || !out_debug) {
        return MBPF_ERR_INVALID_ARG;
    }

    const void *debug_data;
    size_t debug_len;
    int err = mbpf_package_get_section(data, len, MBPF_SEC_DEBUG,
                                        &debug_data, &debug_len);
    if (err != MBPF_OK) {
        return err;
    }

    return mbpf_debug_info_parse(debug_data, debug_len, out_debug);
}
