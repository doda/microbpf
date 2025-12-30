/*
 * microBPF Manifest Generation Implementation
 *
 * Provides CBOR and JSON manifest encoding for .mbpf packages.
 */

#include "mbpf_manifest_gen.h"
#include "mbpf.h"
#include "mbpf_package.h"
#include <string.h>
#include <stdio.h>

/* CBOR major types */
#define CBOR_UINT      0
#define CBOR_NEGINT    1
#define CBOR_BYTES     2
#define CBOR_TEXT      3
#define CBOR_ARRAY     4
#define CBOR_MAP       5
#define CBOR_TAG       6
#define CBOR_SIMPLE    7

/* CBOR writer state */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
    int dry_run;  /* If set, just count bytes without writing */
} cbor_writer_t;

static void cbor_writer_init(cbor_writer_t *w, uint8_t *buf, size_t cap) {
    w->data = buf;
    w->len = 0;
    w->cap = cap;
    w->dry_run = (buf == NULL);
}

static int cbor_write_byte(cbor_writer_t *w, uint8_t b) {
    if (!w->dry_run) {
        if (w->len >= w->cap) return -1;
        w->data[w->len] = b;
    }
    w->len++;
    return 0;
}

static int cbor_write_bytes(cbor_writer_t *w, const uint8_t *data, size_t len) {
    if (!w->dry_run) {
        if (w->len + len > w->cap) return -1;
        memcpy(w->data + w->len, data, len);
    }
    w->len += len;
    return 0;
}

static int cbor_write_uint_header(cbor_writer_t *w, uint8_t major, uint64_t val) {
    uint8_t initial = major << 5;
    if (val < 24) {
        return cbor_write_byte(w, initial | (uint8_t)val);
    } else if (val <= 0xFF) {
        if (cbor_write_byte(w, initial | 24) != 0) return -1;
        return cbor_write_byte(w, (uint8_t)val);
    } else if (val <= 0xFFFF) {
        if (cbor_write_byte(w, initial | 25) != 0) return -1;
        if (cbor_write_byte(w, (val >> 8) & 0xFF) != 0) return -1;
        return cbor_write_byte(w, val & 0xFF);
    } else if (val <= 0xFFFFFFFF) {
        if (cbor_write_byte(w, initial | 26) != 0) return -1;
        if (cbor_write_byte(w, (val >> 24) & 0xFF) != 0) return -1;
        if (cbor_write_byte(w, (val >> 16) & 0xFF) != 0) return -1;
        if (cbor_write_byte(w, (val >> 8) & 0xFF) != 0) return -1;
        return cbor_write_byte(w, val & 0xFF);
    } else {
        if (cbor_write_byte(w, initial | 27) != 0) return -1;
        for (int i = 7; i >= 0; i--) {
            if (cbor_write_byte(w, (val >> (i * 8)) & 0xFF) != 0) return -1;
        }
        return 0;
    }
}

static int cbor_write_unsigned(cbor_writer_t *w, uint64_t val) {
    return cbor_write_uint_header(w, CBOR_UINT, val);
}

static int cbor_write_text_string(cbor_writer_t *w, const char *str) {
    size_t len = strlen(str);
    if (cbor_write_uint_header(w, CBOR_TEXT, len) != 0) return -1;
    return cbor_write_bytes(w, (const uint8_t *)str, len);
}

static int cbor_write_map_header(cbor_writer_t *w, uint64_t count) {
    return cbor_write_uint_header(w, CBOR_MAP, count);
}

static int cbor_write_array_header(cbor_writer_t *w, uint64_t count) {
    return cbor_write_uint_header(w, CBOR_ARRAY, count);
}

/* Helper to get capability name from flag */
static const char *capability_name(uint32_t cap) {
    switch (cap) {
        case MBPF_CAP_LOG:         return "CAP_LOG";
        case MBPF_CAP_MAP_READ:    return "CAP_MAP_READ";
        case MBPF_CAP_MAP_WRITE:   return "CAP_MAP_WRITE";
        case MBPF_CAP_MAP_ITERATE: return "CAP_MAP_ITERATE";
        case MBPF_CAP_EMIT:        return "CAP_EMIT";
        case MBPF_CAP_TIME:        return "CAP_TIME";
        case MBPF_CAP_STATS:       return "CAP_STATS";
        default:                   return NULL;
    }
}

/* Count capabilities we can encode by name */
static uint32_t count_capabilities(uint32_t caps) {
    uint32_t count = 0;
    for (uint32_t cap = 1; cap <= MBPF_CAP_STATS; cap <<= 1) {
        if ((caps & cap) && capability_name(cap) != NULL) {
            count++;
        }
    }
    return count;
}

/* Encode manifest to CBOR */
static int encode_manifest_cbor(const mbpf_manifest_t *m, cbor_writer_t *w) {
    /* Count map entries:
     * Required (10): program_name, program_version, hook_type, hook_ctx_abi_version,
     *                mquickjs_bytecode_version, target, mbpf_api_version, heap_size,
     *                budgets, capabilities
     * Optional: entry_symbol (if not default), maps, helper_versions
     */
    uint32_t map_count = 10;

    int has_custom_entry = (m->entry_symbol[0] != '\0' &&
                            strcmp(m->entry_symbol, "mbpf_prog") != 0);
    if (has_custom_entry) map_count++;
    if (m->map_count > 0) map_count++;
    if (m->helper_version_count > 0) map_count++;

    if (cbor_write_map_header(w, map_count) != 0) return -1;

    /* program_name */
    if (cbor_write_text_string(w, "program_name") != 0) return -1;
    if (cbor_write_text_string(w, m->program_name) != 0) return -1;

    /* program_version */
    if (cbor_write_text_string(w, "program_version") != 0) return -1;
    if (cbor_write_text_string(w, m->program_version) != 0) return -1;

    /* hook_type */
    if (cbor_write_text_string(w, "hook_type") != 0) return -1;
    if (cbor_write_unsigned(w, m->hook_type) != 0) return -1;

    /* hook_ctx_abi_version */
    if (cbor_write_text_string(w, "hook_ctx_abi_version") != 0) return -1;
    if (cbor_write_unsigned(w, m->hook_ctx_abi_version) != 0) return -1;

    /* entry_symbol (optional if not default) */
    if (has_custom_entry) {
        if (cbor_write_text_string(w, "entry_symbol") != 0) return -1;
        if (cbor_write_text_string(w, m->entry_symbol) != 0) return -1;
    }

    /* mquickjs_bytecode_version */
    if (cbor_write_text_string(w, "mquickjs_bytecode_version") != 0) return -1;
    if (cbor_write_unsigned(w, m->mquickjs_bytecode_version) != 0) return -1;

    /* target */
    if (cbor_write_text_string(w, "target") != 0) return -1;
    if (cbor_write_map_header(w, 2) != 0) return -1;
    if (cbor_write_text_string(w, "word_size") != 0) return -1;
    if (cbor_write_unsigned(w, m->target.word_size) != 0) return -1;
    if (cbor_write_text_string(w, "endianness") != 0) return -1;
    if (m->target.endianness == 0) {
        if (cbor_write_text_string(w, "little") != 0) return -1;
    } else {
        if (cbor_write_text_string(w, "big") != 0) return -1;
    }

    /* mbpf_api_version */
    if (cbor_write_text_string(w, "mbpf_api_version") != 0) return -1;
    if (cbor_write_unsigned(w, m->mbpf_api_version) != 0) return -1;

    /* heap_size */
    if (cbor_write_text_string(w, "heap_size") != 0) return -1;
    if (cbor_write_unsigned(w, m->heap_size) != 0) return -1;

    /* budgets */
    if (cbor_write_text_string(w, "budgets") != 0) return -1;
    uint32_t budget_count = 2;
    if (m->budgets.max_wall_time_us > 0) budget_count++;
    if (cbor_write_map_header(w, budget_count) != 0) return -1;
    if (cbor_write_text_string(w, "max_steps") != 0) return -1;
    if (cbor_write_unsigned(w, m->budgets.max_steps) != 0) return -1;
    if (cbor_write_text_string(w, "max_helpers") != 0) return -1;
    if (cbor_write_unsigned(w, m->budgets.max_helpers) != 0) return -1;
    if (m->budgets.max_wall_time_us > 0) {
        if (cbor_write_text_string(w, "max_wall_time_us") != 0) return -1;
        if (cbor_write_unsigned(w, m->budgets.max_wall_time_us) != 0) return -1;
    }

    /* capabilities */
    if (cbor_write_text_string(w, "capabilities") != 0) return -1;
    uint32_t cap_count = count_capabilities(m->capabilities);
    if (cbor_write_array_header(w, cap_count) != 0) return -1;
    for (uint32_t cap = 1; cap <= MBPF_CAP_STATS; cap <<= 1) {
        if (m->capabilities & cap) {
            const char *name = capability_name(cap);
            if (name) {
                if (cbor_write_text_string(w, name) != 0) return -1;
            }
        }
    }

    /* maps (optional) */
    if (m->map_count > 0) {
        if (cbor_write_text_string(w, "maps") != 0) return -1;
        if (cbor_write_array_header(w, m->map_count) != 0) return -1;
        for (uint32_t i = 0; i < m->map_count; i++) {
            const mbpf_map_def_t *map = &m->maps[i];
            uint32_t field_count = 5;
            if (map->flags != 0) field_count++;
            if (cbor_write_map_header(w, field_count) != 0) return -1;
            if (cbor_write_text_string(w, "name") != 0) return -1;
            if (cbor_write_text_string(w, map->name) != 0) return -1;
            if (cbor_write_text_string(w, "type") != 0) return -1;
            if (cbor_write_unsigned(w, map->type) != 0) return -1;
            if (cbor_write_text_string(w, "key_size") != 0) return -1;
            if (cbor_write_unsigned(w, map->key_size) != 0) return -1;
            if (cbor_write_text_string(w, "value_size") != 0) return -1;
            if (cbor_write_unsigned(w, map->value_size) != 0) return -1;
            if (cbor_write_text_string(w, "max_entries") != 0) return -1;
            if (cbor_write_unsigned(w, map->max_entries) != 0) return -1;
            if (map->flags != 0) {
                if (cbor_write_text_string(w, "flags") != 0) return -1;
                if (cbor_write_unsigned(w, map->flags) != 0) return -1;
            }
        }
    }

    /* helper_versions (optional) */
    if (m->helper_version_count > 0) {
        if (cbor_write_text_string(w, "helper_versions") != 0) return -1;
        if (cbor_write_map_header(w, m->helper_version_count) != 0) return -1;
        for (uint32_t i = 0; i < m->helper_version_count; i++) {
            if (cbor_write_text_string(w, m->helper_versions[i].name) != 0) return -1;
            if (cbor_write_unsigned(w, m->helper_versions[i].version) != 0) return -1;
        }
    }

    return 0;
}

int mbpf_manifest_validate(const mbpf_manifest_t *manifest) {
    if (!manifest) return MBPF_ERR_INVALID_ARG;

    /* Required string fields must be non-empty */
    if (manifest->program_name[0] == '\0') return MBPF_ERR_INVALID_ARG;
    if (manifest->program_version[0] == '\0') return MBPF_ERR_INVALID_ARG;

    /* Hook type must be valid */
    if (manifest->hook_type < MBPF_HOOK_TRACEPOINT ||
        manifest->hook_type > MBPF_HOOK_CUSTOM) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Target word size must be 32 or 64 */
    if (manifest->target.word_size != 32 && manifest->target.word_size != 64) {
        return MBPF_ERR_INVALID_ARG;
    }

    /* Heap size must meet minimum */
    if (manifest->heap_size < MBPF_MIN_HEAP_SIZE) {
        return MBPF_ERR_HEAP_TOO_SMALL;
    }

    /* Budgets must be positive */
    if (manifest->budgets.max_steps == 0) return MBPF_ERR_INVALID_ARG;
    if (manifest->budgets.max_helpers == 0) return MBPF_ERR_INVALID_ARG;

    return MBPF_OK;
}

void mbpf_manifest_init_defaults(mbpf_manifest_t *manifest) {
    if (!manifest) return;

    memset(manifest, 0, sizeof(*manifest));

    strcpy(manifest->entry_symbol, "mbpf_prog");
    manifest->hook_ctx_abi_version = 1;

    /* Default to current platform */
    manifest->target.word_size = sizeof(void *) * 8;
    manifest->target.endianness = 0;  /* little */

    manifest->mbpf_api_version = MBPF_API_VERSION;
    manifest->mquickjs_bytecode_version = mbpf_bytecode_version();
    manifest->heap_size = MBPF_MIN_HEAP_SIZE;

    manifest->budgets.max_steps = 10000;
    manifest->budgets.max_helpers = 100;
    manifest->budgets.max_wall_time_us = 0;

    manifest->capabilities = 0;
}

size_t mbpf_manifest_cbor_size(const mbpf_manifest_t *manifest) {
    if (!manifest) return 0;
    if (mbpf_manifest_validate(manifest) != MBPF_OK) return 0;

    cbor_writer_t w;
    cbor_writer_init(&w, NULL, 0);  /* dry run */

    if (encode_manifest_cbor(manifest, &w) != 0) return 0;

    return w.len;
}

int mbpf_manifest_generate_cbor(const mbpf_manifest_t *manifest,
                                 uint8_t *out_data, size_t *out_len) {
    if (!manifest || !out_len) return MBPF_ERR_INVALID_ARG;

    int err = mbpf_manifest_validate(manifest);
    if (err != MBPF_OK) return err;

    size_t required = mbpf_manifest_cbor_size(manifest);
    if (required == 0) return MBPF_ERR_INVALID_ARG;

    if (!out_data || *out_len < required) {
        *out_len = required;
        return MBPF_ERR_NO_MEM;
    }

    cbor_writer_t w;
    cbor_writer_init(&w, out_data, *out_len);

    if (encode_manifest_cbor(manifest, &w) != 0) {
        return MBPF_ERR_NO_MEM;
    }

    *out_len = w.len;
    return MBPF_OK;
}

/* JSON encoding helpers */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
    int dry_run;
} json_writer_t;

static void json_writer_init(json_writer_t *w, char *buf, size_t cap) {
    w->data = buf;
    w->len = 0;
    w->cap = cap;
    w->dry_run = (buf == NULL);
}

static int json_write_str(json_writer_t *w, const char *s) {
    size_t slen = strlen(s);
    if (!w->dry_run) {
        if (w->len + slen >= w->cap) return -1;
        memcpy(w->data + w->len, s, slen);
    }
    w->len += slen;
    return 0;
}

static int json_write_char(json_writer_t *w, char c) {
    if (!w->dry_run) {
        if (w->len + 1 >= w->cap) return -1;
        w->data[w->len] = c;
    }
    w->len++;
    return 0;
}

static int json_write_quoted(json_writer_t *w, const char *s) {
    if (json_write_char(w, '"') != 0) return -1;
    /* Escape special characters */
    for (const char *p = s; *p; p++) {
        char c = *p;
        if (c == '"' || c == '\\') {
            if (json_write_char(w, '\\') != 0) return -1;
        }
        if (json_write_char(w, c) != 0) return -1;
    }
    if (json_write_char(w, '"') != 0) return -1;
    return 0;
}

static int json_write_uint(json_writer_t *w, uint64_t val) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)val);
    return json_write_str(w, buf);
}

/* Encode manifest to JSON */
static int encode_manifest_json(const mbpf_manifest_t *m, json_writer_t *w) {
    if (json_write_char(w, '{') != 0) return -1;

    /* program_name */
    if (json_write_quoted(w, "program_name") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_quoted(w, m->program_name) != 0) return -1;

    /* program_version */
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "program_version") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_quoted(w, m->program_version) != 0) return -1;

    /* hook_type */
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "hook_type") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_uint(w, m->hook_type) != 0) return -1;

    /* hook_ctx_abi_version */
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "hook_ctx_abi_version") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_uint(w, m->hook_ctx_abi_version) != 0) return -1;

    /* entry_symbol (if not default) */
    if (m->entry_symbol[0] != '\0' && strcmp(m->entry_symbol, "mbpf_prog") != 0) {
        if (json_write_str(w, ",") != 0) return -1;
        if (json_write_quoted(w, "entry_symbol") != 0) return -1;
        if (json_write_char(w, ':') != 0) return -1;
        if (json_write_quoted(w, m->entry_symbol) != 0) return -1;
    }

    /* mquickjs_bytecode_version */
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "mquickjs_bytecode_version") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_uint(w, m->mquickjs_bytecode_version) != 0) return -1;

    /* target */
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "target") != 0) return -1;
    if (json_write_str(w, ":{") != 0) return -1;
    if (json_write_quoted(w, "word_size") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_uint(w, m->target.word_size) != 0) return -1;
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "endianness") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (m->target.endianness == 0) {
        if (json_write_quoted(w, "little") != 0) return -1;
    } else {
        if (json_write_quoted(w, "big") != 0) return -1;
    }
    if (json_write_char(w, '}') != 0) return -1;

    /* mbpf_api_version */
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "mbpf_api_version") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_uint(w, m->mbpf_api_version) != 0) return -1;

    /* heap_size */
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "heap_size") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_uint(w, m->heap_size) != 0) return -1;

    /* budgets */
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "budgets") != 0) return -1;
    if (json_write_str(w, ":{") != 0) return -1;
    if (json_write_quoted(w, "max_steps") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_uint(w, m->budgets.max_steps) != 0) return -1;
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "max_helpers") != 0) return -1;
    if (json_write_char(w, ':') != 0) return -1;
    if (json_write_uint(w, m->budgets.max_helpers) != 0) return -1;
    if (m->budgets.max_wall_time_us > 0) {
        if (json_write_str(w, ",") != 0) return -1;
        if (json_write_quoted(w, "max_wall_time_us") != 0) return -1;
        if (json_write_char(w, ':') != 0) return -1;
        if (json_write_uint(w, m->budgets.max_wall_time_us) != 0) return -1;
    }
    if (json_write_char(w, '}') != 0) return -1;

    /* capabilities */
    if (json_write_str(w, ",") != 0) return -1;
    if (json_write_quoted(w, "capabilities") != 0) return -1;
    if (json_write_str(w, ":[") != 0) return -1;
    int first = 1;
    for (uint32_t cap = 1; cap <= MBPF_CAP_STATS; cap <<= 1) {
        if (m->capabilities & cap) {
            const char *name = capability_name(cap);
            if (name) {
                if (!first && json_write_str(w, ",") != 0) return -1;
                if (json_write_quoted(w, name) != 0) return -1;
                first = 0;
            }
        }
    }
    if (json_write_char(w, ']') != 0) return -1;

    /* maps (optional) */
    if (m->map_count > 0) {
        if (json_write_str(w, ",") != 0) return -1;
        if (json_write_quoted(w, "maps") != 0) return -1;
        if (json_write_str(w, ":[") != 0) return -1;
        for (uint32_t i = 0; i < m->map_count; i++) {
            const mbpf_map_def_t *map = &m->maps[i];
            if (i > 0 && json_write_str(w, ",") != 0) return -1;
            if (json_write_char(w, '{') != 0) return -1;
            if (json_write_quoted(w, "name") != 0) return -1;
            if (json_write_char(w, ':') != 0) return -1;
            if (json_write_quoted(w, map->name) != 0) return -1;
            if (json_write_str(w, ",") != 0) return -1;
            if (json_write_quoted(w, "type") != 0) return -1;
            if (json_write_char(w, ':') != 0) return -1;
            if (json_write_uint(w, map->type) != 0) return -1;
            if (json_write_str(w, ",") != 0) return -1;
            if (json_write_quoted(w, "key_size") != 0) return -1;
            if (json_write_char(w, ':') != 0) return -1;
            if (json_write_uint(w, map->key_size) != 0) return -1;
            if (json_write_str(w, ",") != 0) return -1;
            if (json_write_quoted(w, "value_size") != 0) return -1;
            if (json_write_char(w, ':') != 0) return -1;
            if (json_write_uint(w, map->value_size) != 0) return -1;
            if (json_write_str(w, ",") != 0) return -1;
            if (json_write_quoted(w, "max_entries") != 0) return -1;
            if (json_write_char(w, ':') != 0) return -1;
            if (json_write_uint(w, map->max_entries) != 0) return -1;
            if (map->flags != 0) {
                if (json_write_str(w, ",") != 0) return -1;
                if (json_write_quoted(w, "flags") != 0) return -1;
                if (json_write_char(w, ':') != 0) return -1;
                if (json_write_uint(w, map->flags) != 0) return -1;
            }
            if (json_write_char(w, '}') != 0) return -1;
        }
        if (json_write_char(w, ']') != 0) return -1;
    }

    /* helper_versions (optional) */
    if (m->helper_version_count > 0) {
        if (json_write_str(w, ",") != 0) return -1;
        if (json_write_quoted(w, "helper_versions") != 0) return -1;
        if (json_write_str(w, ":{") != 0) return -1;
        for (uint32_t i = 0; i < m->helper_version_count; i++) {
            if (i > 0 && json_write_str(w, ",") != 0) return -1;
            if (json_write_quoted(w, m->helper_versions[i].name) != 0) return -1;
            if (json_write_char(w, ':') != 0) return -1;
            if (json_write_uint(w, m->helper_versions[i].version) != 0) return -1;
        }
        if (json_write_char(w, '}') != 0) return -1;
    }

    if (json_write_char(w, '}') != 0) return -1;

    return 0;
}

size_t mbpf_manifest_json_size(const mbpf_manifest_t *manifest) {
    if (!manifest) return 0;
    if (mbpf_manifest_validate(manifest) != MBPF_OK) return 0;

    json_writer_t w;
    json_writer_init(&w, NULL, 0);  /* dry run */

    if (encode_manifest_json(manifest, &w) != 0) return 0;

    if (w.len == SIZE_MAX) return 0;
    return w.len + 1;  /* include null terminator */
}

int mbpf_manifest_generate_json(const mbpf_manifest_t *manifest,
                                 char *out_data, size_t *out_len) {
    if (!manifest || !out_len) return MBPF_ERR_INVALID_ARG;

    int err = mbpf_manifest_validate(manifest);
    if (err != MBPF_OK) return err;

    size_t required = mbpf_manifest_json_size(manifest);
    if (required == 0) return MBPF_ERR_INVALID_ARG;

    /* required includes null terminator */
    if (!out_data || *out_len < required) {
        *out_len = required;
        return MBPF_ERR_NO_MEM;
    }

    json_writer_t w;
    json_writer_init(&w, out_data, *out_len);

    if (encode_manifest_json(manifest, &w) != 0) {
        return MBPF_ERR_NO_MEM;
    }

    out_data[w.len] = '\0';
    *out_len = w.len;
    return MBPF_OK;
}
