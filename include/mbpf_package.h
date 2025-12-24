/*
 * microBPF Package Format
 *
 * Defines the .mbpf binary package format for distributing
 * precompiled programs with metadata and signatures.
 */

#ifndef MBPF_PACKAGE_H
#define MBPF_PACKAGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic number: "MBPF" in little-endian */
#define MBPF_MAGIC 0x4D425046

/* Current format version */
#define MBPF_FORMAT_VERSION 1

/* File header flags */
#define MBPF_FLAG_SIGNED (1 << 0)
#define MBPF_FLAG_DEBUG  (1 << 1)

/* Section types */
typedef enum {
    MBPF_SEC_MANIFEST  = 1,  /* Metadata (CBOR or JSON) */
    MBPF_SEC_BYTECODE  = 2,  /* MQuickJS bytecode */
    MBPF_SEC_MAPS      = 3,  /* Map definitions (optional) */
    MBPF_SEC_DEBUG     = 4,  /* Debug symbols (optional) */
    MBPF_SEC_SIG       = 5,  /* Ed25519 signature */
} mbpf_section_type_t;

/* File header (20 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t magic;           /* MBPF_MAGIC */
    uint16_t format_version;
    uint16_t header_size;     /* Including section table */
    uint32_t flags;
    uint32_t section_count;
    uint32_t file_crc32;      /* Optional, 0 if unused */
} mbpf_file_header_t;

/* Section descriptor (16 bytes) */
typedef struct __attribute__((packed)) {
    uint32_t type;
    uint32_t offset;
    uint32_t length;
    uint32_t crc32;
} mbpf_section_desc_t;

/* Map definition in manifest */
typedef struct {
    const char *name;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
} mbpf_map_def_t;

/* Budget definition */
typedef struct {
    uint32_t max_steps;
    uint32_t max_helpers;
    uint32_t max_wall_time_us;  /* Optional, 0 if unused */
} mbpf_budgets_t;

/* Target definition */
typedef struct {
    uint8_t word_size;      /* 32 or 64 */
    uint8_t endianness;     /* 0 = little, 1 = big */
} mbpf_target_t;

/* Parsed manifest */
typedef struct {
    char program_name[64];
    char program_version[32];
    uint32_t hook_type;
    uint32_t hook_ctx_abi_version;
    char entry_symbol[64];
    uint32_t mquickjs_bytecode_version;
    mbpf_target_t target;
    uint32_t mbpf_api_version;
    uint32_t heap_size;
    mbpf_budgets_t budgets;
    uint32_t capabilities;
    mbpf_map_def_t *maps;
    uint32_t map_count;
} mbpf_manifest_t;

/* Package parsing API */
int mbpf_package_parse_header(const void *data, size_t len,
                               mbpf_file_header_t *out_header);

int mbpf_package_get_section(const void *data, size_t len,
                              mbpf_section_type_t type,
                              const void **out_data, size_t *out_len);

int mbpf_package_parse_manifest(const void *manifest_data, size_t len,
                                 mbpf_manifest_t *out_manifest);

void mbpf_manifest_free(mbpf_manifest_t *manifest);

/* CRC32 validation */
uint32_t mbpf_crc32(const void *data, size_t len);
int mbpf_package_validate_crc(const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MBPF_PACKAGE_H */
