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
    char name[32];
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
} mbpf_map_def_t;

/* Helper version entry */
typedef struct {
    char name[32];
    uint32_t version;  /* major<<16 | minor */
} mbpf_helper_version_t;

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
    mbpf_helper_version_t *helper_versions;
    uint32_t helper_version_count;
} mbpf_manifest_t;

/* Package parsing API */
int mbpf_package_parse_header(const void *data, size_t len,
                               mbpf_file_header_t *out_header);

int mbpf_package_parse_section_table(const void *data, size_t len,
                                      mbpf_section_desc_t *out_sections,
                                      uint32_t max_sections,
                                      uint32_t *out_count);

int mbpf_package_get_section(const void *data, size_t len,
                              mbpf_section_type_t type,
                              const void **out_data, size_t *out_len);

int mbpf_package_parse_manifest(const void *manifest_data, size_t len,
                                 mbpf_manifest_t *out_manifest);

void mbpf_manifest_free(mbpf_manifest_t *manifest);

/* CRC32 validation */
uint32_t mbpf_crc32(const void *data, size_t len);
int mbpf_package_validate_crc(const void *data, size_t len);
int mbpf_package_validate_section_crc(const void *data, size_t len,
                                       const mbpf_section_desc_t *section);

/* ============================================================================
 * Debug Section API (MBPF_SEC_DEBUG)
 * ============================================================================
 *
 * The DEBUG section is optional and contains symbol information for
 * debugging and provenance tracking:
 * - Symbol names (entry function, map names, hook names)
 * - Source hash for provenance
 *
 * Section binary layout:
 *   [4 bytes: flags]
 *   [32 bytes: source_hash (SHA-256)]
 *   [4 bytes: entry_symbol_len]
 *   [entry_symbol_len bytes: entry_symbol (null-terminated)]
 *   [4 bytes: hook_name_len]
 *   [hook_name_len bytes: hook_name (null-terminated)]
 *   [4 bytes: map_count]
 *   For each map:
 *     [4 bytes: name_len]
 *     [name_len bytes: name (null-terminated)]
 */

/* Debug section flags */
#define MBPF_DEBUG_FLAG_HAS_SOURCE_HASH  (1 << 0)

/* Maximum symbol name length */
#define MBPF_DEBUG_MAX_SYMBOL_LEN 128

/* Debug info structure */
typedef struct {
    uint32_t flags;
    uint8_t source_hash[32];          /* SHA-256 of source for provenance */
    char entry_symbol[MBPF_DEBUG_MAX_SYMBOL_LEN];
    char hook_name[MBPF_DEBUG_MAX_SYMBOL_LEN];
    char (*map_names)[MBPF_DEBUG_MAX_SYMBOL_LEN];  /* Dynamically allocated */
    uint32_t map_count;
} mbpf_debug_info_t;

/*
 * Parse the DEBUG section from a package.
 *
 * Parameters:
 *   debug_data   - Pointer to DEBUG section data
 *   debug_len    - Length of DEBUG section
 *   out_debug    - Receives parsed debug info
 *
 * Returns:
 *   MBPF_OK on success
 *   MBPF_ERR_INVALID_ARG if arguments are NULL
 *   MBPF_ERR_INVALID_PACKAGE if section format is invalid
 *
 * Caller must call mbpf_debug_info_free() to release allocated memory.
 */
int mbpf_debug_info_parse(const void *debug_data, size_t debug_len,
                          mbpf_debug_info_t *out_debug);

/*
 * Free memory allocated by mbpf_debug_info_parse.
 * Safe to call with zeroed structure.
 */
void mbpf_debug_info_free(mbpf_debug_info_t *debug);

/*
 * Check if a package has a DEBUG section.
 *
 * Parameters:
 *   data         - Package data
 *   len          - Package length
 *   out_has_debug - Receives 1 if has debug section, 0 otherwise
 *
 * Returns:
 *   MBPF_OK on success
 *   Error code on parse failure
 */
int mbpf_package_has_debug(const void *data, size_t len, int *out_has_debug);

/*
 * Get debug info from a package (convenience wrapper).
 *
 * Parameters:
 *   data       - Package data
 *   len        - Package length
 *   out_debug  - Receives parsed debug info
 *
 * Returns:
 *   MBPF_OK on success
 *   MBPF_ERR_MISSING_SECTION if no DEBUG section
 *   Other error codes on parse failure
 */
int mbpf_package_get_debug_info(const void *data, size_t len,
                                 mbpf_debug_info_t *out_debug);

/* Ed25519 signature constants */
#define MBPF_ED25519_PUBLIC_KEY_SIZE 32
#define MBPF_ED25519_SIGNATURE_SIZE  64

/* Signature section layout: 64 bytes Ed25519 signature */
typedef struct __attribute__((packed)) {
    uint8_t signature[64];
} mbpf_signature_section_t;

/* Signature verification options */
typedef struct {
    const uint8_t *public_key;   /* 32-byte Ed25519 public key (NULL = no verification) */
    int allow_unsigned;           /* Allow packages without signature section */
    int production_mode;          /* Enforce signatures (disallows unsigned) */
} mbpf_sig_verify_opts_t;

/*
 * Validate Ed25519 signature on a package.
 *
 * The signature covers all bytes from file start up to (but excluding) the
 * signature section. The signature section must be the last section.
 *
 * Parameters:
 *   data         - Package data
 *   len          - Package length
 *   opts         - Verification options
 *
 * Returns:
 *   MBPF_OK on successful verification
 *   MBPF_ERR_SIGNATURE if signature is invalid
 *   MBPF_ERR_MISSING_SECTION if no signature and production_mode is set
 *   MBPF_ERR_INVALID_ARG if public_key is NULL when signature exists
 */
int mbpf_package_verify_signature(const void *data, size_t len,
                                   const mbpf_sig_verify_opts_t *opts);

/*
 * Check if a package has a signature section.
 *
 * Parameters:
 *   data       - Package data
 *   len        - Package length
 *   out_signed - Receives 1 if signed, 0 otherwise
 *
 * Returns:
 *   MBPF_OK on success
 *   Error code on parse failure
 */
int mbpf_package_is_signed(const void *data, size_t len, int *out_signed);

/*
 * Get the signature section from a package.
 *
 * Parameters:
 *   data         - Package data
 *   len          - Package length
 *   out_sig      - Receives pointer to 64-byte signature
 *   out_data_len - Receives length of data covered by signature
 *
 * Returns:
 *   MBPF_OK on success
 *   MBPF_ERR_MISSING_SECTION if no signature section
 */
int mbpf_package_get_signature(const void *data, size_t len,
                                const uint8_t **out_sig,
                                size_t *out_data_len);

/* Bytecode loading API */

/* Result structure for bytecode validation */
typedef struct {
    uint16_t bytecode_version;    /* Version from JSBytecodeHeader */
    int is_valid;                 /* Whether JS_IsBytecode returned true */
    int relocation_result;        /* Result of JS_RelocateBytecode */
} mbpf_bytecode_info_t;

/*
 * Validate and load bytecode from a writable buffer.
 *
 * The bytecode must be in a writable buffer because JS_RelocateBytecode
 * modifies it in place. The caller must copy the bytecode section from
 * the package before calling this function.
 *
 * Parameters:
 *   ctx            - MQuickJS context (must be initialized)
 *   bytecode       - Writable buffer containing bytecode
 *   bytecode_len   - Length of bytecode buffer
 *   out_info       - Optional: receives bytecode info/diagnostics
 *   out_main_func  - Receives the main function JSValue if successful
 *
 * Returns:
 *   MBPF_OK on success
 *   MBPF_ERR_INVALID_BYTECODE if bytecode fails validation
 *   MBPF_ERR_UNSUPPORTED_VER if bytecode version mismatches
 */
struct JSContext;
int mbpf_bytecode_load(struct JSContext *ctx,
                       uint8_t *bytecode, size_t bytecode_len,
                       mbpf_bytecode_info_t *out_info,
                       void *out_main_func);

/* Check if bytecode is valid MQuickJS bytecode */
int mbpf_bytecode_check(const uint8_t *bytecode, size_t bytecode_len,
                        mbpf_bytecode_info_t *out_info);

/* Get the expected bytecode version for this runtime */
uint16_t mbpf_bytecode_version(void);

/* ============================================================================
 * Package Assembly API
 * ============================================================================ */

/* Maximum number of sections in a package */
#define MBPF_MAX_SECTIONS 8

/* Section data for assembly */
typedef struct {
    mbpf_section_type_t type;
    const void *data;
    size_t len;
} mbpf_section_input_t;

/* Assembly options */
typedef struct {
    int compute_file_crc;      /* Compute and store file-level CRC32 */
    int compute_section_crcs;  /* Compute and store per-section CRC32s */
    uint32_t flags;            /* Header flags (MBPF_FLAG_SIGNED, MBPF_FLAG_DEBUG) */
} mbpf_assemble_opts_t;

/*
 * Calculate the size of an assembled package.
 *
 * Parameters:
 *   sections       - Array of section inputs
 *   section_count  - Number of sections
 *
 * Returns:
 *   Total size in bytes, or 0 on error
 */
size_t mbpf_package_size(const mbpf_section_input_t *sections,
                          uint32_t section_count);

/*
 * Assemble a .mbpf package from sections.
 *
 * Sections are written in the order provided. The MANIFEST section should
 * typically be first, followed by BYTECODE. If a SIG section is included,
 * it must be last.
 *
 * Parameters:
 *   sections       - Array of section inputs
 *   section_count  - Number of sections
 *   opts           - Assembly options (may be NULL for defaults)
 *   out_data       - Buffer to receive package data
 *   out_len        - On input, buffer size; on output, bytes written
 *
 * Returns:
 *   MBPF_OK on success
 *   MBPF_ERR_INVALID_ARG if sections is NULL or section_count is 0
 *   MBPF_ERR_NO_MEM if buffer is too small
 */
int mbpf_package_assemble(const mbpf_section_input_t *sections,
                           uint32_t section_count,
                           const mbpf_assemble_opts_t *opts,
                           uint8_t *out_data, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* MBPF_PACKAGE_H */
