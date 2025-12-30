/*
 * microBPF Manifest Generation
 *
 * Provides APIs for generating CBOR and JSON encoded manifest sections
 * for .mbpf packages.
 */

#ifndef MBPF_MANIFEST_GEN_H
#define MBPF_MANIFEST_GEN_H

#include <stddef.h>
#include <stdint.h>
#include "mbpf.h"
#include "mbpf_package.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generate a CBOR-encoded manifest section.
 *
 * Parameters:
 *   manifest   - Parsed manifest structure with all required fields
 *   out_data   - Buffer to receive CBOR-encoded data
 *   out_len    - On input, size of buffer; on output, bytes written
 *
 * Returns:
 *   MBPF_OK on success
 *   MBPF_ERR_INVALID_ARG if manifest is NULL or missing required fields
 *   MBPF_ERR_NO_MEM if buffer is too small (out_len set to required size)
 */
int mbpf_manifest_generate_cbor(const mbpf_manifest_t *manifest,
                                 uint8_t *out_data, size_t *out_len);

/*
 * Generate a JSON-encoded manifest section.
 *
 * Parameters:
 *   manifest   - Parsed manifest structure with all required fields
 *   out_data   - Buffer to receive JSON string (null-terminated)
 *   out_len    - On input, size of buffer (including null terminator);
 *                on output, bytes written (excluding null)
 *
 * Returns:
 *   MBPF_OK on success
 *   MBPF_ERR_INVALID_ARG if manifest is NULL or missing required fields
 *   MBPF_ERR_NO_MEM if buffer is too small (out_len set to required size)
 */
int mbpf_manifest_generate_json(const mbpf_manifest_t *manifest,
                                 char *out_data, size_t *out_len);

/*
 * Calculate the CBOR-encoded size of a manifest without generating it.
 *
 * Parameters:
 *   manifest   - Parsed manifest structure
 *
 * Returns:
 *   Required buffer size in bytes, or 0 on error
 */
size_t mbpf_manifest_cbor_size(const mbpf_manifest_t *manifest);

/*
 * Calculate the JSON-encoded size of a manifest without generating it.
 *
 * Parameters:
 *   manifest   - Parsed manifest structure
 *
 * Returns:
 *   Required buffer size in bytes (including null terminator), or 0 on error
 */
size_t mbpf_manifest_json_size(const mbpf_manifest_t *manifest);

/*
 * Validate a manifest has all required fields.
 *
 * Checks for:
 *   - Non-empty program_name
 *   - Non-empty program_version
 *   - Valid hook_type (1-6)
 *   - Valid target word_size (32 or 64)
 *   - heap_size >= MBPF_MIN_HEAP_SIZE
 *   - max_steps > 0
 *   - max_helpers > 0
 *
 * Parameters:
 *   manifest   - Manifest to validate
 *
 * Returns:
 *   MBPF_OK if manifest is valid
 *   MBPF_ERR_INVALID_ARG if manifest is NULL or has invalid/missing fields
 */
int mbpf_manifest_validate(const mbpf_manifest_t *manifest);

/*
 * Initialize a manifest structure with default values.
 *
 * Sets reasonable defaults:
 *   - entry_symbol = "mbpf_prog"
 *   - hook_ctx_abi_version = 1
 *   - target = current platform (64-bit, little-endian on most systems)
 *   - mbpf_api_version = MBPF_API_VERSION
 *   - mquickjs_bytecode_version = mbpf_bytecode_version()
 *   - heap_size = MBPF_MIN_HEAP_SIZE
 *   - budgets = {10000, 100, 0}
 *   - capabilities = 0
 *
 * Parameters:
 *   manifest   - Manifest to initialize
 */
void mbpf_manifest_init_defaults(mbpf_manifest_t *manifest);

#ifdef __cplusplus
}
#endif

#endif /* MBPF_MANIFEST_GEN_H */
