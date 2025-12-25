/*
 * Ed25519 signature implementation (from TweetNaCl)
 *
 * This is an Ed25519 implementation derived from TweetNaCl
 * (https://tweetnacl.cr.yp.to/). The original code is in the
 * public domain and was written by Daniel J. Bernstein, et al.
 *
 * Includes both signing and verification for toolchain use.
 */

#ifndef MBPF_ED25519_H
#define MBPF_ED25519_H

#include <stddef.h>
#include <stdint.h>

/* Ed25519 constants */
#define ED25519_PUBLIC_KEY_SIZE  32
#define ED25519_SECRET_KEY_SIZE  64  /* Expanded secret key (includes public key) */
#define ED25519_SEED_SIZE        32  /* Random seed for key generation */
#define ED25519_SIGNATURE_SIZE   64

/*
 * Verify an Ed25519 signature.
 *
 * Returns:
 *   0 on successful verification
 *  -1 on verification failure (invalid signature)
 */
int ed25519_verify(const uint8_t *signature,     /* 64 bytes */
                   const uint8_t *message,
                   size_t message_len,
                   const uint8_t *public_key);   /* 32 bytes */

/*
 * Generate an Ed25519 keypair from a 32-byte seed.
 *
 * The seed should be cryptographically random. The secret key output
 * is 64 bytes (seed || public key).
 *
 * Returns: 0 on success (always succeeds for valid pointers)
 */
int ed25519_keypair_from_seed(uint8_t *public_key,    /* 32 bytes out */
                               uint8_t *secret_key,    /* 64 bytes out */
                               const uint8_t *seed);   /* 32 bytes in */

/*
 * Sign a message with Ed25519.
 *
 * The secret_key is the 64-byte expanded key from ed25519_keypair_from_seed.
 *
 * Returns: 0 on success (always succeeds for valid pointers)
 */
int ed25519_sign(uint8_t *signature,           /* 64 bytes out */
                 const uint8_t *message,
                 size_t message_len,
                 const uint8_t *secret_key);    /* 64 bytes in */

#endif /* MBPF_ED25519_H */
