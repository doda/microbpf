/*
 * Ed25519 signature verification (verify-only, from TweetNaCl)
 *
 * This is a minimal Ed25519 verification implementation derived from
 * TweetNaCl (https://tweetnacl.cr.yp.to/). The original code is in the
 * public domain and was written by Daniel J. Bernstein, et al.
 *
 * This subset is verify-only to minimize code size for embedded use.
 */

#ifndef MBPF_ED25519_H
#define MBPF_ED25519_H

#include <stddef.h>
#include <stdint.h>

/* Ed25519 constants */
#define ED25519_PUBLIC_KEY_SIZE 32
#define ED25519_SIGNATURE_SIZE  64

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

#endif /* MBPF_ED25519_H */
