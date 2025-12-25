/*
 * mbpf_sign - Sign .mbpf packages with Ed25519
 *
 * Usage:
 *   mbpf_sign keygen -o keypair.key           Generate new keypair
 *   mbpf_sign pubkey -k keypair.key -o pub.key  Extract public key
 *   mbpf_sign sign -k keypair.key -i pkg.mbpf -o pkg_signed.mbpf
 *   mbpf_sign verify -k pub.key -i pkg.mbpf    Verify signature
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "ed25519.h"
#include "mbpf.h"
#include "mbpf_package.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <command> [options]\n\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  keygen   Generate Ed25519 keypair\n");
    fprintf(stderr, "  pubkey   Extract public key from keypair\n");
    fprintf(stderr, "  sign     Sign a .mbpf package\n");
    fprintf(stderr, "  verify   Verify package signature\n");
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -k FILE  Key file (keypair for sign, public for verify)\n");
    fprintf(stderr, "  -i FILE  Input .mbpf package\n");
    fprintf(stderr, "  -o FILE  Output file\n");
    fprintf(stderr, "  -h       Show help\n");
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

static int get_random_bytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        perror("/dev/urandom");
        return -1;
    }

    size_t nread = fread(buf, 1, len, f);
    fclose(f);

    if (nread != len) {
        fprintf(stderr, "Failed to read %zu random bytes\n", len);
        return -1;
    }

    return 0;
}

static int cmd_keygen(const char *output_file) {
    if (!output_file) {
        fprintf(stderr, "Error: output file required (-o)\n");
        return 1;
    }

    uint8_t seed[ED25519_SEED_SIZE];
    uint8_t public_key[ED25519_PUBLIC_KEY_SIZE];
    uint8_t secret_key[ED25519_SECRET_KEY_SIZE];

    if (get_random_bytes(seed, sizeof(seed)) != 0) {
        return 1;
    }

    ed25519_keypair_from_seed(public_key, secret_key, seed);

    if (write_file(output_file, secret_key, sizeof(secret_key)) != 0) {
        return 1;
    }

    printf("Generated keypair: %s (64 bytes)\n", output_file);
    printf("Public key: ");
    for (int i = 0; i < ED25519_PUBLIC_KEY_SIZE; i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");

    return 0;
}

static int cmd_pubkey(const char *key_file, const char *output_file) {
    if (!key_file) {
        fprintf(stderr, "Error: key file required (-k)\n");
        return 1;
    }
    if (!output_file) {
        fprintf(stderr, "Error: output file required (-o)\n");
        return 1;
    }

    size_t key_len;
    uint8_t *key_data = read_file(key_file, &key_len);
    if (!key_data) {
        return 1;
    }

    if (key_len != ED25519_SECRET_KEY_SIZE) {
        fprintf(stderr, "Error: invalid keypair file (expected %d bytes, got %zu)\n",
                ED25519_SECRET_KEY_SIZE, key_len);
        free(key_data);
        return 1;
    }

    /* Public key is stored in bytes 32-63 of the secret key */
    const uint8_t *public_key = key_data + 32;

    if (write_file(output_file, public_key, ED25519_PUBLIC_KEY_SIZE) != 0) {
        free(key_data);
        return 1;
    }

    printf("Extracted public key: %s (32 bytes)\n", output_file);
    printf("Public key: ");
    for (int i = 0; i < ED25519_PUBLIC_KEY_SIZE; i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");

    free(key_data);
    return 0;
}

static int cmd_sign(const char *key_file, const char *input_file,
                    const char *output_file) {
    if (!key_file) {
        fprintf(stderr, "Error: key file required (-k)\n");
        return 1;
    }
    if (!input_file) {
        fprintf(stderr, "Error: input file required (-i)\n");
        return 1;
    }
    if (!output_file) {
        fprintf(stderr, "Error: output file required (-o)\n");
        return 1;
    }

    /* Read keypair */
    size_t key_len;
    uint8_t *key_data = read_file(key_file, &key_len);
    if (!key_data) {
        return 1;
    }

    if (key_len != ED25519_SECRET_KEY_SIZE) {
        fprintf(stderr, "Error: invalid keypair file (expected %d bytes, got %zu)\n",
                ED25519_SECRET_KEY_SIZE, key_len);
        free(key_data);
        return 1;
    }

    /* Read input package */
    size_t pkg_len;
    uint8_t *pkg_data = read_file(input_file, &pkg_len);
    if (!pkg_data) {
        free(key_data);
        return 1;
    }

    /* Check if already signed */
    int is_signed;
    int err = mbpf_package_is_signed(pkg_data, pkg_len, &is_signed);
    if (err != MBPF_OK) {
        fprintf(stderr, "Error: failed to parse package (code %d)\n", err);
        free(pkg_data);
        free(key_data);
        return 1;
    }

    if (is_signed) {
        fprintf(stderr, "Error: package is already signed\n");
        free(pkg_data);
        free(key_data);
        return 1;
    }

    /* Parse existing package to count sections */
    mbpf_file_header_t header;
    err = mbpf_package_parse_header(pkg_data, pkg_len, &header);
    if (err != MBPF_OK) {
        fprintf(stderr, "Error: failed to parse package header (code %d)\n", err);
        free(pkg_data);
        free(key_data);
        return 1;
    }

    /* Sign the package bytes (everything in the unsigned package) */
    uint8_t signature[ED25519_SIGNATURE_SIZE];
    ed25519_sign(signature, pkg_data, pkg_len, key_data);

    /* Calculate new package size: old package + new section descriptor + signature */
    /* The new header will have section_count + 1 sections */
    uint32_t new_section_count = header.section_count + 1;
    size_t old_header_size = sizeof(mbpf_file_header_t) +
                             header.section_count * sizeof(mbpf_section_desc_t);
    size_t new_header_size = sizeof(mbpf_file_header_t) +
                             new_section_count * sizeof(mbpf_section_desc_t);
    size_t data_size = pkg_len - old_header_size;  /* Size of section data */
    size_t new_pkg_len = new_header_size + data_size + ED25519_SIGNATURE_SIZE;

    /* Allocate new package buffer */
    uint8_t *new_pkg = malloc(new_pkg_len);
    if (!new_pkg) {
        fprintf(stderr, "Error: failed to allocate %zu bytes\n", new_pkg_len);
        free(pkg_data);
        free(key_data);
        return 1;
    }

    /* Write new header */
    mbpf_file_header_t *new_header = (mbpf_file_header_t *)new_pkg;
    new_header->magic = MBPF_MAGIC;
    new_header->format_version = header.format_version;
    new_header->header_size = (uint16_t)new_header_size;
    new_header->flags = header.flags | MBPF_FLAG_SIGNED;
    new_header->section_count = new_section_count;
    new_header->file_crc32 = 0;  /* Can be computed later if needed */

    /* Copy section descriptors, adjusting offsets */
    mbpf_section_desc_t *old_sections = (mbpf_section_desc_t *)(pkg_data + sizeof(mbpf_file_header_t));
    mbpf_section_desc_t *new_sections = (mbpf_section_desc_t *)(new_pkg + sizeof(mbpf_file_header_t));
    size_t offset_adjustment = new_header_size - old_header_size;

    for (uint32_t i = 0; i < header.section_count; i++) {
        new_sections[i].type = old_sections[i].type;
        new_sections[i].offset = old_sections[i].offset + (uint32_t)offset_adjustment;
        new_sections[i].length = old_sections[i].length;
        new_sections[i].crc32 = old_sections[i].crc32;
    }

    /* Add signature section descriptor */
    mbpf_section_desc_t *sig_section = &new_sections[header.section_count];
    sig_section->type = MBPF_SEC_SIG;
    sig_section->offset = (uint32_t)(new_header_size + data_size);
    sig_section->length = ED25519_SIGNATURE_SIZE;
    sig_section->crc32 = 0;

    /* Copy section data */
    memcpy(new_pkg + new_header_size, pkg_data + old_header_size, data_size);

    /* Now re-sign the final package (everything before the signature) */
    size_t data_to_sign = sig_section->offset;
    ed25519_sign(signature, new_pkg, data_to_sign, key_data);

    /* Append signature */
    memcpy(new_pkg + sig_section->offset, signature, ED25519_SIGNATURE_SIZE);

    /* Write output file */
    if (write_file(output_file, new_pkg, new_pkg_len) != 0) {
        free(new_pkg);
        free(pkg_data);
        free(key_data);
        return 1;
    }

    printf("Signed package: %s\n", output_file);
    printf("  Original size: %zu bytes\n", pkg_len);
    printf("  Signed size: %zu bytes\n", new_pkg_len);
    printf("  Sections: %u -> %u\n", header.section_count, new_section_count);

    free(new_pkg);
    free(pkg_data);
    free(key_data);
    return 0;
}

static int cmd_verify(const char *key_file, const char *input_file) {
    if (!key_file) {
        fprintf(stderr, "Error: public key file required (-k)\n");
        return 1;
    }
    if (!input_file) {
        fprintf(stderr, "Error: input file required (-i)\n");
        return 1;
    }

    /* Read public key */
    size_t key_len;
    uint8_t *key_data = read_file(key_file, &key_len);
    if (!key_data) {
        return 1;
    }

    const uint8_t *public_key;
    if (key_len == ED25519_PUBLIC_KEY_SIZE) {
        public_key = key_data;
    } else if (key_len == ED25519_SECRET_KEY_SIZE) {
        /* Allow using keypair file for verification */
        public_key = key_data + 32;
    } else {
        fprintf(stderr, "Error: invalid key file (expected %d or %d bytes, got %zu)\n",
                ED25519_PUBLIC_KEY_SIZE, ED25519_SECRET_KEY_SIZE, key_len);
        free(key_data);
        return 1;
    }

    /* Read package */
    size_t pkg_len;
    uint8_t *pkg_data = read_file(input_file, &pkg_len);
    if (!pkg_data) {
        free(key_data);
        return 1;
    }

    /* Verify signature */
    mbpf_sig_verify_opts_t opts = {
        .public_key = public_key,
        .allow_unsigned = 0,
        .production_mode = 0
    };

    int err = mbpf_package_verify_signature(pkg_data, pkg_len, &opts);

    free(pkg_data);
    free(key_data);

    if (err == MBPF_OK) {
        printf("Signature verification: OK\n");
        return 0;
    } else if (err == MBPF_ERR_MISSING_SECTION) {
        fprintf(stderr, "Error: package is not signed\n");
        return 1;
    } else if (err == MBPF_ERR_SIGNATURE) {
        fprintf(stderr, "Error: invalid signature\n");
        return 1;
    } else {
        fprintf(stderr, "Error: verification failed (code %d)\n", err);
        return 1;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
    }

    const char *cmd = argv[1];
    const char *key_file = NULL;
    const char *input_file = NULL;
    const char *output_file = NULL;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            input_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
        }
    }

    if (strcmp(cmd, "keygen") == 0) {
        return cmd_keygen(output_file);
    } else if (strcmp(cmd, "pubkey") == 0) {
        return cmd_pubkey(key_file, output_file);
    } else if (strcmp(cmd, "sign") == 0) {
        return cmd_sign(key_file, input_file, output_file);
    } else if (strcmp(cmd, "verify") == 0) {
        return cmd_verify(key_file, input_file);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
    }

    return 0;
}
