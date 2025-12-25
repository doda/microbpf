/*
 * Ed25519 signature implementation (from TweetNaCl)
 *
 * This is an Ed25519 implementation derived from TweetNaCl
 * (https://tweetnacl.cr.yp.to/). The original code is in the
 * public domain and was written by Daniel J. Bernstein, et al.
 *
 * Includes both signing and verification for toolchain use.
 */

#include "ed25519.h"
#include <string.h>

/* Field element type (64-bit limbs) */
typedef int64_t gf[16];

/* Curve25519/Ed25519 constants */
static const gf gf0 = {0};
static const gf gf1 = {1};

static const gf D = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};

static const gf D2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};

static const gf X = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};

static const gf Y = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};

static const gf I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};

/* L = 2^252 + 27742317777372353535851937790883648493 (order of base point) */
static const uint8_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* SHA-512 constants */
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static uint64_t load64_be(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static void store64_be(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56); p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40); p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24); p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >> 8);  p[7] = (uint8_t)x;
}

static void sha512_block(uint64_t *state, const uint8_t *data) {
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++)
        w[i] = load64_be(data + i * 8);

    for (int i = 16; i < 80; i++) {
        uint64_t s0 = rotr64(w[i-15], 1) ^ rotr64(w[i-15], 8) ^ (w[i-15] >> 7);
        uint64_t s1 = rotr64(w[i-2], 19) ^ rotr64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int i = 0; i < 80; i++) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t temp1 = h + S1 + ch + K512[i] + w[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* Streaming SHA-512 context */
typedef struct {
    uint64_t state[8];
    uint8_t buf[128];
    size_t buf_len;
    size_t total_len;
} sha512_ctx;

static void sha512_init(sha512_ctx *ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->buf_len = 0;
    ctx->total_len = 0;
}

static void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;

    /* If we have buffered data, try to complete a block */
    if (ctx->buf_len > 0) {
        size_t need = 128 - ctx->buf_len;
        if (len < need) {
            memcpy(ctx->buf + ctx->buf_len, data, len);
            ctx->buf_len += len;
            return;
        }
        memcpy(ctx->buf + ctx->buf_len, data, need);
        sha512_block(ctx->state, ctx->buf);
        data += need;
        len -= need;
        ctx->buf_len = 0;
    }

    /* Process full blocks directly from input */
    while (len >= 128) {
        sha512_block(ctx->state, data);
        data += 128;
        len -= 128;
    }

    /* Buffer remaining data */
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

static void sha512_final(sha512_ctx *ctx, uint8_t *out) {
    size_t total = ctx->total_len;

    /* Append padding */
    ctx->buf[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > 112) {
        memset(ctx->buf + ctx->buf_len, 0, 128 - ctx->buf_len);
        sha512_block(ctx->state, ctx->buf);
        ctx->buf_len = 0;
    }

    memset(ctx->buf + ctx->buf_len, 0, 120 - ctx->buf_len);
    store64_be(ctx->buf + 120, total * 8);
    sha512_block(ctx->state, ctx->buf);

    for (int i = 0; i < 8; i++) {
        store64_be(out + i * 8, ctx->state[i]);
    }
}

/* Field operations */
static void set25519(gf r, const gf a) {
    for (int i = 0; i < 16; i++) r[i] = a[i];
}

static void car25519(gf o) {
    int64_t c;
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i+1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n) {
    gf t, m;
    set25519(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2*i] = t[i] & 0xff;
        o[2*i + 1] = t[i] >> 8;
    }
}

static int neq25519(const gf a, const gf b) {
    uint8_t c[32], d[32];
    pack25519(c, a);
    pack25519(d, b);
    int r = 0;
    for (int i = 0; i < 32; i++) r |= c[i] ^ d[i];
    return r;
}

static uint8_t par25519(const gf a) {
    uint8_t d[32];
    pack25519(d, a);
    return d[0] & 1;
}

static void unpack25519(gf o, const uint8_t *n) {
    for (int i = 0; i < 16; i++) o[i] = n[2*i] + ((int64_t)n[2*i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

static void inv25519(gf o, const gf i) {
    gf c;
    set25519(c, i);
    for (int a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    set25519(o, c);
}

static void pow2523(gf o, const gf i) {
    gf c;
    set25519(c, i);
    for (int a = 250; a >= 0; a--) {
        S(c, c);
        if (a != 1) M(c, c, i);
    }
    set25519(o, c);
}

/* Point operations */
static void add(gf p[4], gf q[4]) {
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], uint8_t b) {
    for (int i = 0; i < 4; i++)
        sel25519(p[i], q[i], b);
}

static void pack(uint8_t *r, gf p[4]) {
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= par25519(tx) << 7;
}

static void scalarmult(gf p[4], gf q[4], const uint8_t *s) {
    gf a[4];
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);

    for (int i = 255; i >= 0; --i) {
        uint8_t bit = (s[i/8] >> (i & 7)) & 1;
        cswap(p, q, bit);
        add(q, p);
        set25519(a[0], p[0]);
        set25519(a[1], p[1]);
        set25519(a[2], p[2]);
        set25519(a[3], p[3]);
        add(p, a);
        cswap(p, q, bit);
    }
}

static void scalarbase(gf p[4], const uint8_t *s) {
    gf q[4];
    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

static int unpackneg(gf r[4], const uint8_t p[32]) {
    gf t, chk, num, den, den2, den4, den6;
    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) == (p[31] >> 7)) Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);
    return 0;
}

static void modL(uint8_t *r, int64_t x[64]) {
    int64_t carry;
    for (int i = 63; i >= 32; --i) {
        carry = 0;
        for (int j = i - 32; j < i - 12; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[i - 12] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (int j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (int j = 0; j < 32; ++j) x[j] -= carry * L[j];
    for (int i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = x[i] & 255;
    }
}

static void reduce(uint8_t *r) {
    int64_t x[64];
    for (int i = 0; i < 64; ++i) x[i] = (uint64_t)r[i];
    for (int i = 0; i < 64; ++i) r[i] = 0;
    modL(r, x);
}

/* Constant-time memory comparison */
static int verify32(const uint8_t *x, const uint8_t *y) {
    unsigned int d = 0;
    for (int i = 0; i < 32; ++i)
        d |= x[i] ^ y[i];
    return (1 & ((d - 1) >> 8)) - 1;
}

/*
 * Ed25519 signature verification using streaming SHA-512.
 *
 * This implementation uses a streaming SHA-512 context to avoid VLAs
 * and enable verification of arbitrarily large messages without
 * stack overflow.
 */
int ed25519_verify(const uint8_t *sig, const uint8_t *m, size_t n,
                   const uint8_t *pk) {
    uint8_t h[64], t[32];
    gf p[4], q[4];
    sha512_ctx ctx;

    if (sig[63] & 224) return -1;
    if (unpackneg(q, pk)) return -1;

    /* Compute h = SHA512(sig[0:32] || pk || m) using streaming */
    sha512_init(&ctx);
    sha512_update(&ctx, sig, 32);      /* R = sig[0:32] */
    sha512_update(&ctx, pk, 32);       /* public key */
    sha512_update(&ctx, m, n);         /* message (can be arbitrarily large) */
    sha512_final(&ctx, h);
    reduce(h);

    /* p = s*B - h*A where A=pk, s=sig[32:64] */
    scalarmult(p, q, h);
    scalarbase(q, sig + 32);
    add(p, q);
    pack(t, p);

    /* Compare with R = sig[0:32] */
    return verify32(sig, t);
}

/*
 * Ed25519 keypair generation and signing
 */

/*
 * Generate Ed25519 keypair from a 32-byte seed.
 * The secret_key output is 64 bytes: SHA512(seed)[0:32] clamped, then public key.
 * Actually, we follow TweetNaCl convention: secret_key = seed || public_key.
 */
int ed25519_keypair_from_seed(uint8_t *public_key, uint8_t *secret_key,
                               const uint8_t *seed) {
    uint8_t h[64];
    gf p[4];
    sha512_ctx ctx;

    /* Hash the seed to get the secret scalar */
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h);

    /* Clamp the scalar */
    h[0] &= 0xf8;
    h[31] &= 0x7f;
    h[31] |= 0x40;

    /* Compute public key = scalar * basepoint */
    scalarbase(p, h);
    pack(public_key, p);

    /* Store seed || public_key as the secret key */
    memcpy(secret_key, seed, 32);
    memcpy(secret_key + 32, public_key, 32);

    return 0;
}

/*
 * Sign a message with Ed25519.
 *
 * Algorithm (RFC 8032):
 *   1. h = SHA512(seed)
 *   2. s = h[0:32] clamped (secret scalar)
 *   3. prefix = h[32:64]
 *   4. r = SHA512(prefix || message) mod L
 *   5. R = r * B
 *   6. k = SHA512(R || public_key || message) mod L
 *   7. S = (r + k * s) mod L
 *   8. signature = R || S
 */
int ed25519_sign(uint8_t *signature, const uint8_t *message, size_t message_len,
                 const uint8_t *secret_key) {
    uint8_t h[64];
    uint8_t r_hash[64];
    uint8_t k_hash[64];
    int64_t x[64];
    gf p[4];
    sha512_ctx ctx;

    /* Extract seed and public key from secret_key */
    const uint8_t *seed = secret_key;
    const uint8_t *public_key = secret_key + 32;

    /* Hash the seed */
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, h);

    /* Clamp the secret scalar s = h[0:32] */
    h[0] &= 0xf8;
    h[31] &= 0x7f;
    h[31] |= 0x40;

    /* r = SHA512(h[32:64] || message) mod L */
    sha512_init(&ctx);
    sha512_update(&ctx, h + 32, 32);  /* prefix */
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, r_hash);
    reduce(r_hash);

    /* R = r * B */
    scalarbase(p, r_hash);
    pack(signature, p);  /* signature[0:32] = R */

    /* k = SHA512(R || public_key || message) mod L */
    sha512_init(&ctx);
    sha512_update(&ctx, signature, 32);  /* R */
    sha512_update(&ctx, public_key, 32);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, k_hash);
    reduce(k_hash);

    /* S = (r + k * s) mod L */
    for (int i = 0; i < 64; i++) {
        x[i] = 0;
    }
    for (int i = 0; i < 32; i++) {
        x[i] = (uint64_t)r_hash[i];
    }
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            x[i + j] += (int64_t)k_hash[i] * (int64_t)h[j];
        }
    }
    modL(signature + 32, x);  /* signature[32:64] = S */

    return 0;
}
