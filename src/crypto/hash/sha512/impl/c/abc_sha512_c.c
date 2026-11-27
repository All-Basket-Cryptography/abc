#include "abc_sha512_c.h"

#include <string.h>

_Static_assert(SIZE_MAX <= UINT64_MAX, "SHA-512 supports size_t widths up to 64 bits");

// FIPS 180-4 §§ 4.2.3 and 5.3.5.
static const uint64_t initial_state[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b), UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f), UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179),
};

static const uint64_t round_constants[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd), UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019), UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe), UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1), UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3), UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483), UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210), UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725), UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926), UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8), UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001), UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910), UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53), UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb), UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60), UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9), UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207), UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6), UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493), UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a), UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
};

static uint64_t rotate_right(uint64_t value, unsigned distance) {
    return (value >> distance) | (value << (64 - distance));
}

static uint64_t read_big_endian(const uint8_t input[8]) {
    return (uint64_t)input[0] << 56 | (uint64_t)input[1] << 48 |
           (uint64_t)input[2] << 40 | (uint64_t)input[3] << 32 |
           (uint64_t)input[4] << 24 | (uint64_t)input[5] << 16 |
           (uint64_t)input[6] << 8  | (uint64_t)input[7];
}

static void write_big_endian(uint8_t output[8], uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) {
        output[i] = (uint8_t)(value >> (56 - 8 * i));
    }
}

// FIPS 180-4 §§ 5.2.2 and 6.4.2.
static void compress(uint64_t state[8], const uint8_t block[ABC_SHA512_C_BLOCK_BYTES]) {
    uint64_t schedule[80];
    for (unsigned i = 0; i < 16; ++i) {
        schedule[i] = read_big_endian(block + i * 8);
    }
    for (unsigned i = 16; i < 80; ++i) {
        uint64_t x = schedule[i - 15], y = schedule[i - 2];
        uint64_t sigma0 = rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7);
        uint64_t sigma1 = rotate_right(y, 19) ^ rotate_right(y, 61) ^ (y >> 6);
        schedule[i] = schedule[i - 16] + sigma0 + schedule[i - 7] + sigma1;
    }

    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (unsigned i = 0; i < 80; ++i) {
        uint64_t sum1 = rotate_right(e, 14) ^ rotate_right(e, 18) ^ rotate_right(e, 41);
        uint64_t choose = (e & f) ^ (~e & g);
        uint64_t first = h + sum1 + choose + round_constants[i] + schedule[i];
        uint64_t sum0 = rotate_right(a, 28) ^ rotate_right(a, 34) ^ rotate_right(a, 39);
        uint64_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint64_t second = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + first;
        d = c;
        c = b;
        b = a;
        a = first + second;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

int abc_sha512_c_init(abc_sha512_c_context *context) {
    if (context == NULL) {
        return ABC_SHA512_C_INVALID_ARGUMENT;
    }
    memset(context, 0, sizeof(*context));
    memcpy(context->state, initial_state, sizeof(initial_state));
    return ABC_SHA512_C_OK;
}

int abc_sha512_c_update(abc_sha512_c_context *context, const uint8_t *input, size_t length) {
    if (context == NULL || (input == NULL && length != 0)) {
        return ABC_SHA512_C_INVALID_ARGUMENT;
    }
    if (length == 0) {
        return ABC_SHA512_C_OK;
    }

    uint64_t low = context->bytes_low + (uint64_t)length;
    uint64_t high = context->bytes_high + (low < context->bytes_low);
    if (high >= (UINT64_C(1) << 61)) {
        return ABC_SHA512_C_MESSAGE_TOO_LONG;
    }
    context->bytes_high = high;
    context->bytes_low = low;

    if (context->used != 0) {
        size_t space = ABC_SHA512_C_BLOCK_BYTES - context->used;
        size_t count = length < space ? length : space;
        memcpy(context->pending + context->used, input, count);
        context->used += count;
        if (context->used < ABC_SHA512_C_BLOCK_BYTES) {
            return ABC_SHA512_C_OK;
        }
        compress(context->state, context->pending);
        input += count;
        length -= count;
    }
    while (length >= ABC_SHA512_C_BLOCK_BYTES) {
        compress(context->state, input);
        input += ABC_SHA512_C_BLOCK_BYTES;
        length -= ABC_SHA512_C_BLOCK_BYTES;
    }
    if (length != 0) {
        memcpy(context->pending, input, length);
    }
    context->used = length;
    return ABC_SHA512_C_OK;
}

int abc_sha512_c_digest(const abc_sha512_c_context *context, uint8_t *output, size_t output_length) {
    if (context == NULL || output == NULL) {
        return ABC_SHA512_C_INVALID_ARGUMENT;
    }
    if (output_length < ABC_SHA512_C_DIGEST_BYTES) {
        return ABC_SHA512_C_DESTINATION_TOO_SHORT;
    }

    uint64_t state[8];
    memcpy(state, context->state, sizeof(state));
    uint8_t final_blocks[2 * ABC_SHA512_C_BLOCK_BYTES] = {0};
    memcpy(final_blocks, context->pending, context->used);
    final_blocks[context->used] = 0x80;
    const size_t end = context->used < ABC_SHA512_C_BLOCK_BYTES - 16
        ? ABC_SHA512_C_BLOCK_BYTES : 2 * ABC_SHA512_C_BLOCK_BYTES;
    write_big_endian(final_blocks + end - 16, (context->bytes_high << 3) | (context->bytes_low >> 61));
    write_big_endian(final_blocks + end - 8, context->bytes_low << 3);
    for (size_t offset = 0; offset < end; offset += ABC_SHA512_C_BLOCK_BYTES) {
        compress(state, final_blocks + offset);
    }
    for (unsigned i = 0; i < 8; ++i) {
        write_big_endian(output + i * 8, state[i]);
    }
    return ABC_SHA512_C_OK;
}

int abc_sha512_c_hash(const uint8_t *input, size_t length, uint8_t *output, size_t output_length) {
    if (output == NULL) {
        return ABC_SHA512_C_INVALID_ARGUMENT;
    }
    if (output_length < ABC_SHA512_C_DIGEST_BYTES) {
        return ABC_SHA512_C_DESTINATION_TOO_SHORT;
    }
    abc_sha512_c_context context;
    abc_sha512_c_init(&context);
    int status = abc_sha512_c_update(&context, input, length);
    if (status != ABC_SHA512_C_OK) {
        return status;
    }
    return abc_sha512_c_digest(&context, output, output_length);
}
