#include "abc_blake2b_c.h"

#include <stdbool.h>
#include <string.h>

_Static_assert(SIZE_MAX <= UINT64_MAX, "BLAKE2b chunk sizes must fit a uint64_t");

static const uint64_t iv[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179),
};

static const uint8_t sigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static uint64_t load_le(const uint8_t *input) {
    uint64_t value = 0;
    for (unsigned byte = 0; byte < 8; ++byte) {
        value |= (uint64_t)input[byte] << (8U * byte);
    }
    return value;
}

static inline uint64_t rotate_right(uint64_t value, unsigned distance) {
    return (value >> distance) | (value << (64U - distance));
}

static inline void mix(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d,
                       uint64_t x, uint64_t y) {
    *a += *b + x;
    *d = rotate_right(*d ^ *a, 32);
    *c += *d;
    *b = rotate_right(*b ^ *c, 24);
    *a += *b + y;
    *d = rotate_right(*d ^ *a, 16);
    *c += *d;
    *b = rotate_right(*b ^ *c, 63);
}

static void compress(uint64_t state[8], const uint8_t *input,
                     uint64_t low, uint64_t high, bool final) {
    uint64_t message[16];
    for (size_t word = 0; word < 16; ++word) {
        message[word] = load_le(input + 8 * word);
    }

    uint64_t v[16];
    memcpy(v, state, sizeof iv);
    memcpy(v + 8, iv, sizeof iv);
    v[12] ^= low;
    v[13] ^= high;
    if (final) {
        v[14] = ~v[14];
    }
    for (size_t round = 0; round < 12; ++round) {
        const uint8_t *s = sigma[round % 10];
        mix(v + 0, v + 4, v + 8,  v + 12, message[s[0]],  message[s[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, message[s[2]],  message[s[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, message[s[4]],  message[s[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, message[s[6]],  message[s[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, message[s[8]],  message[s[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, message[s[10]], message[s[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, message[s[12]], message[s[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, message[s[14]], message[s[15]]);
    }
    for (size_t i = 0; i < 8; ++i) {
        state[i] ^= v[i] ^ v[i + 8];
    }
}

static bool add_count(uint64_t *low, uint64_t *high, uint64_t bytes) {
    const uint64_t sum = *low + bytes;
    const bool carry = sum < *low;
    if (carry && *high == UINT64_MAX) {
        return false;
    }
    *low = sum;
    *high += carry;
    return true;
}

static void consume_block(abc_blake2b_c_context *context, const uint8_t *block) {
    /* The input-length preflight bounds each intermediate counter. */
    (void)add_count(&context->compressed_low, &context->compressed_high, ABC_BLAKE2B_C_BLOCK_BYTES);
    compress(context->state, block, context->compressed_low, context->compressed_high, false);
}

int abc_blake2b_c_init(abc_blake2b_c_context *context, size_t digest_size) {
    if (context == NULL) {
        return ABC_BLAKE2B_C_INVALID_ARGUMENT;
    }
    if (digest_size == 0 || digest_size > ABC_BLAKE2B_C_MAX_DIGEST_BYTES) {
        return ABC_BLAKE2B_C_INVALID_DIGEST_SIZE;
    }
    *context = (abc_blake2b_c_context){0};
    memcpy(context->state, iv, sizeof iv);
    context->state[0] ^= UINT64_C(0x01010000) | (uint64_t)digest_size;
    context->digest_size = digest_size;
    return ABC_BLAKE2B_C_OK;
}

int abc_blake2b_c_update(abc_blake2b_c_context *context, const uint8_t *input, size_t length) {
    if (context == NULL || (input == NULL && length != 0)) {
        return ABC_BLAKE2B_C_INVALID_ARGUMENT;
    }
    if (length == 0) {
        return ABC_BLAKE2B_C_OK;
    }

    uint64_t low = context->compressed_low;
    uint64_t high = context->compressed_high;
    if (!add_count(&low, &high, context->used) || !add_count(&low, &high, length)) {
        return ABC_BLAKE2B_C_MESSAGE_TOO_LONG;
    }

    const size_t available = ABC_BLAKE2B_C_BLOCK_BYTES - context->used;
    if (length <= available) {
        memcpy(context->pending + context->used, input, length);
        context->used += length;
        return ABC_BLAKE2B_C_OK;
    }
    if (context->used != 0) {
        if (available != 0) {
            memcpy(context->pending + context->used, input, available);
            input += available;
            length -= available;
        }
        consume_block(context, context->pending);
    }
    while (length > ABC_BLAKE2B_C_BLOCK_BYTES) {
        consume_block(context, input);
        input += ABC_BLAKE2B_C_BLOCK_BYTES;
        length -= ABC_BLAKE2B_C_BLOCK_BYTES;
    }
    memcpy(context->pending, input, length);
    context->used = length;
    return ABC_BLAKE2B_C_OK;
}

int abc_blake2b_c_digest(const abc_blake2b_c_context *context, uint8_t *output, size_t output_length) {
    if (context == NULL || output == NULL) {
        return ABC_BLAKE2B_C_INVALID_ARGUMENT;
    }
    if (output_length != context->digest_size) {
        return ABC_BLAKE2B_C_INVALID_DIGEST_SIZE;
    }
    uint64_t state[8];
    uint8_t block[ABC_BLAKE2B_C_BLOCK_BYTES] = {0};
    uint64_t low = context->compressed_low;
    uint64_t high = context->compressed_high;
    (void)add_count(&low, &high, context->used);
    memcpy(state, context->state, sizeof state);
    memcpy(block, context->pending, context->used);
    compress(state, block, low, high, true);
    for (size_t i = 0; i < output_length; ++i) {
        output[i] = (uint8_t)(state[i / 8] >> (8 * (i % 8)));
    }
    return ABC_BLAKE2B_C_OK;
}

int abc_blake2b_c_hash(const uint8_t *input, size_t length, uint8_t *output, size_t output_length) {
    if (output == NULL) {
        return ABC_BLAKE2B_C_INVALID_ARGUMENT;
    }
    abc_blake2b_c_context context;
    int status = abc_blake2b_c_init(&context, output_length);
    if (status != ABC_BLAKE2B_C_OK) {
        return status;
    }
    status = abc_blake2b_c_update(&context, input, length);
    if (status != ABC_BLAKE2B_C_OK) {
        return status;
    }
    return abc_blake2b_c_digest(&context, output, output_length);
}
