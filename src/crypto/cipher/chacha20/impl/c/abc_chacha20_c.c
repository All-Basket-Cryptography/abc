#include "abc_chacha20_c.h"

#include <string.h>

_Static_assert(SIZE_MAX <= UINT64_MAX, "ChaCha20 requires byte counts at most 64 bits");

static uint32_t load_word(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

static void store_word(uint8_t *bytes, uint32_t word)
{
    for (size_t i = 0; i < 4; ++i) {
        bytes[i] = (uint8_t)(word >> (8 * i));
    }
}

static uint32_t rotate_left(uint32_t word, unsigned distance)
{
    return (word << distance) | (word >> (32 - distance));
}

static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b;
    *d = rotate_left(*d ^ *a, 16);
    *c += *d;
    *b = rotate_left(*b ^ *c, 12);
    *a += *b;
    *d = rotate_left(*d ^ *a, 8);
    *c += *d;
    *b = rotate_left(*b ^ *c, 7);
}

static void initialize(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12])
{
    state[0] = UINT32_C(0x61707865);
    state[1] = UINT32_C(0x3320646e);
    state[2] = UINT32_C(0x79622d32);
    state[3] = UINT32_C(0x6b206574);
    for (size_t i = 0; i < 8; ++i) {
        state[4 + i] = load_word(key + 4 * i);
    }
    state[12] = 0;
    for (size_t i = 0; i < 3; ++i) {
        state[13 + i] = load_word(nonce + 4 * i);
    }
}

static void generate_block(uint32_t initial[16], uint32_t counter, uint8_t output[64])
{
    uint32_t work[16];
    initial[12] = counter;
    memcpy(work, initial, sizeof(work));
    for (size_t round = 0; round < 10; ++round) {
        quarter_round(&work[0], &work[4], &work[8], &work[12]);
        quarter_round(&work[1], &work[5], &work[9], &work[13]);
        quarter_round(&work[2], &work[6], &work[10], &work[14]);
        quarter_round(&work[3], &work[7], &work[11], &work[15]);
        quarter_round(&work[0], &work[5], &work[10], &work[15]);
        quarter_round(&work[1], &work[6], &work[11], &work[12]);
        quarter_round(&work[2], &work[7], &work[8], &work[13]);
        quarter_round(&work[3], &work[4], &work[9], &work[14]);
    }
    for (size_t i = 0; i < 16; ++i) {
        store_word(output + 4 * i, work[i] + initial[i]);
    }
}

int abc_chacha20_c_fits_counter(uint64_t bytes, uint32_t counter)
{
    return bytes == 0 || (bytes - 1) / ABC_CHACHA20_C_BLOCK_BYTES < (UINT64_C(1) << 32) - counter;
}

int abc_chacha20_c_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                         uint8_t *output, size_t capacity)
{
    uint32_t initial[16];
    if (key == NULL || nonce == NULL || output == NULL) {
        return ABC_CHACHA20_C_INVALID_ARGUMENT;
    }
    if (capacity < ABC_CHACHA20_C_BLOCK_BYTES) {
        return ABC_CHACHA20_C_OUTPUT_TOO_SHORT;
    }
    initialize(initial, key, nonce);
    generate_block(initial, counter, output);
    return ABC_CHACHA20_C_OK;
}

int abc_chacha20_c_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity)
{
    if (key == NULL || nonce == NULL || ((input == NULL || output == NULL) && length != 0)) {
        return ABC_CHACHA20_C_INVALID_ARGUMENT;
    }
    if (capacity < length) {
        return ABC_CHACHA20_C_OUTPUT_TOO_SHORT;
    }
    if (!abc_chacha20_c_fits_counter(length, counter)) {
        return ABC_CHACHA20_C_COUNTER_RANGE;
    }
    if (length == 0) {
        return ABC_CHACHA20_C_OK;
    }
    uint32_t initial[16];
    initialize(initial, key, nonce);
    memmove(output, input, length);
    while (length != 0) {
        uint8_t block[ABC_CHACHA20_C_BLOCK_BYTES];
        generate_block(initial, counter++, block);
        size_t chunk = length < sizeof(block) ? length : sizeof(block);
        for (size_t i = 0; i < chunk; ++i) {
            output[i] ^= block[i];
        }
        output += chunk;
        length -= chunk;
    }
    return ABC_CHACHA20_C_OK;
}
