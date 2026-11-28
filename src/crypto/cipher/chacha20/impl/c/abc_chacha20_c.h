#ifndef ABC_CHACHA20_C_H
#define ABC_CHACHA20_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_CHACHA20_C_KEY_BYTES 32u
#define ABC_CHACHA20_C_NONCE_BYTES 12u
#define ABC_CHACHA20_C_BLOCK_BYTES 64u

enum {
    ABC_CHACHA20_C_OK = 0,
    ABC_CHACHA20_C_INVALID_ARGUMENT = 1,
    ABC_CHACHA20_C_OUTPUT_TOO_SHORT = 2,
    ABC_CHACHA20_C_COUNTER_RANGE = 3
};

int abc_chacha20_c_fits_counter(uint64_t bytes, uint32_t counter);

int abc_chacha20_c_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                         uint8_t *output, size_t capacity);

/* Overlapping input and output are supported. Errors preserve output. */
int abc_chacha20_c_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                       const uint8_t *input, size_t length, uint8_t *output, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
