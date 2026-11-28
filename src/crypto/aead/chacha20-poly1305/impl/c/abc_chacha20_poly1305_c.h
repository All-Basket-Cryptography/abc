#ifndef ABC_CHACHA20_POLY1305_C_H
#define ABC_CHACHA20_POLY1305_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_CHACHA20_POLY1305_C_KEY_BYTES 32u
#define ABC_CHACHA20_POLY1305_C_NONCE_BYTES 12u
#define ABC_CHACHA20_POLY1305_C_TAG_BYTES 16u

enum {
    ABC_CHACHA20_POLY1305_C_OK = 0,
    ABC_CHACHA20_POLY1305_C_INVALID_ARGUMENT = 1,
    ABC_CHACHA20_POLY1305_C_OUTPUT_TOO_SHORT = 2,
    ABC_CHACHA20_POLY1305_C_COUNTER_RANGE = 3,
    ABC_CHACHA20_POLY1305_C_AUTHENTICATION_FAILED = 4
};

/* Use a unique nonce under each key. Output can overlap input and AAD.
   The tag destination must be separate from the ciphertext prefix. */
int abc_chacha20_poly1305_c_seal(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_length, const uint8_t *input, size_t length,
    uint8_t *output, size_t capacity, uint8_t *tag, size_t tag_capacity);

/* Opening authenticates all inputs before it writes any output bytes. */
int abc_chacha20_poly1305_c_open(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_length, const uint8_t *input, size_t length,
    uint8_t *output, size_t capacity, const uint8_t *tag, size_t tag_length);

#ifdef __cplusplus
}
#endif
#endif
