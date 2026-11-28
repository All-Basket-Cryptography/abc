#ifndef ABC_AES256_GCM_C_H
#define ABC_AES256_GCM_C_H

#include "../../../../cipher/aes256/impl/c/abc_aes256_c.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_AES256_GCM_C_NONCE_BYTES 12
#define ABC_AES256_GCM_C_TAG_BYTES 16

typedef struct {
    abc_aes256_c_context cipher;
    uint64_t hash_high;
    uint64_t hash_low;
} abc_aes256_gcm_c_context;

enum { ABC_AES256_GCM_C_AUTHENTICATION_FAILED = 3 };

ABC_AES256_C_API int abc_aes256_gcm_c_init(abc_aes256_gcm_c_context *context, const uint8_t *key, size_t key_size);
ABC_AES256_C_API void abc_aes256_gcm_c_clear(abc_aes256_gcm_c_context *context);

/* A nonce must be unique for each seal with a given key. Buffers must lie
   outside the initialized context. The tag holds exactly 16 bytes. */
ABC_AES256_C_API int abc_aes256_gcm_c_seal(const abc_aes256_gcm_c_context *context,
    const uint8_t *nonce, const uint8_t *aad, size_t aad_size, const uint8_t *plaintext,
    size_t length, uint8_t *ciphertext, size_t output_length, uint8_t *tag);

/* Authentication and argument failures leave plaintext untouched. */
ABC_AES256_C_API int abc_aes256_gcm_c_open(const abc_aes256_gcm_c_context *context,
    const uint8_t *nonce, const uint8_t *aad, size_t aad_size, const uint8_t *ciphertext,
    size_t length, const uint8_t *tag, uint8_t *plaintext, size_t output_length);

#ifdef __cplusplus
}
#endif

#endif
