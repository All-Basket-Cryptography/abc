#ifndef ABC_AES256_C_H
#define ABC_AES256_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_AES256_C_BUILD_DLL)
#define ABC_AES256_C_API __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_AES256_C_API __attribute__((visibility("default")))
#else
#define ABC_AES256_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_AES256_C_KEY_BYTES 32
#define ABC_AES256_C_BLOCK_BYTES 16

typedef struct {
    uint8_t encrypt_keys[15][ABC_AES256_C_BLOCK_BYTES];
    uint8_t decrypt_keys[15][ABC_AES256_C_BLOCK_BYTES];
} abc_aes256_c_context;

enum { ABC_AES256_C_OK, ABC_AES256_C_INVALID_ARGUMENT, ABC_AES256_C_UNSUPPORTED };

ABC_AES256_C_API int abc_aes256_c_available(void);
ABC_AES256_C_API int abc_aes256_c_init(abc_aes256_c_context *context, const uint8_t *key, size_t key_size);

/* Use an initialized context. Each input and output holds exactly one block. */
ABC_AES256_C_API int abc_aes256_c_encrypt(const abc_aes256_c_context *context, const uint8_t *input,
                                         uint8_t *output);
ABC_AES256_C_API int abc_aes256_c_decrypt(const abc_aes256_c_context *context, const uint8_t *input,
                                         uint8_t *output);
ABC_AES256_C_API void abc_aes256_c_clear(abc_aes256_c_context *context);

#ifdef __cplusplus
}
#endif

#endif
