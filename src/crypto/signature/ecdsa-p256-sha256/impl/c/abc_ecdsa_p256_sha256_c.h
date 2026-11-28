#ifndef ABC_ECDSA_P256_SHA256_C_H
#define ABC_ECDSA_P256_SHA256_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_ECDSA_P256_C_BUILD_DLL)
#define ABC_ECDSA_P256_C_API __declspec(dllexport)
#else
#define ABC_ECDSA_P256_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum { ABC_P256_C_OK, ABC_P256_C_INVALID_ARGUMENT, ABC_P256_C_REJECTED,
       ABC_P256_C_PROVIDER_FAILURE, ABC_P256_C_RETRY_EXHAUSTED = 5 };

/* The private scalar is 32 bytes, the public output is uncompressed SEC 1,
 * and the signature contains raw P1363 r || s octets. */
ABC_ECDSA_P256_C_API int abc_ecdsa_p256_sha256_c_public_key(const uint8_t scalar[32], uint8_t public_key[65]);
ABC_ECDSA_P256_C_API int abc_ecdsa_p256_sha256_c_sign(const uint8_t scalar[32], const uint8_t *message,
                                                    size_t length, uint8_t signature[64]);
ABC_ECDSA_P256_C_API int abc_ecdsa_p256_sha256_c_verify(const uint8_t *public_key, size_t public_length,
    const uint8_t *message, size_t length, const uint8_t signature[64]);

#ifdef __cplusplus
}
#endif
#endif
