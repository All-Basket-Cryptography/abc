#ifndef ABC_ECDSA_P256_NONCE_H
#define ABC_ECDSA_P256_NONCE_H

#include "abc_ecdsa_p256_sha256_c.h"

#if defined(_WIN32) && defined(ABC_ECDSA_P256_TEST_SUPPORT)
#define ABC_P256_TEST_API __declspec(dllexport)
#else
#define ABC_P256_TEST_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum { ABC_P256_C_RETRY = 4 };

/* Internal operations for a caller implementing RFC 6979. The nonce
 * operation must only receive a candidate from that deterministic sequence. */
int abc_p256_c_scalar_in_range(const uint8_t scalar[32]);
void abc_p256_c_reduce_digest(const uint8_t digest[32], uint8_t encoded[32]);
int abc_p256_c_public_point(const uint8_t scalar[32], uint8_t out[65]);
ABC_P256_TEST_API int abc_p256_c_sign_candidate(const uint8_t scalar[32], const uint8_t digest[32],
                                               const uint8_t nonce[32], uint8_t out[64]);
int abc_p256_c_verify_digest(const uint8_t *point, size_t point_length, const uint8_t digest[32],
                             const uint8_t signature[64]);

#ifdef __cplusplus
}
#endif
#endif
