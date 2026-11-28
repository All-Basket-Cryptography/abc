#ifndef ABC_HKDF_SHA256_C_H
#define ABC_HKDF_SHA256_C_H

#include "abc_hmac_sha256_c.h"

#if defined(_WIN32) && defined(ABC_HKDF_SHA256_C_SHARED)
#if defined(ABC_HKDF_SHA256_C_BUILD)
#define ABC_HKDF_SHA256_C_API __declspec(dllexport)
#else
#define ABC_HKDF_SHA256_C_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_HKDF_SHA256_C_API __attribute__((visibility("default")))
#else
#define ABC_HKDF_SHA256_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_HKDF_SHA256_C_PRK_BYTES ABC_HMAC_SHA256_C_TAG_BYTES
#define ABC_HKDF_SHA256_C_MAX_OUTPUT_BYTES (255 * ABC_HKDF_SHA256_C_PRK_BYTES)

enum {
    ABC_HKDF_SHA256_C_OK = ABC_HMAC_SHA256_C_OK,
    ABC_HKDF_SHA256_C_INVALID_ARGUMENT = ABC_HMAC_SHA256_C_INVALID_ARGUMENT,
    ABC_HKDF_SHA256_C_LENGTH_LIMIT = ABC_HMAC_SHA256_C_LENGTH_LIMIT,
    ABC_HKDF_SHA256_C_OUT_OF_MEMORY = ABC_HMAC_SHA256_C_OUT_OF_MEMORY,
    ABC_HKDF_SHA256_C_BACKEND_ERROR = ABC_HMAC_SHA256_C_BACKEND_ERROR,
    ABC_HKDF_SHA256_C_OUTPUT_TOO_SHORT = ABC_HMAC_SHA256_C_OUTPUT_TOO_SHORT,
    ABC_HKDF_SHA256_C_PRK_TOO_SHORT = 6,
    ABC_HKDF_SHA256_C_OUTPUT_TOO_LONG = 7
};

/* A zero-length salt uses 32 zero bytes. Success writes exactly 32 PRK bytes. */
ABC_HKDF_SHA256_C_API int abc_hkdf_sha256_c_extract(const uint8_t *salt, size_t salt_length,
                                                  const uint8_t *ikm, size_t ikm_length,
                                                  uint8_t *prk, size_t prk_capacity);

/* PRK needs at least 32 bytes. A NULL info or output is permitted at length zero. */
ABC_HKDF_SHA256_C_API int abc_hkdf_sha256_c_expand(const uint8_t *prk, size_t prk_length,
                                                 const uint8_t *info, size_t info_length,
                                                 uint8_t *output, size_t output_length);

/* Output may overlap inputs in all three operations. Any failure leaves it unchanged. */
ABC_HKDF_SHA256_C_API int abc_hkdf_sha256_c_derive(const uint8_t *salt, size_t salt_length,
                                                 const uint8_t *ikm, size_t ikm_length,
                                                 const uint8_t *info, size_t info_length,
                                                 uint8_t *output, size_t output_length);

#ifdef __cplusplus
}
#endif

#endif
