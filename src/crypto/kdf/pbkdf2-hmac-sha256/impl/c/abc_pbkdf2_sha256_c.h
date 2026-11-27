#ifndef ABC_PBKDF2_SHA256_C_H
#define ABC_PBKDF2_SHA256_C_H

#include "abc_hmac_sha256_c.h"

#if defined(_WIN32) && defined(ABC_PBKDF2_SHA256_C_SHARED)
#if defined(ABC_PBKDF2_SHA256_C_BUILD)
#define ABC_PBKDF2_SHA256_C_API __declspec(dllexport)
#else
#define ABC_PBKDF2_SHA256_C_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_PBKDF2_SHA256_C_API __attribute__((visibility("default")))
#else
#define ABC_PBKDF2_SHA256_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_PBKDF2_SHA256_C_MAX_OUTPUT_BYTES (UINT64_C(32) * UINT32_MAX)
#define ABC_PBKDF2_SHA256_C_MAX_SALT_BYTES (ABC_HMAC_SHA256_C_MAX_MESSAGE_BYTES - UINT64_C(4))

enum {
    ABC_PBKDF2_SHA256_C_OK = ABC_HMAC_SHA256_C_OK,
    ABC_PBKDF2_SHA256_C_INVALID_ARGUMENT = ABC_HMAC_SHA256_C_INVALID_ARGUMENT,
    ABC_PBKDF2_SHA256_C_LENGTH_LIMIT = ABC_HMAC_SHA256_C_LENGTH_LIMIT,
    ABC_PBKDF2_SHA256_C_OUT_OF_MEMORY = ABC_HMAC_SHA256_C_OUT_OF_MEMORY,
    ABC_PBKDF2_SHA256_C_BACKEND_ERROR = ABC_HMAC_SHA256_C_BACKEND_ERROR,
    ABC_PBKDF2_SHA256_C_INVALID_ITERATIONS = 6,
    ABC_PBKDF2_SHA256_C_INVALID_OUTPUT_LENGTH = 7
};

/* NULL password and salt are accepted at length zero. Iterations and output
 * length must be positive. Output may overlap valid password or salt storage.
 * Success writes exactly output_length bytes. Failure preserves output. */
ABC_PBKDF2_SHA256_C_API int abc_pbkdf2_sha256_c_derive(
    const uint8_t *password, size_t password_length, const uint8_t *salt, size_t salt_length,
    uint32_t iterations, uint8_t *output, size_t output_length);

#ifdef __cplusplus
}
#endif

#endif
