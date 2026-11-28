#ifndef ABC_HMAC_SHA256_C_H
#define ABC_HMAC_SHA256_C_H

#include "abc_sha256_c.h"

#if defined(_WIN32) && defined(ABC_HMAC_SHA256_C_SHARED)
#if defined(ABC_HMAC_SHA256_C_BUILD)
#define ABC_HMAC_SHA256_C_API __declspec(dllexport)
#else
#define ABC_HMAC_SHA256_C_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_HMAC_SHA256_C_API __attribute__((visibility("default")))
#else
#define ABC_HMAC_SHA256_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_HMAC_SHA256_C_TAG_BYTES ABC_SHA256_C_DIGEST_BYTES
#define ABC_HMAC_SHA256_C_MAX_KEY_BYTES ABC_SHA256_C_MAX_MESSAGE_BYTES
#define ABC_HMAC_SHA256_C_MAX_MESSAGE_BYTES (ABC_SHA256_C_MAX_MESSAGE_BYTES - UINT64_C(64))

typedef struct abc_hmac_sha256_c_context abc_hmac_sha256_c_context;

enum {
    ABC_HMAC_SHA256_C_OK = ABC_SHA256_C_OK,
    ABC_HMAC_SHA256_C_INVALID_ARGUMENT = ABC_SHA256_C_INVALID_ARGUMENT,
    ABC_HMAC_SHA256_C_LENGTH_LIMIT = ABC_SHA256_C_MESSAGE_TOO_LONG,
    ABC_HMAC_SHA256_C_OUT_OF_MEMORY = ABC_SHA256_C_OUT_OF_MEMORY,
    ABC_HMAC_SHA256_C_BACKEND_ERROR = ABC_SHA256_C_BACKEND_ERROR,
    ABC_HMAC_SHA256_C_OUTPUT_TOO_SHORT = 5
};

/* A NULL key is permitted at length zero. On failure, *context is unchanged. */
ABC_HMAC_SHA256_C_API int abc_hmac_sha256_c_new(const uint8_t *key, size_t key_length,
                                             abc_hmac_sha256_c_context **context);

/* A NULL input is permitted at length zero. Validation errors preserve the context. */
ABC_HMAC_SHA256_C_API int abc_hmac_sha256_c_update(abc_hmac_sha256_c_context *context,
                                                const uint8_t *input, size_t length);

/* Write the first 32 output bytes. The caller can continue updating the context. */
ABC_HMAC_SHA256_C_API int abc_hmac_sha256_c_digest(abc_hmac_sha256_c_context *context,
                                                uint8_t *output, size_t capacity);

/* Output may overlap valid key or input storage. Failures leave output unchanged. */
ABC_HMAC_SHA256_C_API int abc_hmac_sha256_c_authenticate(const uint8_t *key, size_t key_length,
                                                      const uint8_t *input, size_t length,
                                                      uint8_t *output, size_t capacity);

ABC_HMAC_SHA256_C_API void abc_hmac_sha256_c_free(abc_hmac_sha256_c_context *context);

#ifdef __cplusplus
}
#endif

#endif
