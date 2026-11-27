#ifndef ABC_SHA256_C_H
#define ABC_SHA256_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_SHA256_C_SHARED)
#if defined(ABC_SHA256_C_BUILD)
#define ABC_SHA256_C_API __declspec(dllexport)
#else
#define ABC_SHA256_C_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_SHA256_C_API __attribute__((visibility("default")))
#else
#define ABC_SHA256_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_SHA256_C_DIGEST_BYTES 32
#define ABC_SHA256_C_MAX_MESSAGE_BYTES (UINT64_MAX / UINT64_C(8))

typedef struct Hacl_Streaming_MD_state_32_s abc_sha256_c_context;

enum {
    ABC_SHA256_C_OK = 0,
    ABC_SHA256_C_INVALID_ARGUMENT = 1,
    ABC_SHA256_C_MESSAGE_TOO_LONG = 2,
    ABC_SHA256_C_OUT_OF_MEMORY = 3,
    ABC_SHA256_C_BACKEND_ERROR = 4
};

/* On success, *context owns one state. On error, *context is unchanged. */
ABC_SHA256_C_API int abc_sha256_c_new(abc_sha256_c_context **context);

/* NULL input is permitted for length zero. Validation errors preserve state. */
ABC_SHA256_C_API int abc_sha256_c_update(abc_sha256_c_context *context,
                                        const uint8_t *input, size_t length);

/* Snapshot the digest. The caller can continue to update the state. */
ABC_SHA256_C_API int abc_sha256_c_digest(abc_sha256_c_context *context,
                                        uint8_t output[ABC_SHA256_C_DIGEST_BYTES]);

/* NULL input is permitted for length zero. Input and output may overlap. */
ABC_SHA256_C_API int abc_sha256_c_hash(const uint8_t *input, size_t length,
                                      uint8_t output[ABC_SHA256_C_DIGEST_BYTES]);

/* A NULL context is permitted. Each non-NULL context has one owner. */
ABC_SHA256_C_API void abc_sha256_c_free(abc_sha256_c_context *context);

#ifdef __cplusplus
}
#endif

#endif
