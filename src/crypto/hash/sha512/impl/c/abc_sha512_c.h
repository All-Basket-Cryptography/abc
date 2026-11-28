#ifndef ABC_SHA512_C_H
#define ABC_SHA512_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_SHA512_C_SHARED)
#if defined(ABC_SHA512_C_BUILD)
#define ABC_SHA512_C_API __declspec(dllexport)
#else
#define ABC_SHA512_C_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_SHA512_C_API __attribute__((visibility("default")))
#else
#define ABC_SHA512_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_SHA512_C_DIGEST_BYTES 64
#define ABC_SHA512_C_BLOCK_BYTES 128

/* Initialize with abc_sha512_c_init before use. The fields are internal. */
typedef struct {
    uint64_t state[8];
    uint64_t bytes_high;
    uint64_t bytes_low;
    size_t used;
    uint8_t pending[ABC_SHA512_C_BLOCK_BYTES];
} abc_sha512_c_context;

enum {
    ABC_SHA512_C_OK = 0,
    ABC_SHA512_C_INVALID_ARGUMENT = 1,
    ABC_SHA512_C_MESSAGE_TOO_LONG = 2,
    ABC_SHA512_C_DESTINATION_TOO_SHORT = 3
};

ABC_SHA512_C_API int abc_sha512_c_init(abc_sha512_c_context *context);

/* Empty input may be NULL. Nonempty input points to readable bytes outside
   the context. Calls on each context must be serialized. */
ABC_SHA512_C_API int abc_sha512_c_update(abc_sha512_c_context *context,
                                         const uint8_t *input, size_t length);

/* Snapshot into the first 64 output bytes outside the context. */
ABC_SHA512_C_API int abc_sha512_c_digest(const abc_sha512_c_context *context,
                                         uint8_t *output, size_t output_length);

/* Input and output may overlap. Rejection preserves the destination. */
ABC_SHA512_C_API int abc_sha512_c_hash(const uint8_t *input, size_t length,
                                       uint8_t *output, size_t output_length);

#ifdef __cplusplus
}
#endif

#endif
