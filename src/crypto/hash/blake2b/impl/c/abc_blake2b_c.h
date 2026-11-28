#ifndef ABC_BLAKE2B_C_H
#define ABC_BLAKE2B_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_BLAKE2B_C_SHARED)
#if defined(ABC_BLAKE2B_C_BUILD)
#define ABC_BLAKE2B_C_API __declspec(dllexport)
#else
#define ABC_BLAKE2B_C_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_BLAKE2B_C_API __attribute__((visibility("default")))
#else
#define ABC_BLAKE2B_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_BLAKE2B_C_BLOCK_BYTES 128
#define ABC_BLAKE2B_C_MAX_DIGEST_BYTES 64

/* Initialize with abc_blake2b_c_init before use. The fields are internal. */
typedef struct {
    uint64_t state[8];
    uint64_t compressed_low;
    uint64_t compressed_high;
    size_t used;
    size_t digest_size;
    uint8_t pending[ABC_BLAKE2B_C_BLOCK_BYTES];
} abc_blake2b_c_context;

enum {
    ABC_BLAKE2B_C_OK = 0,
    ABC_BLAKE2B_C_INVALID_ARGUMENT = 1,
    ABC_BLAKE2B_C_INVALID_DIGEST_SIZE = 2,
    ABC_BLAKE2B_C_MESSAGE_TOO_LONG = 3
};

/* Starts a fresh message with the given digest size in bytes. */
ABC_BLAKE2B_C_API int abc_blake2b_c_init(abc_blake2b_c_context *context, size_t digest_size);

/* Input may be NULL at length zero. Buffers must lie outside the context. */
ABC_BLAKE2B_C_API int abc_blake2b_c_update(abc_blake2b_c_context *context,
                                         const uint8_t *input, size_t length);

/* Writes a snapshot to a buffer of exactly the configured digest size. */
ABC_BLAKE2B_C_API int abc_blake2b_c_digest(const abc_blake2b_c_context *context,
                                         uint8_t *output, size_t output_length);

/* Uses the output length as the digest size. Input may overlap output. */
ABC_BLAKE2B_C_API int abc_blake2b_c_hash(const uint8_t *input, size_t length,
                                       uint8_t *output, size_t output_length);

#ifdef __cplusplus
}
#endif

#endif
