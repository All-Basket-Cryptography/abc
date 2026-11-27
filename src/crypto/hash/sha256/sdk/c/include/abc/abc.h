#ifndef ABC_CRYPTO_ABC_H
#define ABC_CRYPTO_ABC_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_CRYPTO_SHARED)
#define ABC_API __declspec(dllimport)
#else
#define ABC_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_ABI_VERSION UINT32_C(0x00010000)
#define ABC_SHA256_DIGEST_BYTES 32

typedef int32_t abc_status;
enum {
    ABC_OK = 0,
    ABC_ERROR_NULL = 1,
    ABC_ERROR_LENGTH = 2,
    ABC_ERROR_STATE = 3,
    ABC_ERROR_ALIGNMENT = 4,
    ABC_ERROR_ALLOC = 5,
    ABC_ERROR_PANIC = 6
};

typedef struct abc_sha256 abc_sha256;

ABC_API uint32_t abc_abi_version(void);
ABC_API const char *abc_sha256_implementation(void);

ABC_API abc_status abc_sha256_digest(
    const uint8_t *input, size_t input_len, uint8_t *output, size_t output_capacity);
ABC_API abc_status abc_sha256_new(abc_sha256 **output);
ABC_API abc_status abc_sha256_update(abc_sha256 *context, const uint8_t *input, size_t input_len);
ABC_API abc_status abc_sha256_finalize(abc_sha256 *context, uint8_t *output, size_t output_capacity);
ABC_API abc_status abc_sha256_reset(abc_sha256 *context);
ABC_API void abc_sha256_free(abc_sha256 *context);

#ifdef __cplusplus
}
#endif

#undef ABC_API

#endif
