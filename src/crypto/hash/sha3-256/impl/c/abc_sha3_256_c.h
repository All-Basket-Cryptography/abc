#ifndef ABC_SHA3_256_C_H
#define ABC_SHA3_256_C_H

#include "../../../keccak-p1600/impl/c/abc_keccak_p1600_c.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_SHA3_256_C_DIGEST_BYTES 32
typedef abc_keccak_c_sponge abc_sha3_256_c_context;

ABC_KECCAK_C_API int abc_sha3_256_c_init(abc_sha3_256_c_context *context);
ABC_KECCAK_C_API int abc_sha3_256_c_update(abc_sha3_256_c_context *context, const uint8_t *input, size_t length);
ABC_KECCAK_C_API int abc_sha3_256_c_digest(
    const abc_sha3_256_c_context *context, uint8_t *output, size_t output_length);
ABC_KECCAK_C_API int abc_sha3_256_c_hash(
    const uint8_t *input, size_t length, uint8_t *output, size_t output_length);

#ifdef __cplusplus
}
#endif

#endif
