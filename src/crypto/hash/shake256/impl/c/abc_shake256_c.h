#ifndef ABC_SHAKE256_C_H
#define ABC_SHAKE256_C_H

#include "../../../keccak-p1600/impl/c/abc_keccak_p1600_c.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef abc_keccak_c_sponge abc_shake256_c_context;
typedef abc_keccak_c_reader abc_shake256_c_reader;

ABC_KECCAK_C_API int abc_shake256_c_init(abc_shake256_c_context *context);
ABC_KECCAK_C_API int abc_shake256_c_update(abc_shake256_c_context *context, const uint8_t *input, size_t length);
ABC_KECCAK_C_API int abc_shake256_c_finalize(
    const abc_shake256_c_context *context, abc_shake256_c_reader *reader);
ABC_KECCAK_C_API int abc_shake256_c_read(abc_shake256_c_reader *reader, uint8_t *output, size_t length);
ABC_KECCAK_C_API int abc_shake256_c_xof(
    const uint8_t *input, size_t input_length, uint8_t *output, size_t output_length);

#ifdef __cplusplus
}
#endif

#endif
