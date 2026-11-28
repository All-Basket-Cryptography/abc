#include "abc_sha3_256_c.h"

int abc_sha3_256_c_init(abc_sha3_256_c_context *context) {
    return abc_keccak_c_init(context);
}

int abc_sha3_256_c_update(abc_sha3_256_c_context *context, const uint8_t *input, size_t length) {
    return abc_keccak_c_absorb(context, input, length);
}

static int output_status(const uint8_t *output, size_t output_length) {
    if (output == NULL) {
        return ABC_KECCAK_C_INVALID_ARGUMENT;
    }
    return output_length >= ABC_SHA3_256_C_DIGEST_BYTES ? ABC_KECCAK_C_OK : ABC_KECCAK_C_DESTINATION_TOO_SHORT;
}

int abc_sha3_256_c_digest(const abc_sha3_256_c_context *context, uint8_t *output, size_t output_length) {
    const int status = output_status(output, output_length);
    if (status != ABC_KECCAK_C_OK) {
        return status;
    }
    abc_keccak_c_reader reader;
    const int finished = abc_keccak_c_finish(context, ABC_KECCAK_C_SHA3, &reader);
    return finished != ABC_KECCAK_C_OK ? finished : abc_keccak_c_read(&reader, output, ABC_SHA3_256_C_DIGEST_BYTES);
}

int abc_sha3_256_c_hash(const uint8_t *input, size_t length, uint8_t *output, size_t output_length) {
    const int status = output_status(output, output_length);
    if (status != ABC_KECCAK_C_OK) {
        return status;
    }
    abc_sha3_256_c_context context;
    abc_sha3_256_c_init(&context);
    const int absorbed = abc_sha3_256_c_update(&context, input, length);
    return absorbed != ABC_KECCAK_C_OK ? absorbed : abc_sha3_256_c_digest(&context, output, output_length);
}
