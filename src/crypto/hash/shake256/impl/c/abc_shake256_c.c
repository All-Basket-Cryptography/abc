#include "abc_shake256_c.h"

int abc_shake256_c_init(abc_shake256_c_context *context) {
    return abc_keccak_c_init(context);
}

int abc_shake256_c_update(abc_shake256_c_context *context, const uint8_t *input, size_t length) {
    return abc_keccak_c_absorb(context, input, length);
}

int abc_shake256_c_finalize(const abc_shake256_c_context *context, abc_shake256_c_reader *reader) {
    return abc_keccak_c_finish(context, ABC_KECCAK_C_SHAKE, reader);
}

int abc_shake256_c_read(abc_shake256_c_reader *reader, uint8_t *output, size_t length) {
    return abc_keccak_c_read(reader, output, length);
}

int abc_shake256_c_xof(const uint8_t *input, size_t input_length, uint8_t *output, size_t output_length) {
    if (output == NULL && output_length != 0) {
        return ABC_KECCAK_C_INVALID_ARGUMENT;
    }
    abc_shake256_c_context context;
    abc_shake256_c_init(&context);
    const int absorbed = abc_shake256_c_update(&context, input, input_length);
    if (absorbed != ABC_KECCAK_C_OK) {
        return absorbed;
    }
    abc_shake256_c_reader reader;
    abc_shake256_c_finalize(&context, &reader);
    return abc_shake256_c_read(&reader, output, output_length);
}
