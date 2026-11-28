#include "abc_pbkdf2_sha256_c.h"

#include <stdlib.h>
#include <string.h>

static int first_round(const uint8_t *password, size_t password_length,
                       const uint8_t *salt, size_t salt_length,
                       uint32_t block_index, uint8_t digest[ABC_HMAC_SHA256_C_TAG_BYTES])
{
    const uint8_t index[4] = {
        (uint8_t)(block_index >> 24), (uint8_t)(block_index >> 16),
        (uint8_t)(block_index >> 8), (uint8_t)block_index
    };
    abc_hmac_sha256_c_context *context = NULL;
    int status = abc_hmac_sha256_c_new(password, password_length, &context);
    if (status == ABC_PBKDF2_SHA256_C_OK) {
        status = abc_hmac_sha256_c_update(context, salt, salt_length);
    }
    if (status == ABC_PBKDF2_SHA256_C_OK) {
        status = abc_hmac_sha256_c_update(context, index, sizeof(index));
    }
    if (status == ABC_PBKDF2_SHA256_C_OK) {
        status = abc_hmac_sha256_c_digest(context, digest, ABC_HMAC_SHA256_C_TAG_BYTES);
    }
    abc_hmac_sha256_c_free(context);
    return status;
}

static int derive_block(const uint8_t *password, size_t password_length,
                        const uint8_t *salt, size_t salt_length, uint32_t iterations,
                        uint32_t block_index, uint8_t block[ABC_HMAC_SHA256_C_TAG_BYTES])
{
    uint8_t digest[ABC_HMAC_SHA256_C_TAG_BYTES];
    int status = first_round(password, password_length, salt, salt_length, block_index, digest);
    if (status != ABC_PBKDF2_SHA256_C_OK) {
        return status;
    }
    memcpy(block, digest, sizeof(digest));
    for (uint32_t round = 1; round < iterations; ++round) {
        status = abc_hmac_sha256_c_authenticate(
            password, password_length, digest, sizeof(digest), digest, sizeof(digest));
        if (status != ABC_PBKDF2_SHA256_C_OK) {
            return status;
        }
        for (size_t index = 0; index < sizeof(digest); ++index) {
            block[index] ^= digest[index];
        }
    }
    return ABC_PBKDF2_SHA256_C_OK;
}

int abc_pbkdf2_sha256_c_derive(const uint8_t *password, size_t password_length,
                              const uint8_t *salt, size_t salt_length, uint32_t iterations,
                              uint8_t *output, size_t output_length)
{
    if (output == NULL || (password == NULL && password_length != 0) ||
        (salt == NULL && salt_length != 0)) {
        return ABC_PBKDF2_SHA256_C_INVALID_ARGUMENT;
    }
    if (iterations == 0) {
        return ABC_PBKDF2_SHA256_C_INVALID_ITERATIONS;
    }
    if (output_length == 0 || (uintmax_t)output_length > ABC_PBKDF2_SHA256_C_MAX_OUTPUT_BYTES) {
        return ABC_PBKDF2_SHA256_C_INVALID_OUTPUT_LENGTH;
    }
    if ((uintmax_t)password_length > ABC_HMAC_SHA256_C_MAX_KEY_BYTES ||
        (uintmax_t)salt_length > ABC_PBKDF2_SHA256_C_MAX_SALT_BYTES) {
        return ABC_PBKDF2_SHA256_C_LENGTH_LIMIT;
    }
    uint8_t *staged = malloc(output_length);
    if (staged == NULL) {
        return ABC_PBKDF2_SHA256_C_OUT_OF_MEMORY;
    }
    uint8_t block[ABC_HMAC_SHA256_C_TAG_BYTES];
    size_t offset = 0;
    while (offset < output_length) {
        const uint32_t block_index = (uint32_t)(offset / sizeof(block) + 1);
        int status = derive_block(password, password_length, salt, salt_length, iterations, block_index, block);
        if (status != ABC_PBKDF2_SHA256_C_OK) {
            free(staged);
            return status;
        }
        size_t count = output_length - offset;
        if (count > sizeof(block)) {
            count = sizeof(block);
        }
        memcpy(staged + offset, block, count);
        offset += count;
    }
    memcpy(output, staged, output_length);
    free(staged);
    return ABC_PBKDF2_SHA256_C_OK;
}
