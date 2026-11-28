#include "abc_hkdf_sha256_c.h"

#include <string.h>

int abc_hkdf_sha256_c_extract(const uint8_t *salt, size_t salt_length,
                             const uint8_t *ikm, size_t ikm_length,
                             uint8_t *prk, size_t prk_capacity)
{
    const uint8_t zero_salt[ABC_HKDF_SHA256_C_PRK_BYTES] = {0};
    if (salt_length == 0) {
        salt = zero_salt;
        salt_length = sizeof(zero_salt);
    }
    return abc_hmac_sha256_c_authenticate(salt, salt_length, ikm, ikm_length, prk, prk_capacity);
}

static int check_output(const uint8_t *info, size_t info_length,
                        const uint8_t *output, size_t output_length)
{
    if ((info == NULL && info_length != 0) || (output == NULL && output_length != 0)) {
        return ABC_HKDF_SHA256_C_INVALID_ARGUMENT;
    }
    if (output_length > ABC_HKDF_SHA256_C_MAX_OUTPUT_BYTES) {
        return ABC_HKDF_SHA256_C_OUTPUT_TOO_LONG;
    }
    if (output_length == 0) {
        return ABC_HKDF_SHA256_C_OK;
    }
    size_t overhead = 1;
    if (output_length > ABC_HKDF_SHA256_C_PRK_BYTES) {
        overhead += ABC_HKDF_SHA256_C_PRK_BYTES;
    }
    if (info_length > ABC_HMAC_SHA256_C_MAX_MESSAGE_BYTES - overhead) {
        return ABC_HKDF_SHA256_C_LENGTH_LIMIT;
    }
    return ABC_HKDF_SHA256_C_OK;
}

static int expand_block(const uint8_t *prk, size_t prk_length,
                        const uint8_t *info, size_t info_length,
                        uint8_t counter, uint8_t block[ABC_HKDF_SHA256_C_PRK_BYTES])
{
    abc_hmac_sha256_c_context *state = NULL;
    int status = abc_hmac_sha256_c_new(prk, prk_length, &state);
    if (status == ABC_HKDF_SHA256_C_OK && counter > 1) {
        status = abc_hmac_sha256_c_update(state, block, ABC_HKDF_SHA256_C_PRK_BYTES);
    }
    if (status == ABC_HKDF_SHA256_C_OK) {
        status = abc_hmac_sha256_c_update(state, info, info_length);
    }
    if (status == ABC_HKDF_SHA256_C_OK) {
        status = abc_hmac_sha256_c_update(state, &counter, sizeof(counter));
    }
    if (status == ABC_HKDF_SHA256_C_OK) {
        status = abc_hmac_sha256_c_digest(state, block, ABC_HKDF_SHA256_C_PRK_BYTES);
    }
    abc_hmac_sha256_c_free(state);
    return status;
}

int abc_hkdf_sha256_c_expand(const uint8_t *prk, size_t prk_length,
                            const uint8_t *info, size_t info_length,
                            uint8_t *output, size_t output_length)
{
    if (prk == NULL) {
        return ABC_HKDF_SHA256_C_INVALID_ARGUMENT;
    }
    if (prk_length < ABC_HKDF_SHA256_C_PRK_BYTES) {
        return ABC_HKDF_SHA256_C_PRK_TOO_SHORT;
    }
    if (prk_length > ABC_HMAC_SHA256_C_MAX_KEY_BYTES) {
        return ABC_HKDF_SHA256_C_LENGTH_LIMIT;
    }
    int status = check_output(info, info_length, output, output_length);
    if (status != ABC_HKDF_SHA256_C_OK || output_length == 0) {
        return status;
    }

    uint8_t staged[ABC_HKDF_SHA256_C_MAX_OUTPUT_BYTES];
    uint8_t block[ABC_HKDF_SHA256_C_PRK_BYTES];
    size_t offset = 0;
    size_t counter = 1;
    while (offset < output_length) {
        status = expand_block(prk, prk_length, info, info_length, (uint8_t)counter, block);
        if (status != ABC_HKDF_SHA256_C_OK) {
            return status;
        }
        size_t count = output_length - offset;
        if (count > sizeof(block)) {
            count = sizeof(block);
        }
        memcpy(staged + offset, block, count);
        offset += count;
        counter += 1;
    }
    memcpy(output, staged, output_length);
    return ABC_HKDF_SHA256_C_OK;
}

int abc_hkdf_sha256_c_derive(const uint8_t *salt, size_t salt_length,
                            const uint8_t *ikm, size_t ikm_length,
                            const uint8_t *info, size_t info_length,
                            uint8_t *output, size_t output_length)
{
    int status = check_output(info, info_length, output, output_length);
    if (status != ABC_HKDF_SHA256_C_OK) {
        return status;
    }
    uint8_t prk[ABC_HKDF_SHA256_C_PRK_BYTES];
    status = abc_hkdf_sha256_c_extract(salt, salt_length, ikm, ikm_length, prk, sizeof(prk));
    if (status != ABC_HKDF_SHA256_C_OK) {
        return status;
    }
    return abc_hkdf_sha256_c_expand(prk, sizeof(prk), info, info_length, output, output_length);
}
