#include "abc_hmac_sha256_c.h"

#include <stdlib.h>
#include <string.h>

enum { KEY_BLOCK_BYTES = 64 };

struct abc_hmac_sha256_c_context {
    abc_sha256_c_context *inner;
    uint8_t outer_pad[KEY_BLOCK_BYTES];
};

int abc_hmac_sha256_c_new(const uint8_t *key, size_t key_length, abc_hmac_sha256_c_context **context)
{
    if (context == NULL || (key_length != 0 && key == NULL)) {
        return ABC_HMAC_SHA256_C_INVALID_ARGUMENT;
    }
    if ((uintmax_t)key_length > ABC_HMAC_SHA256_C_MAX_KEY_BYTES) {
        return ABC_HMAC_SHA256_C_LENGTH_LIMIT;
    }

    uint8_t key_block[KEY_BLOCK_BYTES] = {0};
    if (key_length > KEY_BLOCK_BYTES) {
        int status = abc_sha256_c_hash(key, key_length, key_block);
        if (status != ABC_HMAC_SHA256_C_OK) {
            return status;
        }
    } else if (key_length != 0) {
        memcpy(key_block, key, key_length);
    }

    abc_hmac_sha256_c_context *state = malloc(sizeof *state);
    if (state == NULL) {
        return ABC_HMAC_SHA256_C_OUT_OF_MEMORY;
    }
    int status = abc_sha256_c_new(&state->inner);
    if (status != ABC_HMAC_SHA256_C_OK) {
        free(state);
        return status;
    }
    for (size_t i = 0; i < sizeof key_block; ++i) {
        state->outer_pad[i] = key_block[i] ^ 0x5c;
        key_block[i] ^= 0x36;
    }
    status = abc_sha256_c_update(state->inner, key_block, sizeof key_block);
    if (status != ABC_HMAC_SHA256_C_OK) {
        abc_hmac_sha256_c_free(state);
        return status;
    }
    *context = state;
    return ABC_HMAC_SHA256_C_OK;
}

int abc_hmac_sha256_c_update(abc_hmac_sha256_c_context *context, const uint8_t *input, size_t length)
{
    if (context == NULL) {
        return ABC_HMAC_SHA256_C_INVALID_ARGUMENT;
    }
    return abc_sha256_c_update(context->inner, input, length);
}

int abc_hmac_sha256_c_digest(abc_hmac_sha256_c_context *context, uint8_t *output, size_t capacity)
{
    if (context == NULL || output == NULL) {
        return ABC_HMAC_SHA256_C_INVALID_ARGUMENT;
    }
    if (capacity < ABC_HMAC_SHA256_C_TAG_BYTES) {
        return ABC_HMAC_SHA256_C_OUTPUT_TOO_SHORT;
    }

    uint8_t outer_message[KEY_BLOCK_BYTES + ABC_HMAC_SHA256_C_TAG_BYTES];
    memcpy(outer_message, context->outer_pad, KEY_BLOCK_BYTES);
    int status = abc_sha256_c_digest(context->inner, outer_message + KEY_BLOCK_BYTES);
    if (status != ABC_HMAC_SHA256_C_OK) {
        return status;
    }
    return abc_sha256_c_hash(outer_message, sizeof outer_message, output);
}

int abc_hmac_sha256_c_authenticate(const uint8_t *key, size_t key_length,
                                 const uint8_t *input, size_t length, uint8_t *output, size_t capacity)
{
    if (output == NULL || (key_length != 0 && key == NULL) || (length != 0 && input == NULL)) {
        return ABC_HMAC_SHA256_C_INVALID_ARGUMENT;
    }
    if (capacity < ABC_HMAC_SHA256_C_TAG_BYTES) {
        return ABC_HMAC_SHA256_C_OUTPUT_TOO_SHORT;
    }
    if ((uintmax_t)key_length > ABC_HMAC_SHA256_C_MAX_KEY_BYTES ||
        (uintmax_t)length > ABC_HMAC_SHA256_C_MAX_MESSAGE_BYTES) {
        return ABC_HMAC_SHA256_C_LENGTH_LIMIT;
    }

    abc_hmac_sha256_c_context *context;
    int status = abc_hmac_sha256_c_new(key, key_length, &context);
    if (status != ABC_HMAC_SHA256_C_OK) {
        return status;
    }
    status = abc_hmac_sha256_c_update(context, input, length);
    if (status == ABC_HMAC_SHA256_C_OK) {
        status = abc_hmac_sha256_c_digest(context, output, capacity);
    }
    abc_hmac_sha256_c_free(context);
    return status;
}

void abc_hmac_sha256_c_free(abc_hmac_sha256_c_context *context)
{
    if (context != NULL) {
        abc_sha256_c_free(context->inner);
        free(context);
    }
}
