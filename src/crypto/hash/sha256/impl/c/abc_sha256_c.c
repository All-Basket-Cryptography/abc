#include "abc_sha256_c.h"

#include "Hacl_Hash_SHA2.h"
#include "internal/Hacl_Streaming_Types.h"

#include <string.h>

int abc_sha256_c_new(abc_sha256_c_context **context)
{
    if (context == NULL) {
        return ABC_SHA256_C_INVALID_ARGUMENT;
    }
    abc_sha256_c_context *state = Hacl_Hash_SHA2_malloc_256();
    if (state == NULL) {
        return ABC_SHA256_C_OUT_OF_MEMORY;
    }
    *context = state;
    return ABC_SHA256_C_OK;
}

int abc_sha256_c_update(abc_sha256_c_context *context, const uint8_t *input, size_t length)
{
    if (context == NULL || (length != 0 && input == NULL)) {
        return ABC_SHA256_C_INVALID_ARGUMENT;
    }
    if ((uintmax_t)length > ABC_SHA256_C_MAX_MESSAGE_BYTES - context->total_len) {
        return ABC_SHA256_C_MESSAGE_TOO_LONG;
    }

    while (length != 0) {
        uint32_t chunk = length > UINT32_MAX ? UINT32_MAX : (uint32_t)length;
        /* These pinned HACL* functions read input despite their mutable C pointer type. */
        if (Hacl_Hash_SHA2_update_256(context, (uint8_t *)input, chunk) != Hacl_Streaming_Types_Success) {
            return ABC_SHA256_C_BACKEND_ERROR;
        }
        input += chunk;
        length -= chunk;
    }
    return ABC_SHA256_C_OK;
}

int abc_sha256_c_digest(abc_sha256_c_context *context,
                        uint8_t output[ABC_SHA256_C_DIGEST_BYTES])
{
    if (context == NULL || output == NULL) {
        return ABC_SHA256_C_INVALID_ARGUMENT;
    }
    Hacl_Hash_SHA2_digest_256(context, output);
    return ABC_SHA256_C_OK;
}

int abc_sha256_c_hash(const uint8_t *input, size_t length,
                      uint8_t output[ABC_SHA256_C_DIGEST_BYTES])
{
    if (output == NULL || (length != 0 && input == NULL)) {
        return ABC_SHA256_C_INVALID_ARGUMENT;
    }
    if ((uintmax_t)length > ABC_SHA256_C_MAX_MESSAGE_BYTES) {
        return ABC_SHA256_C_MESSAGE_TOO_LONG;
    }

    uint8_t digest[ABC_SHA256_C_DIGEST_BYTES];
    if (length <= UINT32_MAX) {
        uint8_t empty = 0;
        Hacl_Hash_SHA2_hash_256(digest, input ? (uint8_t *)input : &empty, (uint32_t)length);
    } else {
        abc_sha256_c_context *context;
        int status = abc_sha256_c_new(&context);
        if (status != ABC_SHA256_C_OK) {
            return status;
        }
        status = abc_sha256_c_update(context, input, length);
        if (status == ABC_SHA256_C_OK) {
            Hacl_Hash_SHA2_digest_256(context, digest);
        }
        abc_sha256_c_free(context);
        if (status != ABC_SHA256_C_OK) {
            return status;
        }
    }
    memcpy(output, digest, sizeof digest);
    return ABC_SHA256_C_OK;
}

void abc_sha256_c_free(abc_sha256_c_context *context)
{
    if (context != NULL) {
        Hacl_Hash_SHA2_free_256(context);
    }
}
