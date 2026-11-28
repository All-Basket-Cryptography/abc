#include "abc_mldsa65_c.h"

#include "crypto/fipsmodule/ml_dsa/ml_dsa.h"
#include <openssl/mem.h>
#include <string.h>

_Static_assert(MLDSA65_KEYGEN_SEED_BYTES == ABC_MLDSA65_C_SEED_BYTES, "AWS-LC seed width");
_Static_assert(MLDSA65_PUBLIC_KEY_BYTES == ABC_MLDSA65_C_PUBLIC_KEY_BYTES, "AWS-LC public key width");
_Static_assert(MLDSA65_SIGNATURE_BYTES == ABC_MLDSA65_C_SIGNATURE_BYTES, "AWS-LC signature width");

static const uint8_t empty[1] = {0};

static int check_message(const uint8_t *message, size_t message_len,
                         const uint8_t *context, size_t context_len)
{
    if ((message == NULL && message_len != 0) || (context == NULL && context_len != 0)) {
        return ABC_MLDSA65_C_INVALID_ARGUMENT;
    }
    return context_len <= ABC_MLDSA65_C_MAX_CONTEXT_BYTES
        ? ABC_MLDSA65_C_OK : ABC_MLDSA65_C_INVALID_LENGTH;
}

int abc_mldsa65_c_public_key(const uint8_t *seed, size_t seed_len,
                           uint8_t *public_key, size_t capacity)
{
    if (seed == NULL || public_key == NULL) {
        return ABC_MLDSA65_C_INVALID_ARGUMENT;
    }
    if (seed_len != ABC_MLDSA65_C_SEED_BYTES || capacity < ABC_MLDSA65_C_PUBLIC_KEY_BYTES) {
        return ABC_MLDSA65_C_INVALID_LENGTH;
    }
    uint8_t expanded[MLDSA65_PRIVATE_KEY_BYTES];
    uint8_t staged[MLDSA65_PUBLIC_KEY_BYTES];
    int success = ml_dsa_65_keypair_internal(staged, expanded, seed);
    OPENSSL_cleanse(expanded, sizeof(expanded));
    if (success != 1) {
        return ABC_MLDSA65_C_BACKEND_ERROR;
    }
    memcpy(public_key, staged, sizeof(staged));
    return ABC_MLDSA65_C_OK;
}

static int sign_expanded(const uint8_t *expanded,
                         const uint8_t *message, size_t message_len,
                         const uint8_t *context, size_t context_len, uint8_t *signature)
{
    const uint8_t randomness[MLDSA65_SIGNATURE_SEED_BYTES] = {0};
    // FIPS 204 Algorithm 2 frames Pure ML-DSA messages as 00 || len(ctx) || ctx || M.
    uint8_t prefix[2 + ABC_MLDSA65_C_MAX_CONTEXT_BYTES] = {0, (uint8_t)context_len};
    if (context_len != 0) {
        memcpy(prefix + 2, context, context_len);
    }
    uint8_t staged[MLDSA65_SIGNATURE_BYTES];
    size_t length = sizeof(staged);
    int success = ml_dsa_65_sign_internal(expanded, staged, &length, message ? message : empty,
                                         message_len, prefix, 2 + context_len, randomness);
    if (success != 1 || length != sizeof(staged)) {
        return ABC_MLDSA65_C_BACKEND_ERROR;
    }
    memcpy(signature, staged, sizeof(staged));
    return ABC_MLDSA65_C_OK;
}

int abc_mldsa65_c_sign(const uint8_t *seed, size_t seed_len,
                     const uint8_t *message, size_t message_len,
                     const uint8_t *context, size_t context_len, uint8_t *signature, size_t capacity)
{
    int status = check_message(message, message_len, context, context_len);
    if (status != ABC_MLDSA65_C_OK) {
        return status;
    }
    if (seed == NULL || signature == NULL) {
        return ABC_MLDSA65_C_INVALID_ARGUMENT;
    }
    if (seed_len != ABC_MLDSA65_C_SEED_BYTES || capacity < ABC_MLDSA65_C_SIGNATURE_BYTES) {
        return ABC_MLDSA65_C_INVALID_LENGTH;
    }
    uint8_t expanded[MLDSA65_PRIVATE_KEY_BYTES];
    uint8_t public_key[MLDSA65_PUBLIC_KEY_BYTES];
    status = ABC_MLDSA65_C_BACKEND_ERROR;
    if (ml_dsa_65_keypair_internal(public_key, expanded, seed) == 1) {
        status = sign_expanded(expanded, message, message_len, context, context_len, signature);
    }
    OPENSSL_cleanse(expanded, sizeof(expanded));
    return status;
}

int abc_mldsa65_c_verify(const uint8_t *public_key, size_t public_key_len,
                       const uint8_t *message, size_t message_len,
                       const uint8_t *context, size_t context_len,
                       const uint8_t *signature, size_t signature_len)
{
    int status = check_message(message, message_len, context, context_len);
    if (status != ABC_MLDSA65_C_OK) {
        return status;
    }
    if (public_key == NULL || signature == NULL) {
        return ABC_MLDSA65_C_INVALID_ARGUMENT;
    }
    if (public_key_len != ABC_MLDSA65_C_PUBLIC_KEY_BYTES || signature_len != ABC_MLDSA65_C_SIGNATURE_BYTES) {
        return ABC_MLDSA65_C_INVALID_LENGTH;
    }
    return ml_dsa_65_verify(public_key, signature, signature_len, message ? message : empty,
                           message_len, context ? context : empty, context_len) == 1
        ? ABC_MLDSA65_C_OK : ABC_MLDSA65_C_VERIFICATION_FAILED;
}

#ifdef ABC_MLDSA65_C_TEST_SUPPORT
/* The pinned ACVP sigGen cases supply trusted expanded test keys. */
ABC_MLDSA65_C_API int abc_mldsa65_c_sign_expanded_for_test(
    const uint8_t *expanded, const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len, uint8_t *signature)
{
    int status = check_message(message, message_len, context, context_len);
    if (status != ABC_MLDSA65_C_OK) {
        return status;
    }
    return sign_expanded(expanded, message, message_len, context, context_len, signature);
}
#endif
