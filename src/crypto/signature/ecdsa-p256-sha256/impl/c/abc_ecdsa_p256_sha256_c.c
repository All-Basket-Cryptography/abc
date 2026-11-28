#include "abc_ecdsa_p256_sha256_c.h"
#include "ecdsa_p256_nonce.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

typedef struct { uint8_t k[32]; uint8_t v[32]; } nonce_state;

static int sha256(const uint8_t *message, size_t length, uint8_t output[32]) {
    static const uint8_t empty = 0;
    size_t written = 0;
    return EVP_Q_digest(NULL, "SHA256", "provider=default", length == 0 ? &empty : message,
                        length, output, &written) == 1 && written == 32;
}

static int hmac_into(const uint8_t key[32], const uint8_t *message, size_t length, uint8_t dest[32]) {
    uint8_t staged[32];
    size_t written = 0;
    const int result = EVP_Q_mac(NULL, "HMAC", "provider=default", "SHA256", NULL, key, 32,
                                 message, length, staged, sizeof staged, &written) != NULL && written == sizeof staged;
    if (result) memcpy(dest, staged, sizeof staged);
    OPENSSL_cleanse(staged, sizeof staged);
    return result;
}

static int advance(nonce_state *state) {
    return hmac_into(state->k, state->v, sizeof state->v, state->v);
}

static int initialize(nonce_state *state, const uint8_t scalar[32], const uint8_t digest[32]) {
    memset(state->k, 0, sizeof state->k);
    memset(state->v, 1, sizeof state->v);
    uint8_t input[97];
    memcpy(input + 33, scalar, 32);
    abc_p256_c_reduce_digest(digest, input + 65);
    int result = 1;
    for (uint8_t marker = 0; marker < 2 && result; ++marker) {
        memcpy(input, state->v, 32);
        input[32] = marker;
        result = hmac_into(state->k, input, sizeof input, state->k) && advance(state);
    }
    OPENSSL_cleanse(input, sizeof input);
    return result;
}

static int reject(nonce_state *state) {
    uint8_t input[33];
    memcpy(input, state->v, 32);
    input[32] = 0;
    const int result = hmac_into(state->k, input, sizeof input, state->k) && advance(state);
    OPENSSL_cleanse(input, sizeof input);
    return result;
}

int abc_ecdsa_p256_sha256_c_public_key(const uint8_t scalar[32], uint8_t public_key[65]) {
    return abc_p256_c_public_point(scalar, public_key);
}

int abc_ecdsa_p256_sha256_c_sign(const uint8_t scalar[32], const uint8_t *message,
                                 size_t length, uint8_t signature[64]) {
    if (scalar == NULL || signature == NULL || (message == NULL && length != 0) || !abc_p256_c_scalar_in_range(scalar)) {
        return ABC_P256_C_INVALID_ARGUMENT;
    }
    nonce_state state;
    uint8_t digest[32];
    int status = ABC_P256_C_PROVIDER_FAILURE;
    if (!sha256(message, length, digest) || !initialize(&state, scalar, digest)) {
        goto done;
    }
    for (unsigned candidate = 0; candidate < 128; ++candidate) {
        if (!advance(&state)) {
            status = ABC_P256_C_PROVIDER_FAILURE;
            goto done;
        }
        status = abc_p256_c_sign_candidate(scalar, digest, state.v, signature);
        if (status != ABC_P256_C_RETRY) goto done;
        if (!reject(&state)) {
            status = ABC_P256_C_PROVIDER_FAILURE;
            goto done;
        }
    }
    status = ABC_P256_C_RETRY_EXHAUSTED;

done:
    OPENSSL_cleanse(&state, sizeof state);
    OPENSSL_cleanse(digest, sizeof digest);
    return status;
}

int abc_ecdsa_p256_sha256_c_verify(const uint8_t *public_key, size_t public_length,
    const uint8_t *message, size_t length, const uint8_t signature[64]) {
    if (public_key == NULL || signature == NULL || (message == NULL && length != 0)) {
        return ABC_P256_C_INVALID_ARGUMENT;
    }
    uint8_t digest[32];
    if (!sha256(message, length, digest)) {
        return ABC_P256_C_PROVIDER_FAILURE;
    }
    return abc_p256_c_verify_digest(public_key, public_length, digest, signature);
}

#ifdef ABC_ECDSA_P256_TEST_SUPPORT
ABC_P256_TEST_API int abc_p256_c_nonce_transcript(const uint8_t scalar[32], const uint8_t digest[32], uint8_t trace[64]) {
    nonce_state state;
    uint8_t first[32];
    int result = initialize(&state, scalar, digest) && advance(&state);
    if (result) {
        memcpy(first, state.v, sizeof first);
        result = reject(&state) && advance(&state);
    }
    if (result) {
        memcpy(trace, first, sizeof first);
        memcpy(trace + 32, state.v, sizeof state.v);
    }
    OPENSSL_cleanse(first, sizeof first);
    OPENSSL_cleanse(&state, sizeof state);
    return result ? ABC_P256_C_OK : ABC_P256_C_PROVIDER_FAILURE;
}
#endif
