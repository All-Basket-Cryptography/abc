#include "abc_ed25519_c.h"

#include <openssl/evp.h>
#include <string.h>

/* Distinct y-coordinates of the eight points in the cofactor subgroup.
 * Masking the x sign rejects both representatives when both exist. */
static const uint8_t torsion_y[5][32] = {
    {0},
    {1},
    {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
     0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
    {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
     0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
};

static int strong_encoding(const uint8_t encoded[32]) {
    uint8_t y[32];
    memcpy(y, encoded, sizeof y);
    y[31] &= 0x7f;
    /* First compare the high bytes with their maxima, then compare byte zero. */
    uint8_t high_difference = y[31] ^ 0x7f;
    for (size_t i = 1; i < 31; ++i) {
        high_difference |= y[i] ^ 0xff;
    }
    if (high_difference == 0 && y[0] >= 0xed) {
        return 0;
    }
    for (size_t i = 0; i < sizeof torsion_y / sizeof torsion_y[0]; ++i) {
        if (memcmp(y, torsion_y[i], sizeof y) == 0) return 0;
    }
    return 1;
}

static EVP_PKEY *private_key(const uint8_t seed[32]) {
    return EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", "provider=default", seed, 32);
}

int abc_ed25519_c_public_key(const uint8_t seed[32], uint8_t public_key[32]) {
    if (seed == NULL || public_key == NULL) return ABC_ED25519_C_INVALID_ARGUMENT;
    EVP_PKEY *key = private_key(seed);
    if (key == NULL) return ABC_ED25519_C_PROVIDER_FAILURE;
    uint8_t staged[32];
    size_t written = sizeof staged;
    const int result = EVP_PKEY_get_raw_public_key(key, staged, &written);
    EVP_PKEY_free(key);
    if (result != 1 || written != sizeof staged) return ABC_ED25519_C_PROVIDER_FAILURE;
    memcpy(public_key, staged, written);
    return ABC_ED25519_C_OK;
}

int abc_ed25519_c_sign(const uint8_t seed[32], const uint8_t *message, size_t length, uint8_t signature[64]) {
    if (seed == NULL || signature == NULL || (message == NULL && length != 0)) {
        return ABC_ED25519_C_INVALID_ARGUMENT;
    }
    static const uint8_t empty = 0;
    EVP_PKEY *key = private_key(seed);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    uint8_t staged[64];
    size_t written = sizeof staged;
    int status = ABC_ED25519_C_PROVIDER_FAILURE;
    if (key != NULL && context != NULL
        && EVP_DigestSignInit_ex(context, NULL, NULL, NULL, "provider=default", key, NULL) == 1
        && EVP_DigestSign(context, staged, &written, length == 0 ? &empty : message, length) == 1
        && written == sizeof staged) {
        memcpy(signature, staged, written);
        status = ABC_ED25519_C_OK;
    }
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return status;
}

int abc_ed25519_c_verify_strict(const uint8_t public_key[32], const uint8_t *message, size_t length,
                                const uint8_t signature[64]) {
    if (public_key == NULL || signature == NULL || (message == NULL && length != 0)) {
        return ABC_ED25519_C_INVALID_ARGUMENT;
    }
    if (!strong_encoding(public_key) || !strong_encoding(signature)) return ABC_ED25519_C_REJECTED;

    static const uint8_t empty = 0;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key_ex(NULL, "ED25519", "provider=default", public_key, 32);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int status = ABC_ED25519_C_PROVIDER_FAILURE;
    if (key != NULL && context != NULL
        && EVP_DigestVerifyInit_ex(context, NULL, NULL, NULL, "provider=default", key, NULL) == 1) {
        const int result = EVP_DigestVerify(context, signature, 64, length == 0 ? &empty : message, length);
        status = result == 1 ? ABC_ED25519_C_OK : result == 0 ? ABC_ED25519_C_REJECTED : ABC_ED25519_C_PROVIDER_FAILURE;
    }
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return status;
}
