#include "ml_kem_768.h"

#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <string.h>

#ifdef ABC_ML_KEM_768_TESTING
#include "test_seeds.h"
#include <openssl/experimental/kem_deterministic_api.h>
#endif

static int provider_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **key, const uint8_t *seed)
{
#ifdef ABC_ML_KEM_768_TESTING
    if (seed != NULL) {
        size_t length = ABC_ML_KEM_768_SEED_BYTES;
        return EVP_PKEY_keygen_deterministic(ctx, key, seed, &length);
    }
#else
    (void)seed;
#endif
    return EVP_PKEY_keygen(ctx, key);
}

static abc_ml_kem_768_status keygen(abc_ml_kem_768_keypair *result, const uint8_t *seed)
{
    if (result == NULL) {
        return ABC_ML_KEM_768_INVALID_ARGUMENT;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, NULL);
    if (ctx == NULL) {
        return ABC_ML_KEM_768_PROVIDER_ERROR;
    }
    EVP_PKEY *key = NULL;
    abc_ml_kem_768_keypair pending;
    size_t ek_len = sizeof(pending.ek), dk_len = sizeof(pending.dk);
    abc_ml_kem_768_status status = ABC_ML_KEM_768_PROVIDER_ERROR;
    if (EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_CTX_kem_set_params(ctx, NID_MLKEM768) == 1 &&
        provider_keygen(ctx, &key, seed) == 1 &&
        EVP_PKEY_get_raw_public_key(key, pending.ek, &ek_len) == 1 &&
        EVP_PKEY_get_raw_private_key(key, pending.dk, &dk_len) == 1 &&
        ek_len == sizeof(pending.ek) && dk_len == sizeof(pending.dk)) {
        *result = pending;
        status = ABC_ML_KEM_768_OK;
    }
    OPENSSL_cleanse(&pending, sizeof(pending));
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return status;
}

static int provider_encapsulate(EVP_PKEY_CTX *ctx, abc_ml_kem_768_encapsulation *pending,
    size_t *ct_len, size_t *shared_len, const uint8_t *message)
{
#ifdef ABC_ML_KEM_768_TESTING
    if (message != NULL) {
        size_t length = ABC_ML_KEM_768_MESSAGE_BYTES;
        return EVP_PKEY_encapsulate_deterministic(ctx, pending->ciphertext, ct_len,
            pending->shared, shared_len, message, &length);
    }
#else
    (void)message;
#endif
    return EVP_PKEY_encapsulate(ctx, pending->ciphertext, ct_len, pending->shared, shared_len);
}

static abc_ml_kem_768_status encapsulate(
    const uint8_t *ek, size_t ek_len, abc_ml_kem_768_encapsulation *result, const uint8_t *message)
{
    if (ek == NULL || ek_len != ABC_ML_KEM_768_EK_BYTES || result == NULL) {
        return ABC_ML_KEM_768_INVALID_ARGUMENT;
    }
    EVP_PKEY *key = EVP_PKEY_kem_new_raw_public_key(NID_MLKEM768, ek, ek_len);
    if (key == NULL) {
        return ABC_ML_KEM_768_PROVIDER_ERROR;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    abc_ml_kem_768_encapsulation pending;
    size_t ct_len = sizeof(pending.ciphertext), shared_len = sizeof(pending.shared);
    abc_ml_kem_768_status status = ABC_ML_KEM_768_PROVIDER_ERROR;
    if (ctx != NULL && provider_encapsulate(ctx, &pending, &ct_len, &shared_len, message) == 1 &&
        ct_len == sizeof(pending.ciphertext) && shared_len == sizeof(pending.shared)) {
        *result = pending;
        status = ABC_ML_KEM_768_OK;
    }
    OPENSSL_cleanse(&pending, sizeof(pending));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return status;
}

abc_ml_kem_768_status abc_ml_kem_768_keygen(abc_ml_kem_768_keypair *result)
{
    return keygen(result, NULL);
}

abc_ml_kem_768_status abc_ml_kem_768_encapsulate(
    const uint8_t *ek, size_t ek_len, abc_ml_kem_768_encapsulation *result)
{
    return encapsulate(ek, ek_len, result, NULL);
}

abc_ml_kem_768_status abc_ml_kem_768_decapsulate(
    const uint8_t *dk, size_t dk_len, const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *result, size_t result_len)
{
    if (dk == NULL || dk_len != ABC_ML_KEM_768_DK_BYTES || ciphertext == NULL ||
        ciphertext_len != ABC_ML_KEM_768_CT_BYTES || result == NULL ||
        result_len != ABC_ML_KEM_768_SHARED_BYTES) {
        return ABC_ML_KEM_768_INVALID_ARGUMENT;
    }
    EVP_PKEY *key = EVP_PKEY_kem_new_raw_secret_key(NID_MLKEM768, dk, dk_len);
    if (key == NULL) {
        return ABC_ML_KEM_768_PROVIDER_ERROR;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    uint8_t pending[ABC_ML_KEM_768_SHARED_BYTES];
    size_t shared_len = sizeof(pending);
    abc_ml_kem_768_status status = ABC_ML_KEM_768_PROVIDER_ERROR;
    if (ctx != NULL && EVP_PKEY_decapsulate(ctx, pending, &shared_len, ciphertext, ciphertext_len) == 1 &&
        shared_len == sizeof(pending)) {
        memcpy(result, pending, shared_len);
        status = ABC_ML_KEM_768_OK;
    }
    OPENSSL_cleanse(pending, sizeof(pending));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return status;
}

#ifdef ABC_ML_KEM_768_TESTING
abc_ml_kem_768_status abc_ml_kem_768_keygen_fixture(
    const uint8_t seed[ABC_ML_KEM_768_SEED_BYTES], abc_ml_kem_768_keypair *result)
{
    return seed == NULL ? ABC_ML_KEM_768_INVALID_ARGUMENT : keygen(result, seed);
}

abc_ml_kem_768_status abc_ml_kem_768_encapsulate_fixture(
    const uint8_t *ek, size_t ek_len, const uint8_t message[ABC_ML_KEM_768_MESSAGE_BYTES],
    abc_ml_kem_768_encapsulation *result)
{
    return message == NULL ? ABC_ML_KEM_768_INVALID_ARGUMENT : encapsulate(ek, ek_len, result, message);
}
#endif
