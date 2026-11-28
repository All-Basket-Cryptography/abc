#pragma once
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdint.h>

static inline EVP_PKEY *abc_mldsa_seed(const void *seed)
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, (void *)seed, 32),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", "provider=default");
    EVP_PKEY *key = NULL;
    if (!(ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_CTX_set_params(ctx, params) == 1 &&
          EVP_PKEY_keygen(ctx, &key) == 1)) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static inline int abc_mldsa_public(const void *seed, void *out)
{
    EVP_PKEY *key = abc_mldsa_seed(seed);
    size_t length = 0;
    int ok = key && EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, out, 1952, &length) == 1
        && length == 1952;
    EVP_PKEY_free(key);
    return ok;
}

static inline int abc_mldsa_sign(const void *seed, const void *message, size_t message_len,
    const void *context, size_t context_len, void *out)
{
    EVP_PKEY *key = abc_mldsa_seed(seed);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const uint8_t zero = 0;
    int deterministic = 1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic),
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)(context ? context : &zero),
            context_len),
        OSSL_PARAM_construct_end()
    };
    size_t length = 3309;
    int ok = key && ctx && EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, "provider=default", key, params) == 1 &&
        EVP_DigestSign(ctx, out, &length, message ? message : &zero, message_len) == 1 && length == 3309;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static inline int abc_mldsa_verify(const void *public_key, const void *message, size_t message_len,
    const void *context, size_t context_len, const void *signature)
{
    OSSL_PARAM public_params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)public_key, 1952),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY_CTX *import = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", "provider=default");
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const uint8_t zero = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)(context ? context : &zero),
            context_len),
        OSSL_PARAM_construct_end()
    };
    int ok = import && EVP_PKEY_fromdata_init(import) == 1 &&
        EVP_PKEY_fromdata(import, &key, EVP_PKEY_PUBLIC_KEY, public_params) == 1 && ctx &&
        EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, "provider=default", key, params) == 1 &&
        EVP_DigestVerify(ctx, signature, 3309, message ? message : &zero, message_len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(import);
    return ok;
}
