#pragma once
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <stdint.h>

static inline EVP_PKEY *abc_mlkem_seed(const void *seed)
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, (void *)seed, 64),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", "provider=default");
    EVP_PKEY *key = NULL;
    if (!(ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_CTX_set_params(ctx, params) == 1 &&
          EVP_PKEY_keygen(ctx, &key) == 1)) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static inline int abc_mlkem_random_seed(void *seed)
{
    return RAND_priv_bytes(seed, 64) == 1;
}

static inline int abc_mlkem_public(const void *seed, void *out)
{
    EVP_PKEY *key = abc_mlkem_seed(seed);
    size_t length = 0;
    int ok = key && EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, out, 1184, &length) == 1
        && length == 1184;
    EVP_PKEY_free(key);
    return ok;
}

static inline int abc_mlkem_encapsulate(const void *public_key, void *ciphertext, void *secret)
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)public_key, 1184),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY_CTX *import = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", "provider=default");
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    if (import && EVP_PKEY_fromdata_init(import) == 1 &&
        EVP_PKEY_fromdata(import, &key, EVP_PKEY_PUBLIC_KEY, params) == 1) {
        ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=default");
    }
    size_t ciphertext_len = 1088, secret_len = 32;
    int ok = ctx && EVP_PKEY_encapsulate_init(ctx, NULL) == 1 &&
        EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_len, secret, &secret_len) == 1 &&
        ciphertext_len == 1088 && secret_len == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(import);
    return ok;
}

static inline int abc_mlkem_decapsulate(const void *seed, const void *ciphertext, void *secret)
{
    EVP_PKEY *key = abc_mlkem_seed(seed);
    EVP_PKEY_CTX *ctx = key ? EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=default") : NULL;
    size_t length = 32;
    int ok = ctx && EVP_PKEY_decapsulate_init(ctx, NULL) == 1 &&
        EVP_PKEY_decapsulate(ctx, secret, &length, ciphertext, 1088) == 1 && length == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}
