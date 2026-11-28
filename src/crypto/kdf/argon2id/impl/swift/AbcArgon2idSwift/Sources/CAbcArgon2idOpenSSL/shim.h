#pragma once
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <stdint.h>

static inline int abc_argon2id(const void *password, size_t password_len, const void *salt, size_t salt_len,
    const void *secret, size_t secret_len, const void *ad, size_t ad_len,
    uint32_t memory, uint32_t passes, uint32_t lanes, unsigned char *out, size_t out_len)
{
    uint32_t version = 0x13, threads = 1;
    const unsigned char empty = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)(password ? password : &empty), password_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (void *)(secret ? secret : &empty), secret_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD, (void *)(ad ? ad : &empty), ad_len),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &passes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version),
        OSSL_PARAM_construct_end()
    };
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", "provider=default");
    EVP_KDF_CTX *ctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    int result = ctx && EVP_KDF_derive(ctx, out, out_len, params) == 1;
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return result;
}
