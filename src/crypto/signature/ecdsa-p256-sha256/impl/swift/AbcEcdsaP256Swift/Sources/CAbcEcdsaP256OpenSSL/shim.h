#pragma once
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdint.h>
#include <string.h>

static inline EVP_PKEY *abc_p256_private(const uint8_t *scalar)
{
    uint8_t der[51] = {0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20};
    const uint8_t tail[12] = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
    memcpy(der + 7, scalar, 32);
    memcpy(der + 39, tail, sizeof(tail));
    const unsigned char *cursor = der;
    EVP_PKEY *key = d2i_AutoPrivateKey_ex(NULL, &cursor, sizeof(der), NULL, "provider=default");
    OPENSSL_cleanse(der, sizeof(der));
    return key;
}

static inline int abc_p256_public(const uint8_t *scalar, uint8_t *output)
{
    EVP_PKEY *key = abc_p256_private(scalar);
    size_t length = 0;
    int ok = key && EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, output, 65, &length) == 1
        && length == 65 && output[0] == 4;
    EVP_PKEY_free(key);
    return ok;
}

static inline int abc_p256_sign(const uint8_t *scalar, const uint8_t *message, size_t length, uint8_t *out)
{
    EVP_PKEY *key = abc_p256_private(scalar);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int deterministic = 1;
    const uint8_t empty = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &deterministic),
        OSSL_PARAM_construct_end()
    };
    unsigned char der[72];
    size_t der_len = sizeof(der);
    int ok = key && ctx && EVP_DigestSignInit_ex(ctx, NULL, "SHA256", NULL, "provider=default", key, params) == 1
        && EVP_DigestSign(ctx, der, &der_len, message ? message : &empty, length) == 1;
    const unsigned char *cursor = der;
    ECDSA_SIG *sig = ok ? d2i_ECDSA_SIG(NULL, &cursor, (long)der_len) : NULL;
    const BIGNUM *r = NULL, *s = NULL;
    if (sig) ECDSA_SIG_get0(sig, &r, &s);
    ok = sig && cursor == der + der_len && BN_bn2binpad(r, out, 32) == 32 && BN_bn2binpad(s, out + 32, 32) == 32;
    ECDSA_SIG_free(sig);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static inline int abc_p256_verify(const uint8_t *pub, size_t pub_len, const uint8_t *msg, size_t length,
    const uint8_t *signature)
{
    char group[] = "prime256v1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pub, pub_len),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY_CTX *import = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=default");
    EVP_PKEY *key = NULL;
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(signature, 32, NULL), *s = BN_bin2bn(signature + 32, 32, NULL);
    int have_sig = sig && r && s && ECDSA_SIG_set0(sig, r, s) == 1;
    if (!have_sig) { BN_free(r); BN_free(s); }
    unsigned char wire[72], *next = wire;
    int der_len = have_sig ? i2d_ECDSA_SIG(sig, &next) : -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const uint8_t empty = 0;
    int ok = der_len > 0 && import && EVP_PKEY_fromdata_init(import) == 1 &&
        EVP_PKEY_fromdata(import, &key, EVP_PKEY_PUBLIC_KEY, params) == 1 && ctx &&
        EVP_DigestVerifyInit_ex(ctx, NULL, "SHA256", NULL, "provider=default", key, NULL) == 1 &&
        EVP_DigestVerify(ctx, wire, (size_t)der_len, msg ? msg : &empty, length) == 1;
    EVP_MD_CTX_free(ctx);
    ECDSA_SIG_free(sig);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(import);
    return ok;
}
