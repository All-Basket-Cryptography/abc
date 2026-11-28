#pragma once
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
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

/* Return 1 for a signature, 2 if RFC 6979 must advance its state, or 0 on a provider error. */
static inline int abc_p256_sign_candidate(const uint8_t *scalar, const uint8_t *digest,
    const uint8_t *nonce, uint8_t *out)
{
    EVP_PKEY *key = abc_p256_private(scalar);
    EC_KEY *ec = key ? EVP_PKEY_get1_EC_KEY(key) : NULL;
    const EC_GROUP *group = ec ? EC_KEY_get0_group(ec) : NULL;
    const BIGNUM *order = group ? EC_GROUP_get0_order(group) : NULL;
    BN_CTX *ctx = BN_CTX_secure_new();
    BIGNUM *k = BN_secure_new(), *inverse = BN_secure_new(), *r = BN_secure_new(), *x = BN_secure_new();
    BIGNUM *exponent = order ? BN_dup(order) : NULL;
    EC_POINT *point = group ? EC_POINT_new(group) : NULL;
    ECDSA_SIG *sig = NULL;
    int status = 0;
    if (!ctx || !k || !inverse || !r || !x || !point || !order || !exponent ||
        !BN_bin2bn(nonce, 32, k) || !BN_sub_word(exponent, 2)) goto end;
    BN_set_flags(k, BN_FLG_CONSTTIME);
    BN_set_flags(inverse, BN_FLG_CONSTTIME);
    if (BN_is_zero(k) || BN_cmp(k, order) >= 0) {
        status = 2;
        goto end;
    }
    if (EC_POINT_mul(group, point, k, NULL, NULL, ctx) != 1 ||
        EC_POINT_get_affine_coordinates(group, point, x, NULL, ctx) != 1 ||
        BN_nnmod(r, x, order, ctx) != 1) goto end;
    if (BN_is_zero(r)) {
        status = 2;
        goto end;
    }
    // The fixed prime order permits Fermat inversion with a public exponent.
    if (BN_mod_exp_mont_consttime(inverse, k, exponent, order, ctx, NULL) != 1) goto end;

    /* The library reports s=0 explicitly when supplied with k's inverse and r. */
    int marked = ERR_set_mark();
    sig = ECDSA_do_sign_ex(digest, 32, inverse, r, ec);
    unsigned long error = ERR_peek_last_error();
    if (marked) ERR_pop_to_mark();
    else ERR_clear_error();
    if (!sig) {
        if (ERR_GET_LIB(error) == ERR_LIB_EC && ERR_GET_REASON(error) == EC_R_NEED_NEW_SETUP_VALUES)
            status = 2;
        goto end;
    }
    const BIGNUM *rr = NULL, *ss = NULL;
    ECDSA_SIG_get0(sig, &rr, &ss);
    uint8_t pending[64];
    if (BN_bn2binpad(rr, pending, 32) == 32 && BN_bn2binpad(ss, pending + 32, 32) == 32) {
        memcpy(out, pending, sizeof(pending));
        status = 1;
    }
end:
    ECDSA_SIG_free(sig);
    EC_POINT_clear_free(point);
    BN_free(exponent);
    BN_clear_free(x);
    BN_clear_free(r);
    BN_clear_free(inverse);
    BN_clear_free(k);
    BN_CTX_free(ctx);
    EC_KEY_free(ec);
    EVP_PKEY_free(key);
    return status;
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
