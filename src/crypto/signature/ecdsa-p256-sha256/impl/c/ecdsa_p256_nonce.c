#include "ecdsa_p256_nonce.h"

/* OpenSSL 3.5's EVP signer chooses its own nonce. The provider-backed EC
 * and ECDSA APIs below let the RFC 6979 state machine supply each candidate. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecerr.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#include <string.h>

static const uint8_t order_bytes[32] = {
    0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};

int abc_p256_c_scalar_in_range(const uint8_t scalar[32]) {
    uint32_t borrow = 0;
    uint8_t present = 0;
    for (size_t i = 32; i > 0; --i) {
        const uint32_t difference = (uint32_t)scalar[i - 1] - order_bytes[i - 1] - borrow;
        borrow = difference >> 31;
        present |= scalar[i - 1];
    }
    return (int)(borrow & (present != 0));
}

void abc_p256_c_reduce_digest(const uint8_t digest[32], uint8_t encoded[32]) {
    uint8_t reduced[32];
    uint32_t borrow = 0;
    for (size_t i = 32; i > 0; --i) {
        const uint32_t difference = (uint32_t)digest[i - 1] - order_bytes[i - 1] - borrow;
        reduced[i - 1] = (uint8_t)difference;
        borrow = difference >> 31;
    }
    const uint8_t keep = (uint8_t)(0u - borrow);
    for (size_t i = 0; i < 32; ++i) {
        encoded[i] = (digest[i] & keep) | (reduced[i] & (uint8_t)~keep);
    }
    OPENSSL_cleanse(reduced, sizeof reduced);
}

static BIGNUM *secret_integer(const uint8_t bytes[32]) {
    BIGNUM *result = BN_secure_new();
    if (result == NULL || BN_bin2bn(bytes, 32, result) == NULL) {
        BN_clear_free(result);
        return NULL;
    }
    BN_set_flags(result, BN_FLG_CONSTTIME);
    return result;
}

int abc_p256_c_public_point(const uint8_t scalar[32], uint8_t out[65]) {
    if (scalar == NULL || out == NULL || !abc_p256_c_scalar_in_range(scalar)) {
        return ABC_P256_C_INVALID_ARGUMENT;
    }
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *point = group == NULL ? NULL : EC_POINT_new(group);
    BIGNUM *d = secret_integer(scalar);
    uint8_t staged[65];
    int status = ABC_P256_C_PROVIDER_FAILURE;
    if (point != NULL && d != NULL && EC_POINT_mul(group, point, d, NULL, NULL, NULL) == 1
        && EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, staged, sizeof staged, NULL) == sizeof staged) {
        memcpy(out, staged, sizeof staged);
        status = ABC_P256_C_OK;
    }
    BN_clear_free(d);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return status;
}

int abc_p256_c_sign_candidate(const uint8_t scalar[32], const uint8_t digest[32],
                              const uint8_t nonce[32], uint8_t out[64]) {
    if (scalar == NULL || digest == NULL || nonce == NULL || out == NULL || !abc_p256_c_scalar_in_range(scalar)) {
        return ABC_P256_C_INVALID_ARGUMENT;
    }
    if (!abc_p256_c_scalar_in_range(nonce)) {
        return ABC_P256_C_RETRY;
    }

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP *group = key == NULL ? NULL : EC_KEY_get0_group(key);
    const BIGNUM *order = group == NULL ? NULL : EC_GROUP_get0_order(group);
    EC_POINT *point = group == NULL ? NULL : EC_POINT_new(group);
    BN_CTX *context = BN_CTX_secure_new();
    BIGNUM *d = secret_integer(scalar), *k = secret_integer(nonce);
    BIGNUM *r = BN_secure_new(), *inverse = BN_secure_new();
    BIGNUM *exponent = order == NULL ? NULL : BN_dup(order);
    int status = ABC_P256_C_PROVIDER_FAILURE;
    ECDSA_SIG *signature = NULL;
    uint8_t staged[64];
    if (point == NULL || context == NULL || d == NULL || k == NULL || r == NULL || inverse == NULL || exponent == NULL
        || EC_KEY_set_private_key(key, d) != 1 || EC_POINT_mul(group, point, k, NULL, NULL, context) != 1
        || EC_POINT_get_affine_coordinates(group, point, r, NULL, context) != 1 || BN_nnmod(r, r, order, context) != 1) {
        goto done;
    }
    if (BN_is_zero(r)) {
        status = ABC_P256_C_RETRY;
        goto done;
    }
    /* The group order is prime. Fermat inversion keeps the exponent fixed. */
    if (BN_sub_word(exponent, 2) != 1 || BN_mod_exp_mont_consttime(inverse, k, exponent, order, context, NULL) != 1) {
        goto done;
    }

    /* Supplying both precomputations prevents this call from choosing a nonce. */
    const unsigned long before = ERR_peek_last_error();
    const int marked = ERR_set_mark();
    signature = ECDSA_do_sign_ex(digest, 32, inverse, r, key);
    if (signature == NULL) {
        const unsigned long error = ERR_peek_last_error();
        if (error != 0 && ERR_GET_LIB(error) == ERR_LIB_EC && ERR_GET_REASON(error) == EC_R_NEED_NEW_SETUP_VALUES) {
            status = ABC_P256_C_RETRY;
        }
    }
    if (marked) {
        (void)ERR_pop_to_mark();
    } else if (before == 0) {
        ERR_clear_error();
    }
    if (signature != NULL) {
        const BIGNUM *actual_r, *s;
        ECDSA_SIG_get0(signature, &actual_r, &s);
        if (BN_bn2binpad(actual_r, staged, 32) == 32 && BN_bn2binpad(s, staged + 32, 32) == 32) {
            memcpy(out, staged, sizeof staged);
            status = ABC_P256_C_OK;
        }
    }

done:
    ECDSA_SIG_free(signature);
    BN_clear_free(inverse);
    BN_clear_free(r);
    BN_clear_free(k);
    BN_clear_free(d);
    BN_free(exponent);
    BN_CTX_free(context);
    EC_POINT_free(point);
    EC_KEY_free(key);
    return status;
}

int abc_p256_c_verify_digest(const uint8_t *point, size_t point_length, const uint8_t digest[32],
                             const uint8_t signature[64]) {
    if (point == NULL || digest == NULL || signature == NULL) {
        return ABC_P256_C_INVALID_ARGUMENT;
    }
    if (!((point_length == 33 && (point[0] == 2 || point[0] == 3)) || (point_length == 65 && point[0] == 4))
        || !abc_p256_c_scalar_in_range(signature) || !abc_p256_c_scalar_in_range(signature + 32)) {
        return ABC_P256_C_REJECTED;
    }
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_GROUP *group = key == NULL ? NULL : EC_KEY_get0_group(key);
    EC_POINT *pub = group == NULL ? NULL : EC_POINT_new(group);
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(signature, 32, NULL), *s = BN_bin2bn(signature + 32, 32, NULL);
    int status = ABC_P256_C_PROVIDER_FAILURE;
    if (pub == NULL || sig == NULL || r == NULL || s == NULL) {
        goto done;
    }
    if (EC_POINT_oct2point(group, pub, point, point_length, NULL) != 1 || EC_POINT_is_on_curve(group, pub, NULL) != 1
        || EC_POINT_is_at_infinity(group, pub) != 0) {
        status = ABC_P256_C_REJECTED;
        goto done;
    }
    if (EC_KEY_set_public_key(key, pub) != 1 || ECDSA_SIG_set0(sig, r, s) != 1) {
        goto done;
    }
    r = s = NULL;
    const int verified = ECDSA_do_verify(digest, 32, sig, key);
    status = verified == 1 ? ABC_P256_C_OK : verified == 0 ? ABC_P256_C_REJECTED : ABC_P256_C_PROVIDER_FAILURE;

done:
    BN_free(s);
    BN_free(r);
    ECDSA_SIG_free(sig);
    EC_POINT_free(pub);
    EC_KEY_free(key);
    return status;
}
