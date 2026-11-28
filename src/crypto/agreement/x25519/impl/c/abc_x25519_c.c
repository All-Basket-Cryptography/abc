#include "abc_x25519_c.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

static int valid(const void *bytes, size_t length) {
    return bytes != NULL && length == ABC_X25519_C_BYTES;
}

int abc_x25519_c_public_key(const uint8_t *scalar, size_t scalar_length,
                           uint8_t *public_key, size_t output_length) {
    if (!valid(scalar, scalar_length) || !valid(public_key, output_length)) {
        return ABC_X25519_C_INVALID_LENGTH;
    }
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", "provider=default", scalar, scalar_length);
    if (key == NULL) {
        return ABC_X25519_C_PROVIDER_FAILURE;
    }
    uint8_t staged[ABC_X25519_C_BYTES];
    size_t written = sizeof staged;
    const int result = EVP_PKEY_get_raw_public_key(key, staged, &written);
    EVP_PKEY_free(key);
    if (result != 1 || written != sizeof staged) {
        return ABC_X25519_C_PROVIDER_FAILURE;
    }
    memcpy(public_key, staged, written);
    return ABC_X25519_C_OK;
}

int abc_x25519_c_shared_secret(const uint8_t *scalar, size_t scalar_length,
    const uint8_t *peer, size_t peer_length, uint8_t *secret, size_t output_length) {
    if (!valid(scalar, scalar_length) || !valid(peer, peer_length) || !valid(secret, output_length)) {
        return ABC_X25519_C_INVALID_LENGTH;
    }
    EVP_PKEY *local = EVP_PKEY_new_raw_private_key_ex(NULL, "X25519", "provider=default", scalar, scalar_length);
    EVP_PKEY *remote = EVP_PKEY_new_raw_public_key_ex(NULL, "X25519", "provider=default", peer, peer_length);
    EVP_PKEY_CTX *context = local == NULL ? NULL : EVP_PKEY_CTX_new_from_pkey(NULL, local, "provider=default");
    uint8_t staged[ABC_X25519_C_BYTES], zero[ABC_X25519_C_BYTES] = {0};
    size_t written = sizeof staged;
    int status = ABC_X25519_C_PROVIDER_FAILURE;
    if (context != NULL && remote != NULL && EVP_PKEY_derive_init(context) == 1) {
        if (EVP_PKEY_derive_set_peer(context, remote) != 1 || EVP_PKEY_derive(context, staged, &written) != 1) {
            status = ABC_X25519_C_INVALID_PEER;
        } else if (written == sizeof staged) {
            if (CRYPTO_memcmp(staged, zero, sizeof staged) == 0) {
                status = ABC_X25519_C_INVALID_PEER;
            } else {
                memcpy(secret, staged, written);
                status = ABC_X25519_C_OK;
            }
        }
    }
    OPENSSL_cleanse(staged, sizeof staged);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(remote);
    EVP_PKEY_free(local);
    return status;
}
