#pragma once
#include <openssl/evp.h>
#include <stdint.h>

static inline int abc_ed25519_sign(const void *seed, const void *message, size_t length, void *output)
{
    const uint8_t empty = 0;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", "provider=default", seed, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t written = 64;
    int ok = key && ctx && EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, "provider=default", key, NULL) == 1 &&
        EVP_DigestSign(ctx, output, &written, message ? message : &empty, length) == 1 && written == 64;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}
