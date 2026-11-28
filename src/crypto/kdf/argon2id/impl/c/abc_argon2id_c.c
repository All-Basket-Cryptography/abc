#include "abc_argon2id_c.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <string.h>

static int valid_bytes(abc_argon2id_c_bytes bytes) {
    return bytes.size <= UINT32_MAX && (bytes.size == 0 || bytes.data != NULL);
}

static OSSL_PARAM octets(const char *name, abc_argon2id_c_bytes bytes) {
    return OSSL_PARAM_construct_octet_string(name, (void *)bytes.data, bytes.size);
}

int abc_argon2id_c_derive(abc_argon2id_c_parameters parameters,
    abc_argon2id_c_bytes password, abc_argon2id_c_bytes salt, abc_argon2id_c_bytes secret,
    abc_argon2id_c_bytes associated_data, size_t matrix_budget, uint8_t *tag, size_t tag_length) {
    if (parameters.passes == 0 || parameters.lanes == 0 || parameters.lanes >= (UINT32_C(1) << 24)
        || parameters.memory_kib < UINT64_C(8) * parameters.lanes) {
        return ABC_ARGON2ID_C_INVALID_PARAMETERS;
    }
    if (tag == NULL || tag_length < 4 || tag_length > UINT32_MAX || !valid_bytes(password)
        || !valid_bytes(salt) || salt.size < 8 || !valid_bytes(secret) || !valid_bytes(associated_data)) {
        return ABC_ARGON2ID_C_INVALID_BUFFER;
    }
    if (parameters.memory_kib > matrix_budget / 1024) {
        return ABC_ARGON2ID_C_MEMORY_BUDGET;
    }

    uint32_t version = 0x13, threads = 1, early_clean = 1;
    uint8_t empty = 0;
    if (password.size == 0) {
        password.data = &empty;
    }
    OSSL_PARAM args[11];
    size_t next = 0;
    args[next++] = octets(OSSL_KDF_PARAM_PASSWORD, password);
    args[next++] = octets(OSSL_KDF_PARAM_SALT, salt);
    if (secret.size != 0) args[next++] = octets(OSSL_KDF_PARAM_SECRET, secret);
    if (associated_data.size != 0) args[next++] = octets(OSSL_KDF_PARAM_ARGON2_AD, associated_data);
    args[next++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &parameters.passes);
    args[next++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &parameters.lanes);
    args[next++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &parameters.memory_kib);
    args[next++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version);
    args[next++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
    args[next++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_EARLY_CLEAN, &early_clean);
    args[next] = OSSL_PARAM_construct_end();

    EVP_KDF *algorithm = EVP_KDF_fetch(NULL, "ARGON2ID", "provider=default");
    if (algorithm == NULL) {
        return ABC_ARGON2ID_C_PROVIDER_FAILURE;
    }
    EVP_KDF_CTX *context = EVP_KDF_CTX_new(algorithm);
    EVP_KDF_free(algorithm);
    if (context == NULL) {
        return ABC_ARGON2ID_C_PROVIDER_FAILURE;
    }
    uint8_t *staged = OPENSSL_malloc(tag_length);
    int status = ABC_ARGON2ID_C_PROVIDER_FAILURE;
    if (staged != NULL && EVP_KDF_derive(context, staged, tag_length, args) == 1) {
        memcpy(tag, staged, tag_length);
        status = ABC_ARGON2ID_C_OK;
    }
    OPENSSL_clear_free(staged, tag_length);
    EVP_KDF_CTX_free(context);
    return status;
}
