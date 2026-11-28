#include "argon2id.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <algorithm>
#include <array>
#include <memory>

namespace abc::native_argon2id {
namespace {

bool valid(Bytes bytes) noexcept {
    return bytes.size <= UINT32_MAX && (bytes.size == 0 || bytes.data != nullptr);
}

OSSL_PARAM octets(const char* name, Bytes bytes) noexcept {
    return OSSL_PARAM_construct_octet_string(name, const_cast<std::uint8_t*>(bytes.data), bytes.size);
}

struct ClearTag {
    std::size_t size;

    void operator()(std::uint8_t* tag) const noexcept {
        OPENSSL_clear_free(tag, size);
    }
};

}  // namespace

Status derive(Parameters parameters, Bytes password, Bytes salt, Bytes secret, Bytes associated_data,
              std::size_t matrix_budget, std::uint8_t* tag, std::size_t tag_length) noexcept {
    if (parameters.passes == 0 || parameters.lanes == 0 || parameters.lanes >= (std::uint32_t{1} << 24)
        || parameters.memory_kib < std::uint64_t{8} * parameters.lanes) {
        return Status::invalid_parameters;
    }
    if (tag == nullptr || tag_length < 4 || tag_length > UINT32_MAX || !valid(password) || !valid(salt)
        || salt.size < 8 || !valid(secret) || !valid(associated_data)) {
        return Status::invalid_buffer;
    }
    if (parameters.memory_kib > matrix_budget / 1024) {
        return Status::memory_budget;
    }

    std::uint32_t version = 0x13, threads = 1, early_clean = 1;
    std::uint8_t empty = 0;
    if (password.size == 0) {
        password = {&empty, 0};
    }
    std::array<OSSL_PARAM, 11> args;
    auto cursor = args.begin();
    *cursor++ = octets(OSSL_KDF_PARAM_PASSWORD, password);
    *cursor++ = octets(OSSL_KDF_PARAM_SALT, salt);
    if (secret.size != 0) *cursor++ = octets(OSSL_KDF_PARAM_SECRET, secret);
    if (associated_data.size != 0) *cursor++ = octets(OSSL_KDF_PARAM_ARGON2_AD, associated_data);
    *cursor++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &parameters.passes);
    *cursor++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &parameters.lanes);
    *cursor++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &parameters.memory_kib);
    *cursor++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version);
    *cursor++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
    *cursor++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_EARLY_CLEAN, &early_clean);
    *cursor = OSSL_PARAM_construct_end();

    const std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> algorithm{
        EVP_KDF_fetch(nullptr, "ARGON2ID", "provider=default"), EVP_KDF_free};
    if (!algorithm) {
        return Status::provider_failure;
    }
    const std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> context{EVP_KDF_CTX_new(algorithm.get()), EVP_KDF_CTX_free};
    if (!context) {
        return Status::provider_failure;
    }
    const std::unique_ptr<std::uint8_t, ClearTag> staged{static_cast<std::uint8_t*>(OPENSSL_malloc(tag_length)), {tag_length}};
    if (!staged || EVP_KDF_derive(context.get(), staged.get(), tag_length, args.data()) != 1) {
        return Status::provider_failure;
    }
    std::copy_n(staged.get(), tag_length, tag);
    return Status::ok;
}

}  // namespace abc::native_argon2id
