#include "ml_dsa_65.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <memory>

namespace abc::native_ml_dsa_65 {
namespace {

constexpr auto algorithm = "ML-DSA-65";
constexpr auto provider = "provider=default";
constexpr std::uint8_t empty = 0;
using Context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Digest = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

Context new_context() noexcept {
    return Context{EVP_PKEY_CTX_new_from_name(nullptr, algorithm, provider), EVP_PKEY_CTX_free};
}

OSSL_PARAM octets(const char* name, Bytes bytes) noexcept {
    auto data = bytes.size == 0 ? &empty : bytes.data;
    return OSSL_PARAM_construct_octet_string(name, const_cast<std::uint8_t*>(data), bytes.size);
}

bool valid(Bytes message, Bytes context) noexcept {
    return (message.size == 0 || message.data != nullptr) && (context.size == 0 || context.data != nullptr)
        && context.size <= 255;
}

Key from_seed(const Seed& seed) noexcept {
    const auto context = new_context();
    OSSL_PARAM params[]{octets(OSSL_PKEY_PARAM_ML_DSA_SEED, {seed.data(), seed.size()}), OSSL_PARAM_construct_end()};
    EVP_PKEY* value = nullptr;
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1 || EVP_PKEY_CTX_set_params(context.get(), params) != 1
        || EVP_PKEY_generate(context.get(), &value) != 1) {
        EVP_PKEY_free(value);
        value = nullptr;
    }
    return Key{value, EVP_PKEY_free};
}

Key import_raw(const char* name, Bytes bytes, int selection) noexcept {
    const auto context = new_context();
    OSSL_PARAM params[]{octets(name, bytes), OSSL_PARAM_construct_end()};
    EVP_PKEY* value = nullptr;
    if (!context || EVP_PKEY_fromdata_init(context.get()) != 1
        || EVP_PKEY_fromdata(context.get(), &value, selection, params) != 1) {
        EVP_PKEY_free(value);
        value = nullptr;
    }
    return Key{value, EVP_PKEY_free};
}

Status sign_message(const Key& key, Bytes message, Bytes domain, Signature& output) noexcept {
    unsigned int deterministic = 1;
    OSSL_PARAM params[]{OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic),
                        octets(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, domain), OSSL_PARAM_construct_end()};
    const Digest context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    Signature staged;
    auto length = staged.size();
    if (!key || !context || EVP_DigestSignInit_ex(context.get(), nullptr, nullptr, nullptr, provider, key.get(), params) != 1
        || EVP_DigestSign(context.get(), staged.data(), &length, message.size == 0 ? &empty : message.data, message.size) != 1
        || length != staged.size()) {
        return Status::provider_failure;
    }
    output = staged;
    return Status::ok;
}

}  // namespace

Status public_key(const Seed& seed, PublicKey& output) noexcept {
    const auto private_key = from_seed(seed);
    PublicKey staged;
    std::size_t size = 0;
    if (!private_key || EVP_PKEY_get_octet_string_param(private_key.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                                        staged.data(), staged.size(), &size) != 1 || size != staged.size()) {
        return Status::provider_failure;
    }
    output = staged;
    return Status::ok;
}

Status sign(const Seed& seed, Bytes message, Bytes context, Signature& output) noexcept {
    if (!valid(message, context)) {
        return Status::invalid_argument;
    }
    return sign_message(from_seed(seed), message, context, output);
}

Status verify(const PublicKey& public_key, Bytes message, Bytes domain, const Signature& signature) noexcept {
    if (!valid(message, domain)) {
        return Status::invalid_argument;
    }
    const auto key = import_raw(OSSL_PKEY_PARAM_PUB_KEY, {public_key.data(), public_key.size()}, EVP_PKEY_PUBLIC_KEY);
    if (!key) {
        return Status::rejected;
    }
    OSSL_PARAM params[]{octets(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, domain), OSSL_PARAM_construct_end()};
    const Digest context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!context || EVP_DigestVerifyInit_ex(context.get(), nullptr, nullptr, nullptr, provider, key.get(), params) != 1) {
        return Status::provider_failure;
    }
    const auto verified = EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                                           message.size == 0 ? &empty : message.data, message.size);
    return verified == 1 ? Status::ok : verified == 0 ? Status::rejected : Status::provider_failure;
}

#ifdef ABC_MLDSA65_TESTING
Status sign_expanded_for_test(const ExpandedKey& key, Bytes message, Bytes context, Signature& output) noexcept {
    if (!valid(message, context)) {
        return Status::invalid_argument;
    }
    return sign_message(import_raw(OSSL_PKEY_PARAM_PRIV_KEY, {key.data(), key.size()}, EVP_PKEY_KEYPAIR),
                        message, context, output);
}
#endif

}  // namespace abc::native_ml_dsa_65
