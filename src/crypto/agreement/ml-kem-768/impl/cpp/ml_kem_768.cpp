#include "ml_kem_768.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <memory>

namespace abc::native_ml_kem_768 {
namespace {

constexpr auto algorithm = "ML-KEM-768";
constexpr auto provider = "provider=default";
using Context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

Context new_context() noexcept {
    return Context{EVP_PKEY_CTX_new_from_name(nullptr, algorithm, provider), EVP_PKEY_CTX_free};
}

OSSL_PARAM octets(const char* name, const std::uint8_t* bytes, std::size_t size) noexcept {
    return OSSL_PARAM_construct_octet_string(name, const_cast<std::uint8_t*>(bytes), size);
}

template<class Buffer>
bool export_raw(const Key& key, const char* name, Buffer& output) noexcept {
    std::size_t written = 0;
    return EVP_PKEY_get_octet_string_param(key.get(), name, output.data(), output.size(), &written) == 1
        && written == output.size();
}

Key import_raw(const char* name, const std::uint8_t* bytes, std::size_t size, int selection) noexcept {
    const auto context = new_context();
    OSSL_PARAM params[]{octets(name, bytes, size), OSSL_PARAM_construct_end()};
    EVP_PKEY* value = nullptr;
    if (!context || EVP_PKEY_fromdata_init(context.get()) != 1
        || EVP_PKEY_fromdata(context.get(), &value, selection, params) != 1) {
        EVP_PKEY_free(value);
        value = nullptr;
    }
    return Key{value, EVP_PKEY_free};
}

Status keygen(KeyPair& output, OSSL_PARAM* params) noexcept {
    const auto context = new_context();
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1
        || (params != nullptr && EVP_PKEY_CTX_set_params(context.get(), params) != 1)) {
        return Status::provider_failure;
    }
    EVP_PKEY* value = nullptr;
    const auto generated = EVP_PKEY_generate(context.get(), &value);
    const Key key{value, EVP_PKEY_free};
    if (!key || generated != 1) {
        return Status::provider_failure;
    }
    KeyPair staged;
    auto status = Status::provider_failure;
    if (export_raw(key, OSSL_PKEY_PARAM_PUB_KEY, staged.public_key)
        && export_raw(key, OSSL_PKEY_PARAM_PRIV_KEY, staged.private_key)) {
        output = staged;
        status = Status::ok;
    }
    OPENSSL_cleanse(staged.private_key.data(), staged.private_key.size());
    return status;
}

Status seal(const PublicKey& public_key, Encapsulation& output, const OSSL_PARAM* parameters) noexcept {
    const auto key = import_raw(OSSL_PKEY_PARAM_PUB_KEY, public_key.data(), public_key.size(), EVP_PKEY_PUBLIC_KEY);
    if (!key) {
        return Status::rejected_key;
    }
    const Context context{EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), provider), EVP_PKEY_CTX_free};
    if (!context || EVP_PKEY_encapsulate_init(context.get(), parameters) != 1) {
        return Status::provider_failure;
    }
    Encapsulation staged;
    auto ct_size = staged.ciphertext.size();
    auto sk_size = staged.shared_secret.size();
    auto status = Status::provider_failure;
    if (EVP_PKEY_encapsulate(context.get(), staged.ciphertext.data(), &ct_size, staged.shared_secret.data(), &sk_size) == 1
        && ct_size == staged.ciphertext.size() && sk_size == staged.shared_secret.size()) {
        output = staged;
        status = Status::ok;
    }
    OPENSSL_cleanse(staged.shared_secret.data(), staged.shared_secret.size());
    return status;
}

}  // namespace

Status generate(KeyPair& result) noexcept { return keygen(result, nullptr); }

Status encapsulate(const PublicKey& key, Encapsulation& result) noexcept { return seal(key, result, nullptr); }

Status decapsulate(const PrivateKey& private_key, const Ciphertext& ciphertext, Secret& output) noexcept {
    const auto key = import_raw(OSSL_PKEY_PARAM_PRIV_KEY, private_key.data(), private_key.size(), EVP_PKEY_KEYPAIR);
    if (!key) {
        return Status::rejected_key;
    }
    const Context context{EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), provider), EVP_PKEY_CTX_free};
    if (!context || EVP_PKEY_decapsulate_init(context.get(), nullptr) != 1) {
        return Status::provider_failure;
    }
    Secret staged;
    auto size = staged.size();
    auto status = Status::provider_failure;
    if (EVP_PKEY_decapsulate(context.get(), staged.data(), &size, ciphertext.data(), ciphertext.size()) == 1
        && size == staged.size()) {
        output = staged;
        status = Status::ok;
    }
    OPENSSL_cleanse(staged.data(), staged.size());
    return status;
}

#ifdef ABC_MLKEM768_TESTING
Status generate_for_test(const TestSeed& seed, KeyPair& output) noexcept {
    OSSL_PARAM params[]{octets(OSSL_PKEY_PARAM_ML_KEM_SEED, seed.data(), seed.size()), OSSL_PARAM_construct_end()};
    return keygen(output, params);
}

Status encapsulate_for_test(const PublicKey& key, const Secret& entropy, Encapsulation& output) noexcept {
    const OSSL_PARAM params[]{octets(OSSL_KEM_PARAM_IKME, entropy.data(), entropy.size()), OSSL_PARAM_construct_end()};
    return seal(key, output, params);
}
#endif

}  // namespace abc::native_ml_kem_768
