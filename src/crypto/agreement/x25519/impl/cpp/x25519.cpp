#include "x25519.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <memory>

namespace abc::native_x25519 {
namespace {

using ProviderKey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

ProviderKey private_key(const Key& scalar) noexcept {
    return ProviderKey{EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", "provider=default",
                                                     scalar.data(), scalar.size()), EVP_PKEY_free};
}

struct StagedSecret {
    Key bytes;

    ~StagedSecret() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

}  // namespace

Status public_key(const Key& scalar, Key& output) noexcept {
    const auto local = private_key(scalar);
    Key staged;
    auto written = staged.size();
    if (!local || EVP_PKEY_get_raw_public_key(local.get(), staged.data(), &written) != 1 || written != staged.size()) {
        return Status::provider_failure;
    }
    output = staged;
    return Status::ok;
}

Status shared_secret(const Key& scalar, const Key& peer_public, Key& output) noexcept {
    const auto local = private_key(scalar);
    const ProviderKey remote{EVP_PKEY_new_raw_public_key_ex(nullptr, "X25519", "provider=default",
                                                           peer_public.data(), peer_public.size()), EVP_PKEY_free};
    if (!local || !remote) {
        return Status::provider_failure;
    }
    const std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context{
        EVP_PKEY_CTX_new_from_pkey(nullptr, local.get(), "provider=default"), EVP_PKEY_CTX_free};
    if (!context || EVP_PKEY_derive_init(context.get()) != 1) {
        return Status::provider_failure;
    }
    StagedSecret staged;
    auto written = staged.bytes.size();
    if (EVP_PKEY_derive_set_peer(context.get(), remote.get()) != 1
        || EVP_PKEY_derive(context.get(), staged.bytes.data(), &written) != 1) {
        return Status::invalid_peer;
    }
    if (written != staged.bytes.size()) {
        return Status::provider_failure;
    }
    const Key zero{};
    if (CRYPTO_memcmp(staged.bytes.data(), zero.data(), zero.size()) == 0) {
        return Status::invalid_peer;
    }
    output = staged.bytes;
    return Status::ok;
}

}  // namespace abc::native_x25519
