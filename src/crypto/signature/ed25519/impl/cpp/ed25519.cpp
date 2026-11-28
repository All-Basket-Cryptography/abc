#include "ed25519.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <memory>

namespace abc::native_ed25519 {
namespace {

constexpr Key torsion_y[] = {
    {0},
    {1},
    {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
     0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
    {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
     0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
};

bool strong_encoding(const std::uint8_t* encoded) noexcept {
    Key y;
    std::copy_n(encoded, y.size(), y.begin());
    y.back() &= 0x7f;
    constexpr auto modulus = [] {
        Key result{};
        for (auto& byte : result) byte = 0xff;
        result.front() = 0xed;
        result.back() = 0x7f;
        return result;
    }();
    if (!std::lexicographical_compare(y.rbegin(), y.rend(), modulus.rbegin(), modulus.rend())) {
        return false;
    }
    return std::none_of(std::begin(torsion_y), std::end(torsion_y), [&y](const Key& point) { return y == point; });
}

using Pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Digest = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

Pkey private_key(const Key& seed) noexcept {
    return Pkey{EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", "provider=default",
                                                seed.data(), seed.size()), EVP_PKEY_free};
}

constexpr std::uint8_t empty = 0;

}  // namespace

Status public_key(const Key& seed, Key& output) noexcept {
    const auto key = private_key(seed);
    Key staged;
    auto written = staged.size();
    if (!key || EVP_PKEY_get_raw_public_key(key.get(), staged.data(), &written) != 1 || written != staged.size()) {
        return Status::provider_failure;
    }
    output = staged;
    return Status::ok;
}

Status sign(const Key& seed, const std::uint8_t* message, std::size_t length, Signature& output) noexcept {
    if (message == nullptr && length != 0) {
        return Status::invalid_argument;
    }
    const auto key = private_key(seed);
    const Digest context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    Signature staged;
    auto written = staged.size();
    if (!key || !context || EVP_DigestSignInit_ex(context.get(), nullptr, nullptr, nullptr, "provider=default",
                                                 key.get(), nullptr) != 1
        || EVP_DigestSign(context.get(), staged.data(), &written, length == 0 ? &empty : message, length) != 1
        || written != staged.size()) {
        return Status::provider_failure;
    }
    output = staged;
    return Status::ok;
}

Status verify_strict(const Key& public_key, const std::uint8_t* message, std::size_t length,
                     const Signature& signature) noexcept {
    if (message == nullptr && length != 0) {
        return Status::invalid_argument;
    }
    if (!strong_encoding(public_key.data()) || !strong_encoding(signature.data())) {
        return Status::rejected;
    }
    const Pkey key{EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", "provider=default",
                                                  public_key.data(), public_key.size()), EVP_PKEY_free};
    const Digest context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!key || !context || EVP_DigestVerifyInit_ex(context.get(), nullptr, nullptr, nullptr, "provider=default",
                                                    key.get(), nullptr) != 1) {
        return Status::provider_failure;
    }
    const auto result = EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                                         length == 0 ? &empty : message, length);
    return result == 1 ? Status::ok : result == 0 ? Status::rejected : Status::provider_failure;
}

}  // namespace abc::native_ed25519
