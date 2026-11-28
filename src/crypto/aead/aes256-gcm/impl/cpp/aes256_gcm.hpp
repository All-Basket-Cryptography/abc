#ifndef ABC_NATIVE_CPP_AES256_GCM_HPP
#define ABC_NATIVE_CPP_AES256_GCM_HPP

#include "../../../../cipher/aes256/impl/cpp/aes256.hpp"

namespace abc::native_aes256_gcm {

using Key = native_aes256::Key;
using Nonce = std::array<std::uint8_t, 12>;
using Tag = std::array<std::uint8_t, 16>;
enum class Status { ok, invalid_argument, uninitialized, unsupported, authentication_failed };

class Gcm {
public:
    Gcm() noexcept = default;
    ~Gcm();
    Gcm(const Gcm&) = delete;
    Gcm& operator=(const Gcm&) = delete;

    [[nodiscard]] Status initialize(const Key& key) noexcept;
    void clear() noexcept;

    // Each encryption with the same key requires a distinct nonce.
    [[nodiscard]] Status seal(const Nonce& nonce, const std::uint8_t* aad, std::size_t aad_length,
                              const std::uint8_t* input, std::size_t length, std::uint8_t* output,
                              std::size_t output_length, Tag& tag) const noexcept;
    [[nodiscard]] Status open(const Nonce& nonce, const std::uint8_t* aad, std::size_t aad_length,
                              const std::uint8_t* input, std::size_t length, const Tag& tag,
                              std::uint8_t* output, std::size_t output_length) const noexcept;

private:
    void clear_hash() noexcept;
    native_aes256::Cipher cipher_;
    std::array<std::uint64_t, 2> hash_{};
};

}  // namespace abc::native_aes256_gcm

#endif
