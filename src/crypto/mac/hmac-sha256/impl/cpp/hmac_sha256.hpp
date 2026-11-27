#ifndef ABC_NATIVE_CPP_HMAC_SHA256_HPP
#define ABC_NATIVE_CPP_HMAC_SHA256_HPP

#include "sha256.hpp"

namespace abc::native_hmac_sha256 {

using Status = native_sha256::Status;
using Tag = native_sha256::Digest;

inline constexpr auto block_size = native_sha256::block_size;
inline constexpr auto tag_size = native_sha256::digest_size;
inline constexpr auto max_key_bytes = native_sha256::max_message_bytes;
inline constexpr auto max_message_bytes = native_sha256::max_message_bytes - block_size;

class Hmac {
public:
    Hmac() noexcept;

    // Start a new message under this key. Rejected keys preserve the current state.
    [[nodiscard]] Status set_key(const std::uint8_t* key, std::size_t length) noexcept;
    [[nodiscard]] Status update(const std::uint8_t* input, std::size_t length) noexcept;
    [[nodiscard]] Tag digest() const noexcept;

private:
    void set_pads(const std::array<std::uint8_t, block_size>& normalized) noexcept;

    native_sha256::Hasher inner_, outer_;
};

// The result is assigned after all key and message bytes have been read.
[[nodiscard]] Status authenticate(const std::uint8_t* key, std::size_t key_length,
                                  const std::uint8_t* input, std::size_t length, Tag& output) noexcept;

}  // namespace abc::native_hmac_sha256

#endif
