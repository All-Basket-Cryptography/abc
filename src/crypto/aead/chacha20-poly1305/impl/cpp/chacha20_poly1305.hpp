#ifndef ABC_NATIVE_CPP_CHACHA20_POLY1305_HPP
#define ABC_NATIVE_CPP_CHACHA20_POLY1305_HPP

#include "chacha20.hpp"
#include "poly1305.hpp"

namespace abc::native_chacha20_poly1305 {

using Key = native_chacha20::Key;
using Nonce = native_chacha20::Nonce;
using Tag = native_poly1305::Tag;

enum class Status { ok, invalid_argument, output_too_short, counter_range, authentication_failed };

// The tag must have separate storage from the used ciphertext prefix.
// The source, destination and AAD may overlap. Use a unique nonce per key.
[[nodiscard]] Status seal_detached(
    const Key& key, const Nonce& nonce, const std::uint8_t* aad, std::size_t aad_length,
    const std::uint8_t* input, std::size_t length, std::uint8_t* output,
    std::size_t capacity, Tag& tag) noexcept;

// Any rejected operation preserves the destination.
[[nodiscard]] Status open_detached(
    const Key& key, const Nonce& nonce, const std::uint8_t* aad, std::size_t aad_length,
    const std::uint8_t* input, std::size_t length, std::uint8_t* output,
    std::size_t capacity, const Tag& tag) noexcept;

}  // namespace abc::native_chacha20_poly1305
#endif
