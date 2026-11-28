#ifndef ABC_NATIVE_CPP_ED25519_HPP
#define ABC_NATIVE_CPP_ED25519_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace abc::native_ed25519 {

using Key = std::array<std::uint8_t, 32>;
using Signature = std::array<std::uint8_t, 64>;
enum class Status { ok, invalid_argument, rejected, provider_failure };

[[nodiscard]] Status public_key(const Key& seed, Key& output) noexcept;
[[nodiscard]] Status sign(const Key& seed, const std::uint8_t* message, std::size_t length,
                          Signature& output) noexcept;
[[nodiscard]] Status verify_strict(const Key& key, const std::uint8_t* message, std::size_t length,
                                   const Signature& signature) noexcept;

}  // namespace abc::native_ed25519

#endif
