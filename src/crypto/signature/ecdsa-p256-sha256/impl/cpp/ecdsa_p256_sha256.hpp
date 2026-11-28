#ifndef ABC_NATIVE_CPP_ECDSA_P256_SHA256_HPP
#define ABC_NATIVE_CPP_ECDSA_P256_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace abc::native_ecdsa_p256_sha256 {

using Scalar = std::array<std::uint8_t, 32>;
using PublicKey = std::array<std::uint8_t, 65>;
using Signature = std::array<std::uint8_t, 64>;
enum class Status { ok, invalid_argument, rejected, provider_failure, retry_exhausted };

[[nodiscard]] Status public_key(const Scalar& scalar, PublicKey& output) noexcept;
[[nodiscard]] Status sign(const Scalar& scalar, const std::uint8_t* message, std::size_t length,
                          Signature& output) noexcept;
[[nodiscard]] Status verify(const std::uint8_t* key, std::size_t key_length, const std::uint8_t* message,
                            std::size_t length, const Signature& signature) noexcept;

}  // namespace abc::native_ecdsa_p256_sha256

#endif
