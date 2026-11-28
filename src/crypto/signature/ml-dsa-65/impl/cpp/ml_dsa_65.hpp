#ifndef ABC_NATIVE_CPP_ML_DSA_65_HPP
#define ABC_NATIVE_CPP_ML_DSA_65_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace abc::native_ml_dsa_65 {

using Seed = std::array<std::uint8_t, 32>;
using PublicKey = std::array<std::uint8_t, 1952>;
using Signature = std::array<std::uint8_t, 3309>;
struct Bytes { const std::uint8_t* data; std::size_t size; };
enum class Status { ok, invalid_argument, rejected, provider_failure };

[[nodiscard]] Status public_key(const Seed& seed, PublicKey& output) noexcept;
[[nodiscard]] Status sign(const Seed& seed, Bytes message, Bytes context, Signature& output) noexcept;
[[nodiscard]] Status verify(const PublicKey& key, Bytes message, Bytes context, const Signature& signature) noexcept;

#ifdef ABC_MLDSA65_TESTING
using ExpandedKey = std::array<std::uint8_t, 4032>;
[[nodiscard]] Status sign_expanded_for_test(const ExpandedKey& key, Bytes message, Bytes context,
                                            Signature& output) noexcept;
#endif

}  // namespace abc::native_ml_dsa_65

#endif
