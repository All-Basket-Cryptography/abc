#ifndef ABC_NATIVE_CPP_ML_KEM_768_HPP
#define ABC_NATIVE_CPP_ML_KEM_768_HPP

#include <array>
#include <cstdint>

namespace abc::native_ml_kem_768 {

using PublicKey = std::array<std::uint8_t, 1184>;
using PrivateKey = std::array<std::uint8_t, 2400>;
using Ciphertext = std::array<std::uint8_t, 1088>;
using Secret = std::array<std::uint8_t, 32>;
struct KeyPair { PublicKey public_key; PrivateKey private_key; };
struct Encapsulation { Ciphertext ciphertext; Secret shared_secret; };
enum class Status { ok, rejected_key, provider_failure };

[[nodiscard]] Status generate(KeyPair& result) noexcept;
[[nodiscard]] Status encapsulate(const PublicKey& key, Encapsulation& result) noexcept;
[[nodiscard]] Status decapsulate(const PrivateKey& key, const Ciphertext& ciphertext, Secret& result) noexcept;

#ifdef ABC_MLKEM768_TESTING
using TestSeed = std::array<std::uint8_t, 64>;
[[nodiscard]] Status generate_for_test(const TestSeed& seed, KeyPair& result) noexcept;
[[nodiscard]] Status encapsulate_for_test(const PublicKey& key, const Secret& entropy, Encapsulation& result) noexcept;
#endif

}  // namespace abc::native_ml_kem_768

#endif
