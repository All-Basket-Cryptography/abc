#ifndef ABC_NATIVE_CPP_X25519_HPP
#define ABC_NATIVE_CPP_X25519_HPP

#include <array>
#include <cstdint>

namespace abc::native_x25519 {

using Key = std::array<std::uint8_t, 32>;
enum class Status { ok, invalid_peer, provider_failure };

// Input and output arrays may alias. Failure preserves the output.
[[nodiscard]] Status public_key(const Key& scalar, Key& output) noexcept;
[[nodiscard]] Status shared_secret(const Key& scalar, const Key& peer_public, Key& output) noexcept;

}  // namespace abc::native_x25519

#endif
