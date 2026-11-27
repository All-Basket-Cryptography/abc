#ifndef ABC_NATIVE_CPP_CHACHA20_HPP
#define ABC_NATIVE_CPP_CHACHA20_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace abc::native_chacha20 {

inline constexpr std::size_t key_size = 32;
inline constexpr std::size_t nonce_size = 12;
inline constexpr std::size_t block_size = 64;

using Key = std::array<std::uint8_t, key_size>;
using Nonce = std::array<std::uint8_t, nonce_size>;
using Block = std::array<std::uint8_t, block_size>;

enum class Status { ok, invalid_argument, output_too_short, counter_range };

[[nodiscard]] bool fits_counter(std::uint64_t bytes, std::uint32_t counter) noexcept;
[[nodiscard]] Block stream_block(const Key& key, const Nonce& nonce, std::uint32_t counter) noexcept;

// The equally long output prefix can overlap input. Errors preserve output.
[[nodiscard]] Status apply(const Key& key, const Nonce& nonce, std::uint32_t counter,
                           const std::uint8_t* input, std::size_t length,
                           std::uint8_t* output, std::size_t capacity) noexcept;

}  // namespace abc::native_chacha20

#endif
