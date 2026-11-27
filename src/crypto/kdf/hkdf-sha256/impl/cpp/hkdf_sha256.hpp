#ifndef ABC_NATIVE_CPP_HKDF_SHA256_HPP
#define ABC_NATIVE_CPP_HKDF_SHA256_HPP

#include "hmac_sha256.hpp"

namespace abc::native_hkdf_sha256 {

using Prk = native_hmac_sha256::Tag;
inline constexpr auto max_output_bytes = 255 * native_hmac_sha256::tag_size;
inline constexpr auto max_info_bytes = native_hmac_sha256::max_message_bytes - Prk{}.size() - 1;

enum class Status { ok, invalid_argument, input_too_long, prk_too_short, output_too_long };

// All admitted, nonempty inputs and outputs must refer to actual buffers.
// Expand and derive require a destination disjoint from info. Null is
// admissible with length zero. Errors preserve the destination.
[[nodiscard]] Status extract(const std::uint8_t* salt, std::size_t salt_length,
                             const std::uint8_t* ikm, std::size_t ikm_length, Prk& output) noexcept;
[[nodiscard]] Status expand(const std::uint8_t* prk, std::size_t prk_length,
                            const std::uint8_t* info, std::size_t info_length,
                            std::uint8_t* output, std::size_t output_length) noexcept;
[[nodiscard]] Status derive(const std::uint8_t* salt, std::size_t salt_length,
                            const std::uint8_t* ikm, std::size_t ikm_length,
                            const std::uint8_t* info, std::size_t info_length,
                            std::uint8_t* output, std::size_t output_length) noexcept;

}  // namespace abc::native_hkdf_sha256

#endif
