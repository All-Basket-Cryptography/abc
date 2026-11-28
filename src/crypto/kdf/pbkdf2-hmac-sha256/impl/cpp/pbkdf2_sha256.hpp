#ifndef ABC_NATIVE_CPP_PBKDF2_SHA256_HPP
#define ABC_NATIVE_CPP_PBKDF2_SHA256_HPP

#include "hmac_sha256.hpp"

namespace abc::native_pbkdf2_sha256 {

inline constexpr auto max_output_bytes = std::uint64_t{UINT32_MAX} * native_hmac_sha256::tag_size;
inline constexpr auto max_salt_bytes = native_hmac_sha256::max_message_bytes - 4;

enum class Status { ok, invalid_argument, input_too_long, invalid_iterations, invalid_output_length };

// An admitted nonempty input or output must refer to a buffer of that size.
// Salt and output must be disjoint. Rejection preserves output.
[[nodiscard]] Status derive(const std::uint8_t* password, std::size_t password_length,
                            const std::uint8_t* salt, std::size_t salt_length, std::uint32_t iterations,
                            std::uint8_t* output, std::size_t output_length) noexcept;

}  // namespace abc::native_pbkdf2_sha256

#endif
