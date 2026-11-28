#ifndef ABC_NATIVE_CPP_ARGON2ID_HPP
#define ABC_NATIVE_CPP_ARGON2ID_HPP

#include <cstddef>
#include <cstdint>

namespace abc::native_argon2id {

struct Bytes { const std::uint8_t* data; std::size_t size; };
struct Parameters { std::uint32_t memory_kib; std::uint32_t passes; std::uint32_t lanes; };
enum class Status { ok, invalid_parameters, invalid_buffer, memory_budget, provider_failure };

// The budget covers the requested memory matrix. Failure preserves the tag.
[[nodiscard]] Status derive(Parameters parameters, Bytes password, Bytes salt, Bytes secret, Bytes associated_data,
                            std::size_t matrix_budget, std::uint8_t* tag, std::size_t tag_length) noexcept;

}  // namespace abc::native_argon2id

#endif
