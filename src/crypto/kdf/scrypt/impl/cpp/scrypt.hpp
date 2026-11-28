#ifndef ABC_NATIVE_CPP_SCRYPT_HPP
#define ABC_NATIVE_CPP_SCRYPT_HPP

#include <cstddef>
#include <cstdint>

namespace abc::native_scrypt {

struct Parameters {
    std::size_t n;
    std::uint32_t r;
    std::uint32_t p;
};

enum class Status { ok, bad_parameters, invalid_buffer, length_limit, workspace_too_small, backend_error };

[[nodiscard]] Status workspace_bytes(Parameters parameters, std::size_t& bytes) noexcept;

// The used workspace prefix must be disjoint from all other buffers.
// Output may overlap the password or salt. Empty inputs may be null.
// Preflight rejection preserves both writable buffers.
[[nodiscard]] Status derive(const std::uint8_t* password, std::size_t password_length,
    const std::uint8_t* salt, std::size_t salt_length, Parameters parameters,
    std::uint8_t* workspace, std::size_t workspace_length,
    std::uint8_t* output, std::size_t output_length) noexcept;

}  // namespace abc::native_scrypt

#endif
