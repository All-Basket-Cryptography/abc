#ifndef ABC_NATIVE_CPP_SHA256_HPP
#define ABC_NATIVE_CPP_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace abc::native_sha256 {

inline constexpr std::size_t digest_size = 32;
inline constexpr std::size_t block_size = 64;
inline constexpr std::uint64_t max_message_bytes = (std::uint64_t{1} << 61) - 1;

using Digest = std::array<std::uint8_t, digest_size>;

enum class Status { ok, message_too_long, invalid_argument };

class Hasher {
public:
    Hasher() noexcept = default;

    // Rejection preserves the state. An admissible nonempty input points to
    // length readable bytes outside this context. A null pointer is permitted
    // for an empty input.
    [[nodiscard]] Status update(const std::uint8_t* input, std::size_t length) noexcept;
    [[nodiscard]] Digest digest() const noexcept;
    void reset() noexcept;

private:
    std::array<std::uint32_t, 8> state_{
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };
    std::array<std::uint8_t, block_size> pending_{};
    std::size_t used_ = 0;
    std::uint64_t length_ = 0;
};

// The result is assigned only after every input byte has been processed.
[[nodiscard]] Status hash(const std::uint8_t* input, std::size_t length, Digest& result) noexcept;

}  // namespace abc::native_sha256

#endif
