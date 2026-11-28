#ifndef ABC_NATIVE_CPP_SHA512_HPP
#define ABC_NATIVE_CPP_SHA512_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace abc::native_sha512 {

inline constexpr std::size_t digest_size = 64;
inline constexpr std::size_t block_size = 128;
using Digest = std::array<std::uint8_t, digest_size>;

enum class Status { ok, message_too_long, invalid_argument };

class Hasher {
public:
    Hasher() noexcept = default;

    // Rejection preserves the state. A nonempty input points to length
    // readable bytes outside this context. Empty input may be null.
    [[nodiscard]] Status update(const std::uint8_t* input, std::size_t length) noexcept;
    [[nodiscard]] Digest digest() const noexcept;
    void reset() noexcept;

private:
    std::array<std::uint64_t, 8> state_{
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
    };
    std::array<std::uint8_t, block_size> pending_{};
    std::size_t used_ = 0;
    std::uint64_t bytes_high_ = 0;
    std::uint64_t bytes_low_ = 0;
};

// Assign the digest after consuming the input. Input and result may overlap.
[[nodiscard]] Status hash(const std::uint8_t* input, std::size_t length, Digest& result) noexcept;

}  // namespace abc::native_sha512

#endif
