#ifndef ABC_NATIVE_CPP_BLAKE2B_HPP
#define ABC_NATIVE_CPP_BLAKE2B_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace abc::native_blake2b {

inline constexpr std::size_t block_size = 128;
inline constexpr std::size_t max_digest_size = 64;

enum class Status { ok, invalid_buffer, invalid_digest_size, message_limit };

namespace detail {

struct Counter {
    std::uint64_t low = 0;
    std::uint64_t high = 0;

    [[nodiscard]] bool add(std::uint64_t bytes) noexcept;
};

}  // namespace detail

class Hasher {
public:
    Hasher() noexcept;
    [[nodiscard]] std::size_t digest_size() const noexcept;
    void reset() noexcept;
    [[nodiscard]] Status reset(std::size_t digest_size) noexcept;
    [[nodiscard]] Status update(const std::uint8_t* input, std::size_t length) noexcept;
    [[nodiscard]] Status digest(std::uint8_t* output, std::size_t length) const noexcept;

private:
    std::array<std::uint64_t, 8> state_{};
    std::array<std::uint8_t, block_size> pending_{};
    detail::Counter count_{};
    std::size_t used_ = 0;
    std::size_t digest_size_ = max_digest_size;
};

[[nodiscard]] Status hash(const std::uint8_t* input, std::size_t length,
                          std::uint8_t* output, std::size_t output_length) noexcept;

}  // namespace abc::native_blake2b

#endif
