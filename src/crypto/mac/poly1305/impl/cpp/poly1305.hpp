#ifndef ABC_NATIVE_CPP_POLY1305_HPP
#define ABC_NATIVE_CPP_POLY1305_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace abc::native_poly1305 {

inline constexpr std::size_t key_size = 32;
inline constexpr std::size_t tag_size = 16;
using Key = std::array<std::uint8_t, key_size>;
using Tag = std::array<std::uint8_t, tag_size>;

enum class Status { ok, invalid_argument, state = 5 };

class Mac {
public:
    explicit Mac(const Key& key) noexcept;
    ~Mac() noexcept;
    Mac(const Mac&) = delete;
    Mac& operator=(const Mac&) = delete;

    [[nodiscard]] Status update(const std::uint8_t* input, std::size_t length) noexcept;
    // Finalization closes the message. Repeated calls return the same tag.
    [[nodiscard]] Tag finish() noexcept;

private:
    using Limbs = std::array<std::uint64_t, 5>;

    void absorb(const std::uint8_t* block, std::uint64_t high_bit) noexcept;
    void erase() noexcept;

    Limbs h_{}, r_{}, folded_{};
    std::array<std::uint32_t, 4> pad_{};
    std::array<std::uint8_t, 16> pending_{};
    Tag tag_{};
    std::size_t used_ = 0;
    bool finished_ = false;
};

// Use a fresh one-time key for each distinct message.
[[nodiscard]] Status authenticate(const Key& key, const std::uint8_t* input, std::size_t length,
                                  Tag& output) noexcept;

}  // namespace abc::native_poly1305
#endif
