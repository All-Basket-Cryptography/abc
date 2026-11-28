#ifndef ABC_NATIVE_CPP_AES256_HPP
#define ABC_NATIVE_CPP_AES256_HPP

#include <array>
#include <cstdint>

namespace abc::native_aes256 {

using Key = std::array<std::uint8_t, 32>;
using Block = std::array<std::uint8_t, 16>;
enum class Status { ok, uninitialized, unsupported };

[[nodiscard]] bool available() noexcept;

class Cipher {
public:
    Cipher() noexcept = default;
    ~Cipher();
    Cipher(const Cipher&) = delete;
    Cipher& operator=(const Cipher&) = delete;

    [[nodiscard]] Status initialize(const Key& key) noexcept;
    [[nodiscard]] Status encrypt(const Block& input, Block& output) const noexcept;
    [[nodiscard]] Status decrypt(const Block& input, Block& output) const noexcept;
    void clear() noexcept;

private:
    std::array<Block, 15> encryption_{};
    std::array<Block, 15> decryption_{};
    bool initialized_ = false;
};

}  // namespace abc::native_aes256

#endif
