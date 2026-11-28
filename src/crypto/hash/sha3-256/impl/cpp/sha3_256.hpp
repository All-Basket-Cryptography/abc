#ifndef ABC_NATIVE_CPP_SHA3_256_HPP
#define ABC_NATIVE_CPP_SHA3_256_HPP

#include "../../../keccak-p1600/impl/cpp/keccak_p1600.hpp"

namespace abc::native_sha3_256 {

using Status = native_keccak_p1600::Status;
inline constexpr std::size_t digest_size = 32;
inline constexpr std::size_t rate = native_keccak_p1600::rate;
using Digest = std::array<std::uint8_t, digest_size>;

class Hasher {
public:
    [[nodiscard]] Status update(const std::uint8_t* input, std::size_t length) noexcept;
    [[nodiscard]] Digest digest() const noexcept;
    void reset() noexcept;

private:
    native_keccak_p1600::Sponge sponge_;
};

[[nodiscard]] Status hash(const std::uint8_t* input, std::size_t length, Digest& output) noexcept;

}  // namespace abc::native_sha3_256

#endif
