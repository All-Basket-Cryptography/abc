#ifndef ABC_NATIVE_CPP_SHAKE256_HPP
#define ABC_NATIVE_CPP_SHAKE256_HPP

#include "../../../keccak-p1600/impl/cpp/keccak_p1600.hpp"

namespace abc::native_shake256 {

using Status = native_keccak_p1600::Status;
using Reader = native_keccak_p1600::Reader;
inline constexpr std::size_t rate = native_keccak_p1600::rate;

class Hasher {
public:
    [[nodiscard]] Status update(const std::uint8_t* input, std::size_t length) noexcept;
    [[nodiscard]] Reader finalize() const noexcept;
    void reset() noexcept;

private:
    native_keccak_p1600::Sponge sponge_;
};

[[nodiscard]] Status xof(const std::uint8_t* input, std::size_t input_length,
                         std::uint8_t* output, std::size_t output_length) noexcept;

}  // namespace abc::native_shake256

#endif
