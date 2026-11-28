#include "shake256.hpp"

namespace abc::native_shake256 {

Status Hasher::update(const std::uint8_t* input, std::size_t length) noexcept {
    return sponge_.absorb(input, length);
}

Reader Hasher::finalize() const noexcept {
    return sponge_.finish(native_keccak_p1600::Domain::shake);
}

void Hasher::reset() noexcept { sponge_.reset(); }

Status xof(const std::uint8_t* input, std::size_t input_length,
           std::uint8_t* output, std::size_t output_length) noexcept {
    if (output == nullptr && output_length != 0) {
        return Status::invalid_argument;
    }
    Hasher hasher;
    const auto status = hasher.update(input, input_length);
    return status == Status::ok ? hasher.finalize().read(output, output_length) : status;
}

}  // namespace abc::native_shake256
