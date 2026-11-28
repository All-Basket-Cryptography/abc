#include "sha3_256.hpp"

namespace abc::native_sha3_256 {

Status Hasher::update(const std::uint8_t* input, std::size_t length) noexcept {
    return sponge_.absorb(input, length);
}

Digest Hasher::digest() const noexcept {
    auto reader = sponge_.finish(native_keccak_p1600::Domain::sha3);
    Digest output{};
    static_cast<void>(reader.read(output.data(), output.size()));
    return output;
}

void Hasher::reset() noexcept { sponge_.reset(); }

Status hash(const std::uint8_t* input, std::size_t length, Digest& output) noexcept {
    Hasher hasher;
    const auto status = hasher.update(input, length);
    if (status == Status::ok) {
        output = hasher.digest();
    }
    return status;
}

}  // namespace abc::native_sha3_256
