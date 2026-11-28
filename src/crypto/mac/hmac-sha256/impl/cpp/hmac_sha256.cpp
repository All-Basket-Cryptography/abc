#include "hmac_sha256.hpp"

#include <algorithm>

namespace abc::native_hmac_sha256 {

Hmac::Hmac() noexcept {
    set_pads({});
}

void Hmac::set_pads(const std::array<std::uint8_t, block_size>& normalized) noexcept {
    auto pad = normalized;
    inner_.reset();
    outer_.reset();
    for (auto& byte : pad) {
        byte ^= 0x36;
    }
    // Both fresh states are given exactly one block from a valid buffer.
    (void)inner_.update(pad.data(), pad.size());
    for (auto& byte : pad) {
        byte ^= 0x36 ^ 0x5c;
    }
    (void)outer_.update(pad.data(), pad.size());
}

Status Hmac::set_key(const std::uint8_t* key, std::size_t length) noexcept {
    if (length > max_key_bytes) {
        return Status::message_too_long;
    }
    if (key == nullptr && length != 0) {
        return Status::invalid_argument;
    }

    std::array<std::uint8_t, block_size> normalized{};
    if (length > block_size) {
        Tag hashed{};
        const auto status = native_sha256::hash(key, length, hashed);
        if (status != Status::ok) {
            return status;
        }
        std::copy(hashed.begin(), hashed.end(), normalized.begin());
    } else if (length != 0) {
        std::copy_n(key, length, normalized.begin());
    }
    set_pads(normalized);
    return Status::ok;
}

Status Hmac::update(const std::uint8_t* input, std::size_t length) noexcept {
    return inner_.update(input, length);
}

Tag Hmac::digest() const noexcept {
    const Tag intermediate = inner_.digest();
    auto snapshot = outer_;
    (void)snapshot.update(intermediate.data(), intermediate.size());
    return snapshot.digest();
}

Status authenticate(const std::uint8_t* key, std::size_t key_length,
                    const std::uint8_t* input, std::size_t length, Tag& output) noexcept {
    Hmac state;
    if (const auto status = state.set_key(key, key_length); status != Status::ok) {
        return status;
    }
    if (const auto status = state.update(input, length); status != Status::ok) {
        return status;
    }
    output = state.digest();
    return Status::ok;
}

}  // namespace abc::native_hmac_sha256
