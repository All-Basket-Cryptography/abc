#include "pbkdf2_sha256.hpp"

#include <algorithm>

namespace abc::native_pbkdf2_sha256 {
namespace {

native_hmac_sha256::Tag block(const native_hmac_sha256::Hmac& keyed,
                              const std::uint8_t* salt, std::size_t salt_length,
                              std::uint32_t index, std::uint32_t iterations) noexcept {
    const std::array<std::uint8_t, 4> counter{
        static_cast<std::uint8_t>(index >> 24), static_cast<std::uint8_t>(index >> 16),
        static_cast<std::uint8_t>(index >> 8), static_cast<std::uint8_t>(index),
    };
    auto first = keyed;
    // The admitted salt leaves room for the entire counter and the HMAC pad.
    (void)first.update(salt, salt_length);
    (void)first.update(counter.data(), counter.size());
    auto previous = first.digest();
    auto result = previous;
    for (std::uint32_t round = 1; round < iterations; ++round) {
        auto hmac = keyed;
        (void)hmac.update(previous.data(), previous.size());
        previous = hmac.digest();
        for (std::size_t i = 0; i < result.size(); ++i) {
            result[i] ^= previous[i];
        }
    }
    return result;
}

}  // namespace

Status derive(const std::uint8_t* password, std::size_t password_length,
              const std::uint8_t* salt, std::size_t salt_length, std::uint32_t iterations,
              std::uint8_t* output, std::size_t output_length) noexcept {
    if (iterations == 0) {
        return Status::invalid_iterations;
    }
    if (output_length == 0 || output_length > max_output_bytes) {
        return Status::invalid_output_length;
    }
    if (password_length > native_hmac_sha256::max_key_bytes || salt_length > max_salt_bytes) {
        return Status::input_too_long;
    }
    if ((password == nullptr && password_length != 0) || (salt == nullptr && salt_length != 0) ||
        output == nullptr) {
        return Status::invalid_argument;
    }

    native_hmac_sha256::Hmac keyed;
    // Length and pointer checks above establish the internal HMAC preconditions.
    (void)keyed.set_key(password, password_length);
    for (std::size_t offset = 0; offset < output_length;) {
        const auto index = static_cast<std::uint32_t>(offset / native_hmac_sha256::tag_size + 1);
        const auto bytes = block(keyed, salt, salt_length, index, iterations);
        const auto count = std::min(bytes.size(), output_length - offset);
        std::copy_n(bytes.begin(), count, output + offset);
        offset += count;
    }
    return Status::ok;
}

}  // namespace abc::native_pbkdf2_sha256
