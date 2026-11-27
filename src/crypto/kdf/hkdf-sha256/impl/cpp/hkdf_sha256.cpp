#include "hkdf_sha256.hpp"

#include <algorithm>

namespace abc::native_hkdf_sha256 {
namespace {

Status validate_expansion(const std::uint8_t* info, std::size_t info_length,
                          const std::uint8_t* output, std::size_t output_length) noexcept {
    if (output_length > max_output_bytes) {
        return Status::output_too_long;
    }
    if (info_length > max_info_bytes) {
        return Status::input_too_long;
    }
    if ((info == nullptr && info_length != 0) || (output == nullptr && output_length != 0)) {
        return Status::invalid_argument;
    }
    return Status::ok;
}

Status mac_status(native_hmac_sha256::Status status) noexcept {
    if (status == native_hmac_sha256::Status::ok) {
        return Status::ok;
    }
    return status == native_hmac_sha256::Status::message_too_long
        ? Status::input_too_long : Status::invalid_argument;
}

}  // namespace

Status extract(const std::uint8_t* salt, std::size_t salt_length,
               const std::uint8_t* ikm, std::size_t ikm_length, Prk& output) noexcept {
    // An empty HMAC key and a 32-byte zero key have the same padded key.
    return mac_status(native_hmac_sha256::authenticate(salt, salt_length, ikm, ikm_length, output));
}

Status expand(const std::uint8_t* prk, std::size_t prk_length,
              const std::uint8_t* info, std::size_t info_length,
              std::uint8_t* output, std::size_t output_length) noexcept {
    if (prk_length < Prk{}.size()) {
        return Status::prk_too_short;
    }
    if (const auto status = validate_expansion(info, info_length, output, output_length); status != Status::ok) {
        return status;
    }
    native_hmac_sha256::Hmac keyed;
    if (const auto status = mac_status(keyed.set_key(prk, prk_length)); status != Status::ok) {
        return status;
    }
    Prk previous{};
    for (std::size_t offset = 0; offset < output_length; offset += previous.size()) {
        auto hmac = keyed;
        const auto counter = static_cast<std::uint8_t>(offset / previous.size() + 1);
        // Admission bounds reserve room for the previous block and counter.
        if (offset != 0) {
            (void)hmac.update(previous.data(), previous.size());
        }
        (void)hmac.update(info, info_length);
        (void)hmac.update(&counter, 1);
        previous = hmac.digest();
        std::copy_n(previous.begin(), std::min(previous.size(), output_length - offset), output + offset);
    }
    return Status::ok;
}

Status derive(const std::uint8_t* salt, std::size_t salt_length,
              const std::uint8_t* ikm, std::size_t ikm_length,
              const std::uint8_t* info, std::size_t info_length,
              std::uint8_t* output, std::size_t output_length) noexcept {
    if (const auto status = validate_expansion(info, info_length, output, output_length); status != Status::ok) {
        return status;
    }
    Prk prk{};
    if (const auto status = extract(salt, salt_length, ikm, ikm_length, prk); status != Status::ok) {
        return status;
    }
    return expand(prk.data(), prk.size(), info, info_length, output, output_length);
}

}  // namespace abc::native_hkdf_sha256
