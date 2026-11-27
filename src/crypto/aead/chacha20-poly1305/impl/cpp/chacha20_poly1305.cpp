#include "chacha20_poly1305.hpp"

#include <algorithm>
#include <limits>

namespace abc::native_chacha20_poly1305 {
namespace {

namespace chacha = abc::native_chacha20;
namespace poly = abc::native_poly1305;

Status validate(const std::uint8_t* associated, std::size_t associated_length,
                const std::uint8_t* input, std::size_t length, std::uint8_t* output,
                std::size_t capacity) noexcept {
    static_assert(std::numeric_limits<std::size_t>::digits <= 64);
    if ((associated_length != 0 && associated == nullptr) ||
        (length != 0 && (input == nullptr || output == nullptr))) {
        return Status::invalid_argument;
    }
    if (capacity < length) {
        return Status::output_too_short;
    }
    if (!chacha::fits_counter(length, 1)) {
        return Status::counter_range;
    }
    return Status::ok;
}

bool overlaps_tag(const std::uint8_t* output, std::size_t length, const Tag& tag) noexcept {
    if (length == 0) {
        return false;
    }
    const auto first = reinterpret_cast<std::uintptr_t>(output);
    const auto second = reinterpret_cast<std::uintptr_t>(tag.data());
    return first <= second ? second - first < length : first - second < tag.size();
}

template<std::size_t N>
void erase(std::array<std::uint8_t, N>& material) noexcept {
    volatile std::uint8_t* bytes = material.data();
    for (std::size_t i = 0; i < N; ++i) {
        bytes[i] = 0;
    }
}

poly::Key derive_poly_key(const Key& key, const Nonce& nonce) noexcept {
    auto block = chacha::stream_block(key, nonce, 0);
    poly::Key seed{};
    std::copy_n(block.begin(), seed.size(), seed.begin());
    erase(block);
    return seed;
}

void padded(poly::Mac& mac, const std::uint8_t* input, std::size_t length) noexcept {
    constexpr std::array<std::uint8_t, 16> padding{};
    const auto zeroes = (padding.size() - length % padding.size()) % padding.size();
    (void)mac.update(input, length);
    (void)mac.update(padding.data(), zeroes);
}

Tag finish_mac(poly::Mac& mac, const std::uint8_t* ciphertext, std::size_t length,
               std::size_t aad_length) noexcept {
    padded(mac, ciphertext, length);
    std::array<std::uint8_t, 16> lengths{};
    for (std::size_t i = 0; i < 8; ++i) {
        lengths[i] = static_cast<std::uint8_t>(std::uint64_t{aad_length} >> (8 * i));
        lengths[8 + i] = static_cast<std::uint8_t>(std::uint64_t{length} >> (8 * i));
    }
    (void)mac.update(lengths.data(), lengths.size());
    return mac.finish();
}

}  // namespace

Status seal_detached(const Key& key, const Nonce& nonce, const std::uint8_t* aad,
                     std::size_t aad_length, const std::uint8_t* input, std::size_t length,
                     std::uint8_t* output, std::size_t capacity, Tag& tag) noexcept {
    const auto status = validate(aad, aad_length, input, length, output, capacity);
    if (status != Status::ok) {
        return status;
    }
    if (overlaps_tag(output, length, tag)) {
        return Status::invalid_argument;
    }
    auto seed = derive_poly_key(key, nonce);
    poly::Mac mac(seed);
    erase(seed);
    padded(mac, aad, aad_length);
    (void)chacha::apply(key, nonce, 1, input, length, output, capacity);
    tag = finish_mac(mac, output, length, aad_length);
    return Status::ok;
}

Status open_detached(const Key& key, const Nonce& nonce, const std::uint8_t* aad,
                     std::size_t aad_length, const std::uint8_t* input, std::size_t length,
                     std::uint8_t* output, std::size_t capacity, const Tag& tag) noexcept {
    const auto status = validate(aad, aad_length, input, length, output, capacity);
    if (status != Status::ok) {
        return status;
    }
    auto seed = derive_poly_key(key, nonce);
    poly::Mac mac(seed);
    erase(seed);
    padded(mac, aad, aad_length);
    const auto expected = finish_mac(mac, input, length, aad_length);
    volatile unsigned mismatch = 0;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        mismatch = mismatch | (expected[i] ^ tag[i]);
    }
    if (mismatch != 0) {
        return Status::authentication_failed;
    }
    (void)chacha::apply(key, nonce, 1, input, length, output, capacity);
    return Status::ok;
}

}  // namespace abc::native_chacha20_poly1305
