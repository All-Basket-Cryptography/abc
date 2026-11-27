#include "poly1305.hpp"

#include <algorithm>
#include <cstring>

namespace abc::native_poly1305 {
namespace {

using Limbs = std::array<std::uint64_t, 5>;
constexpr auto limb_mask = (std::uint64_t{1} << 26) - 1;
constexpr auto full_bit = std::uint64_t{1} << 24;

void zero_bytes(void* data, std::size_t length) noexcept {
    auto* bytes = static_cast<volatile unsigned char*>(data);
    for (std::size_t i = 0; i < length; ++i) {
        bytes[i] = 0;
    }
}

std::uint32_t load_word(const std::uint8_t* source) noexcept {
    return std::uint32_t{source[0]} | std::uint32_t{source[1]} << 8 |
           std::uint32_t{source[2]} << 16 | std::uint32_t{source[3]} << 24;
}

Limbs unpack(const std::uint8_t* data) noexcept {
    const std::uint64_t a = load_word(data), b = load_word(data + 4);
    const std::uint64_t c = load_word(data + 8), d = load_word(data + 12);
    return {a & limb_mask, (a >> 26 | b << 6) & limb_mask,
            (b >> 20 | c << 12) & limb_mask, (c >> 14 | d << 18) & limb_mask, d >> 8};
}

void carry(Limbs& limbs) noexcept {
    for (std::size_t i = 0; i + 1 < limbs.size(); ++i) {
        limbs[i + 1] += limbs[i] >> 26;
        limbs[i] &= limb_mask;
    }
    limbs[0] += (limbs[4] >> 26) * 5;
    limbs[4] &= limb_mask;
    limbs[1] += limbs[0] >> 26;
    limbs[0] &= limb_mask;
}

}  // namespace

Mac::Mac(const Key& key) noexcept {
    std::array<std::uint8_t, 16> clamped{};
    std::copy_n(key.begin(), clamped.size(), clamped.begin());
    for (std::size_t i = 0; i < pad_.size(); ++i) {
        clamped[4 * i + 3] &= 15;
        pad_[i] = load_word(key.data() + 16 + 4 * i);
    }
    for (std::size_t i = 4; i < clamped.size(); i += 4) {
        clamped[i] &= 252;
    }
    r_ = unpack(clamped.data());
    for (std::size_t i = 1; i < r_.size(); ++i) {
        folded_[i] = 5 * r_[i];
    }
    zero_bytes(clamped.data(), clamped.size());
}

Mac::~Mac() noexcept { erase(); }

void Mac::erase() noexcept {
    zero_bytes(h_.data(), sizeof(h_));
    zero_bytes(r_.data(), sizeof(r_));
    zero_bytes(folded_.data(), sizeof(folded_));
    zero_bytes(pad_.data(), sizeof(pad_));
    zero_bytes(pending_.data(), sizeof(pending_));
    used_ = 0;
}

void Mac::absorb(const std::uint8_t* block, std::uint64_t high_bit) noexcept {
    auto h = unpack(block);
    for (std::size_t i = 0; i < h.size(); ++i) {
        h[i] += h_[i];
    }
    h[4] += high_bit;
    h_.fill(0);
    for (std::size_t i = 0; i < h.size(); ++i) {
        for (std::size_t j = 0; j < r_.size(); ++j) {
            const auto column = i + j;
            if (column < h_.size()) {
                h_[column] += h[i] * r_[j];
            } else {
                h_[column - h_.size()] += h[i] * folded_[j];
            }
        }
    }
    carry(h_);
}

Status Mac::update(const std::uint8_t* input, std::size_t length) noexcept {
    if (input == nullptr && length != 0) {
        return Status::invalid_argument;
    }
    if (finished_) {
        return Status::state;
    }
    if (length == 0) {
        return Status::ok;
    }
    if (used_ != 0) {
        const auto width = std::min(length, pending_.size() - used_);
        std::memcpy(pending_.data() + used_, input, width);
        used_ += width;
        if (used_ < pending_.size()) {
            return Status::ok;
        }
        absorb(pending_.data(), full_bit);
        input += width;
        length -= width;
        used_ = 0;
    }
    while (length >= pending_.size()) {
        absorb(input, full_bit);
        input += pending_.size();
        length -= pending_.size();
    }
    if (length != 0) {
        std::memcpy(pending_.data(), input, length);
        used_ = length;
    }
    return Status::ok;
}

Tag Mac::finish() noexcept {
    if (finished_) {
        return tag_;
    }
    if (used_ != 0) {
        std::fill(pending_.begin() + used_, pending_.end(), 0);
        pending_[used_] = 1;
        absorb(pending_.data(), 0);
    }
    carry(h_);
    auto reduced = h_;
    reduced[0] += 5;
    for (std::size_t i = 0; i + 1 < reduced.size(); ++i) {
        reduced[i + 1] += reduced[i] >> 26;
        reduced[i] &= limb_mask;
    }
    const auto mask = std::uint64_t{0} - (reduced[4] >> 26);
    reduced[4] &= limb_mask;
    for (std::size_t i = 0; i < h_.size(); ++i) {
        h_[i] ^= (h_[i] ^ reduced[i]) & mask;
    }
    const std::array<std::uint32_t, 4> words{
        static_cast<std::uint32_t>(h_[0] | h_[1] << 26),
        static_cast<std::uint32_t>(h_[1] >> 6 | h_[2] << 20),
        static_cast<std::uint32_t>(h_[2] >> 12 | h_[3] << 14),
        static_cast<std::uint32_t>(h_[3] >> 18 | h_[4] << 8),
    };
    std::uint64_t sum = 0;
    for (std::size_t word = 0; word < words.size(); ++word) {
        sum = (sum >> 32) + words[word] + pad_[word];
        for (std::size_t byte = 0; byte < 4; ++byte) {
            tag_[4 * word + byte] = static_cast<std::uint8_t>(sum >> (8 * byte));
        }
    }
    erase();
    finished_ = true;
    return tag_;
}

Status authenticate(const Key& key, const std::uint8_t* input, std::size_t length,
                    Tag& output) noexcept {
    Mac mac(key);
    const auto outcome = mac.update(input, length);
    if (outcome == Status::ok) {
        output = mac.finish();
    }
    return outcome;
}

}  // namespace abc::native_poly1305
