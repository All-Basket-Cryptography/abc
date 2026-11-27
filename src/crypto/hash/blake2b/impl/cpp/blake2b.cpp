#include "blake2b.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace abc::native_blake2b {
namespace {

using ChainingValue = std::array<std::uint64_t, 8>;
using WorkingState = std::array<std::uint64_t, 16>;

constexpr ChainingValue iv{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

constexpr std::size_t sigma[10][16]{
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

constexpr std::uint64_t load_le(const std::uint8_t* input) noexcept {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < 8; ++i) {
        result |= static_cast<std::uint64_t>(input[i]) << (8U * i);
    }
    return result;
}

template<unsigned Bits>
constexpr std::uint64_t rotate_right(std::uint64_t value) noexcept {
    return (value >> Bits) | (value << (64U - Bits));
}

inline void mix(std::uint64_t& a, std::uint64_t& b, std::uint64_t& c, std::uint64_t& d,
                const std::uint64_t x, const std::uint64_t y) noexcept {
    a += b + x;
    d = rotate_right<32>(d ^ a);
    c += d;
    b = rotate_right<24>(b ^ c);
    a += b + y;
    d = rotate_right<16>(d ^ a);
    c += d;
    b = rotate_right<63>(b ^ c);
}

void compress(ChainingValue& state, const std::uint8_t* input,
              detail::Counter count, bool last) noexcept {
    WorkingState words;
    for (std::size_t i = 0; i < words.size(); ++i) {
        words[i] = load_le(input + 8 * i);
    }
    WorkingState v{
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        iv[0], iv[1], iv[2], iv[3], iv[4] ^ count.low, iv[5] ^ count.high,
        last ? ~iv[6] : iv[6], iv[7],
    };

    for (std::size_t round = 0; round < 12; ++round) {
        const auto& s = sigma[round % 10];
        mix(v[0], v[4], v[8],  v[12], words[s[0]],  words[s[1]]);
        mix(v[1], v[5], v[9],  v[13], words[s[2]],  words[s[3]]);
        mix(v[2], v[6], v[10], v[14], words[s[4]],  words[s[5]]);
        mix(v[3], v[7], v[11], v[15], words[s[6]],  words[s[7]]);
        mix(v[0], v[5], v[10], v[15], words[s[8]],  words[s[9]]);
        mix(v[1], v[6], v[11], v[12], words[s[10]], words[s[11]]);
        mix(v[2], v[7], v[8],  v[13], words[s[12]], words[s[13]]);
        mix(v[3], v[4], v[9],  v[14], words[s[14]], words[s[15]]);
    }
    for (std::size_t i = 0; i < state.size(); ++i) {
        state[i] ^= v[i] ^ v[i + state.size()];
    }
}

}  // namespace

bool detail::Counter::add(std::uint64_t bytes) noexcept {
    const auto sum = low + bytes;
    const bool carry = sum < low;
    if (carry && high == std::numeric_limits<std::uint64_t>::max()) {
        return false;
    }
    low = sum;
    high += carry;
    return true;
}

Hasher::Hasher() noexcept {
    reset();
}

std::size_t Hasher::digest_size() const noexcept {
    return digest_size_;
}

void Hasher::reset() noexcept {
    state_ = iv;
    state_[0] ^= UINT64_C(0x01010000) | static_cast<std::uint64_t>(digest_size_);
    count_ = {};
    used_ = 0;
}

Status Hasher::reset(std::size_t digest_size) noexcept {
    if (digest_size == 0 || digest_size > max_digest_size) {
        return Status::invalid_digest_size;
    }
    digest_size_ = digest_size;
    reset();
    return Status::ok;
}

Status Hasher::update(const std::uint8_t* input, std::size_t length) noexcept {
    static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));
    if (length == 0) {
        return Status::ok;
    }
    if (input == nullptr) {
        return Status::invalid_buffer;
    }

    // count_ records compressed bytes. Check the total before changing either buffer.
    auto total = count_;
    if (!total.add(used_) || !total.add(length)) {
        return Status::message_limit;
    }

    const auto available = block_size - used_;
    if (length <= available) {
        std::memcpy(pending_.data() + used_, input, length);
        used_ += length;
        return Status::ok;
    }

    if (used_ != 0) {
        std::memcpy(pending_.data() + used_, input, available);
        input += available;
        length -= available;
        static_cast<void>(count_.add(block_size));
        compress(state_, pending_.data(), count_, false);
    }
    while (length > block_size) {
        static_cast<void>(count_.add(block_size));
        compress(state_, input, count_, false);
        input += block_size;
        length -= block_size;
    }
    std::memcpy(pending_.data(), input, length);
    used_ = length;
    return Status::ok;
}

Status Hasher::digest(std::uint8_t* output, std::size_t length) const noexcept {
    if (length != digest_size_) {
        return Status::invalid_digest_size;
    }
    if (output == nullptr) {
        return Status::invalid_buffer;
    }
    auto state = state_;
    auto count = count_;
    auto block = pending_;
    std::fill(block.begin() + static_cast<std::ptrdiff_t>(used_), block.end(), 0);
    static_cast<void>(count.add(used_));
    compress(state, block.data(), count, true);
    for (std::size_t i = 0; i < length; ++i) {
        output[i] = static_cast<std::uint8_t>(state[i / 8] >> (8 * (i % 8)));
    }
    return Status::ok;
}

Status hash(const std::uint8_t* input, std::size_t length,
            std::uint8_t* output, std::size_t output_length) noexcept {
    Hasher context;
    if (const auto status = context.reset(output_length); status != Status::ok) {
        return status;
    }
    if (output == nullptr) {
        return Status::invalid_buffer;
    }
    if (const auto status = context.update(input, length); status != Status::ok) {
        return status;
    }
    return context.digest(output, output_length);
}

}  // namespace abc::native_blake2b
