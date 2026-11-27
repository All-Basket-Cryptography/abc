#include "sha256.hpp"

#include <algorithm>

namespace abc::native_sha256 {
namespace {

using State = std::array<std::uint32_t, 8>;

// FIPS 180-4 § 4.2.2.
constexpr std::array<std::uint32_t, 64> round_constants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

constexpr std::uint32_t rotate_right(std::uint32_t word, unsigned distance) noexcept {
    return (word >> distance) | (word << (32U - distance));
}

std::uint32_t load_word(const std::uint8_t* input) noexcept {
    return (std::uint32_t{input[0]} << 24) | (std::uint32_t{input[1]} << 16)
        | (std::uint32_t{input[2]} << 8) | std::uint32_t{input[3]};
}

// FIPS 180-4 §§ 5.2.1 and 6.2.2.
void compress(State& state, const std::uint8_t* block) noexcept {
    std::array<std::uint32_t, 64> words;
    for (std::size_t i = 0; i < 16; ++i) {
        words[i] = load_word(block + i * 4);
    }
    for (std::size_t i = 16; i < words.size(); ++i) {
        const auto a = words[i - 15];
        const auto b = words[i - 2];
        const auto low = rotate_right(a, 7) ^ rotate_right(a, 18) ^ (a >> 3);
        const auto high = rotate_right(b, 17) ^ rotate_right(b, 19) ^ (b >> 10);
        words[i] = words[i - 16] + low + words[i - 7] + high;
    }

    auto [a, b, c, d, e, f, g, h] = state;
    for (std::size_t i = 0; i < words.size(); ++i) {
        const auto upper = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        const auto choose = (e & f) ^ (~e & g);
        const auto first = h + upper + choose + round_constants[i] + words[i];
        const auto lower = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        const auto majority = (a & b) ^ (a & c) ^ (b & c);
        const auto second = lower + majority;
        h = g;
        g = f;
        f = e;
        e = d + first;
        d = c;
        c = b;
        b = a;
        a = first + second;
    }
    const State work{a, b, c, d, e, f, g, h};
    for (std::size_t i = 0; i < state.size(); ++i) {
        state[i] += work[i];
    }
}

}  // namespace

Status Hasher::update(const std::uint8_t* input, std::size_t length) noexcept {
    if (length > max_message_bytes - length_) {
        return Status::message_too_long;
    }
    if (length == 0) {
        return Status::ok;
    }
    if (input == nullptr) {
        return Status::invalid_argument;
    }
    length_ += static_cast<std::uint64_t>(length);

    if (used_ != 0) {
        const auto count = std::min(length, block_size - used_);
        std::copy_n(input, count, pending_.data() + used_);
        used_ += count;
        if (used_ < block_size) {
            return Status::ok;
        }
        compress(state_, pending_.data());
        input += count;
        length -= count;
    }
    while (length >= block_size) {
        compress(state_, input);
        input += block_size;
        length -= block_size;
    }
    std::copy_n(input, length, pending_.data());
    used_ = length;
    return Status::ok;
}

Digest Hasher::digest() const noexcept {
    auto state = state_;
    std::array<std::uint8_t, 2 * block_size> final_blocks{};
    std::copy_n(pending_.data(), used_, final_blocks.data());
    final_blocks[used_] = 0x80;
    const auto end = used_ < block_size - 8 ? block_size : 2 * block_size;
    const auto bits = length_ * 8;
    for (unsigned byte = 0; byte < 8; ++byte) {
        final_blocks[end - 1 - byte] = static_cast<std::uint8_t>(bits >> (byte * 8));
    }
    for (std::size_t offset = 0; offset < end; offset += block_size) {
        compress(state, final_blocks.data() + offset);
    }

    Digest result{};
    for (std::size_t i = 0; i < state.size(); ++i) {
        for (unsigned byte = 0; byte < 4; ++byte) {
            result[i * 4 + byte] = static_cast<std::uint8_t>(state[i] >> (24 - byte * 8));
        }
    }
    return result;
}

void Hasher::reset() noexcept { *this = Hasher{}; }

Status hash(const std::uint8_t* input, std::size_t length, Digest& result) noexcept {
    Hasher hasher;
    const auto status = hasher.update(input, length);
    if (status == Status::ok) {
        result = hasher.digest();
    }
    return status;
}

}  // namespace abc::native_sha256
