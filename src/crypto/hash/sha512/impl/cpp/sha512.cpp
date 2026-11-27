#include "sha512.hpp"

#include <algorithm>
#include <limits>

namespace abc::native_sha512 {
namespace {

using State = std::array<std::uint64_t, 8>;
static_assert(std::numeric_limits<std::size_t>::digits <= 64);

// FIPS 180-4 § 4.2.3.
constexpr std::array<std::uint64_t, 80> round_constants{
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

constexpr std::uint64_t rotate_right(std::uint64_t word, unsigned distance) noexcept {
    return (word >> distance) | (word << (64U - distance));
}

std::uint64_t load_word(const std::uint8_t* input) noexcept {
    return (std::uint64_t{input[0]} << 56) | (std::uint64_t{input[1]} << 48)
        | (std::uint64_t{input[2]} << 40) | (std::uint64_t{input[3]} << 32)
        | (std::uint64_t{input[4]} << 24) | (std::uint64_t{input[5]} << 16)
        | (std::uint64_t{input[6]} << 8) | std::uint64_t{input[7]};
}

void store_word(std::uint8_t* output, std::uint64_t word) noexcept {
    for (unsigned byte = 0; byte < 8; ++byte) {
        output[byte] = static_cast<std::uint8_t>(word >> (56 - byte * 8));
    }
}

constexpr bool add_length(std::uint64_t& high, std::uint64_t& low, std::uint64_t count) noexcept {
    const auto next_low = low + count;
    const auto next_high = high + (next_low < low);
    if (next_high >= (std::uint64_t{1} << 61)) {
        return false;
    }
    high = next_high;
    low = next_low;
    return true;
}

constexpr bool length_boundaries() noexcept {
    std::uint64_t high = 3, low = UINT64_MAX;
    if (!add_length(high, low, 1) || high != 4 || low != 0) {
        return false;
    }
    high = (std::uint64_t{1} << 61) - 1;
    low = UINT64_MAX - 1;
    return add_length(high, low, 1) && !add_length(high, low, 1)
        && add_length(high, low, 0) && high == (std::uint64_t{1} << 61) - 1 && low == UINT64_MAX;
}

static_assert(length_boundaries(), "SHA-512 byte counter bounds");

// FIPS 180-4 §§ 5.2.2 and 6.4.2.
void compress(State& state, const std::uint8_t* block) noexcept {
    std::array<std::uint64_t, 80> words;
    for (std::size_t i = 0; i < 16; ++i) {
        words[i] = load_word(block + i * 8);
    }
    for (std::size_t i = 16; i < words.size(); ++i) {
        const auto a = words[i - 15];
        const auto b = words[i - 2];
        const auto low = rotate_right(a, 1) ^ rotate_right(a, 8) ^ (a >> 7);
        const auto high = rotate_right(b, 19) ^ rotate_right(b, 61) ^ (b >> 6);
        words[i] = words[i - 16] + low + words[i - 7] + high;
    }

    auto [a, b, c, d, e, f, g, h] = state;
    for (std::size_t i = 0; i < words.size(); ++i) {
        const auto upper = rotate_right(e, 14) ^ rotate_right(e, 18) ^ rotate_right(e, 41);
        const auto choose = (e & f) ^ (~e & g);
        const auto first = h + upper + choose + round_constants[i] + words[i];
        const auto lower = rotate_right(a, 28) ^ rotate_right(a, 34) ^ rotate_right(a, 39);
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
    if (length == 0) {
        return Status::ok;
    }
    if (input == nullptr) {
        return Status::invalid_argument;
    }
    if (!add_length(bytes_high_, bytes_low_, static_cast<std::uint64_t>(length))) {
        return Status::message_too_long;
    }

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
    const auto end = used_ < block_size - 16 ? block_size : 2 * block_size;
    store_word(final_blocks.data() + end - 16, (bytes_high_ << 3) | (bytes_low_ >> 61));
    store_word(final_blocks.data() + end - 8, bytes_low_ << 3);
    for (std::size_t offset = 0; offset < end; offset += block_size) {
        compress(state, final_blocks.data() + offset);
    }

    Digest result{};
    for (std::size_t i = 0; i < state.size(); ++i) {
        store_word(result.data() + i * 8, state[i]);
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

}  // namespace abc::native_sha512
