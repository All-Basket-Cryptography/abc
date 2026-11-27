#include "chacha20.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace abc::native_chacha20 {
namespace {

using Word = std::uint32_t;
using State = std::array<Word, 16>;

Word load_word(const std::uint8_t* bytes) noexcept {
    return Word{bytes[0]} | Word{bytes[1]} << 8 | Word{bytes[2]} << 16 | Word{bytes[3]} << 24;
}

Word rotate_left(Word word, unsigned distance) noexcept {
    return (word << distance) | (word >> (32 - distance));
}

void quarter_round(Word& a, Word& b, Word& c, Word& d) noexcept {
    a += b;
    d = rotate_left(d ^ a, 16);
    c += d;
    b = rotate_left(b ^ c, 12);
    a += b;
    d = rotate_left(d ^ a, 8);
    c += d;
    b = rotate_left(b ^ c, 7);
}

State initialize(const Key& key, const Nonce& nonce) noexcept {
    State initial{0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U};
    for (std::size_t i = 0; i < key.size() / 4; ++i) {
        initial[4 + i] = load_word(key.data() + 4 * i);
    }
    for (std::size_t i = 0; i < nonce.size() / 4; ++i) {
        initial[13 + i] = load_word(nonce.data() + 4 * i);
    }
    return initial;
}

Block generate(State& initial, Word counter) noexcept {
    initial[12] = counter;
    auto state = initial;
    for (int round = 0; round < 10; ++round) {
        for (std::size_t column = 0; column < 4; ++column) {
            quarter_round(state[column], state[4 + column], state[8 + column], state[12 + column]);
        }
        for (std::size_t diagonal = 0; diagonal < 4; ++diagonal) {
            quarter_round(state[diagonal], state[4 + (diagonal + 1) % 4],
                          state[8 + (diagonal + 2) % 4], state[12 + (diagonal + 3) % 4]);
        }
    }
    Block output{};
    for (std::size_t i = 0; i < state.size(); ++i) {
        const auto word = state[i] + initial[i];
        for (std::size_t byte = 0; byte < 4; ++byte) {
            output[4 * i + byte] = static_cast<std::uint8_t>(word >> (8 * byte));
        }
    }
    return output;
}

}  // namespace

bool fits_counter(std::uint64_t bytes, std::uint32_t counter) noexcept {
    return bytes == 0 || (bytes - 1) / block_size < (std::uint64_t{1} << 32) - counter;
}

Block stream_block(const Key& key, const Nonce& nonce, std::uint32_t counter) noexcept {
    auto initial = initialize(key, nonce);
    return generate(initial, counter);
}

Status apply(const Key& key, const Nonce& nonce, std::uint32_t counter,
             const std::uint8_t* input, std::size_t length, std::uint8_t* output,
             std::size_t capacity) noexcept {
    static_assert(std::numeric_limits<std::size_t>::digits <= 64);
    if (length != 0 && (input == nullptr || output == nullptr)) {
        return Status::invalid_argument;
    }
    if (capacity < length) {
        return Status::output_too_short;
    }
    if (!fits_counter(length, counter)) {
        return Status::counter_range;
    }
    if (length == 0) {
        return Status::ok;
    }
    auto initial = initialize(key, nonce);
    std::memmove(output, input, length);
    while (length != 0) {
        const auto block = generate(initial, counter++);
        const auto width = std::min(block.size(), length);
        for (std::size_t i = 0; i < width; ++i) {
            output[i] ^= block[i];
        }
        output += width;
        length -= width;
    }
    return Status::ok;
}

}  // namespace abc::native_chacha20
