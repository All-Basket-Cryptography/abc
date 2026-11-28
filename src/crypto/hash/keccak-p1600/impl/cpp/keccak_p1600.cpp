#include "keccak_p1600.hpp"

#include <algorithm>
#include <utility>

namespace abc::native_keccak_p1600 {
namespace {

constexpr std::array<std::uint64_t, 24> round_constants{
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

struct Move {
    std::size_t destination;
    unsigned rotation;
};

constexpr std::array<Move, 24> make_rho_pi() noexcept {
    std::array<Move, 24> moves{};
    unsigned x = 1, y = 0;
    for (unsigned step = 0; step < moves.size(); ++step) {
        const unsigned next_y = (2 * x + 3 * y) % 5;
        x = y;
        y = next_y;
        moves[step] = {x + 5 * y, ((step + 1) * (step + 2) / 2) % 64};
    }
    return moves;
}

constexpr auto rho_pi = make_rho_pi();

constexpr bool valid_cycle() noexcept {
    std::array<bool, 25> seen{};
    for (const auto move : rho_pi) {
        if (move.destination == 0 || move.destination >= seen.size() || seen[move.destination]
            || move.rotation == 0 || move.rotation >= 64) {
            return false;
        }
        seen[move.destination] = true;
    }
    return rho_pi.back().destination == 1;
}

static_assert(valid_cycle(), "rho/pi must visit each nonzero lane once");

constexpr std::uint64_t rotl(std::uint64_t word, unsigned distance) noexcept {
    return (word << distance) | (word >> (64 - distance));
}

template<std::size_t... Steps>
void apply_rho_pi(State& state, std::index_sequence<Steps...>) noexcept {
    auto saved = state[1];
    const auto move = [&](Move operation) {
        const auto previous = state[operation.destination];
        state[operation.destination] = rotl(saved, operation.rotation);
        saved = previous;
    };
    (move(rho_pi[Steps]), ...);
}

std::uint64_t load_lane(const std::uint8_t* bytes) noexcept {
    return std::uint64_t{bytes[0]} | (std::uint64_t{bytes[1]} << 8)
        | (std::uint64_t{bytes[2]} << 16) | (std::uint64_t{bytes[3]} << 24)
        | (std::uint64_t{bytes[4]} << 32) | (std::uint64_t{bytes[5]} << 40)
        | (std::uint64_t{bytes[6]} << 48) | (std::uint64_t{bytes[7]} << 56);
}

void store_lane(std::uint8_t* bytes, std::uint64_t word) noexcept {
    for (unsigned i = 0; i < 8; ++i) {
        bytes[i] = static_cast<std::uint8_t>(word >> (8 * i));
    }
}

void xor_byte(State& state, std::size_t offset, std::uint8_t byte) noexcept {
    state[offset / 8] ^= std::uint64_t{byte} << (8 * (offset % 8));
}

std::uint8_t read_byte(const State& state, std::size_t offset) noexcept {
    return static_cast<std::uint8_t>(state[offset / 8] >> (8 * (offset % 8)));
}

}  // namespace

void permute(State& state) noexcept {
    for (const auto constant : round_constants) {
        // Theta column parity.
        std::array<std::uint64_t, 5> parity;
        for (std::size_t x = 0; x < 5; ++x) {
            parity[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (std::size_t x = 0; x < 5; ++x) {
            const auto delta = parity[(x + 4) % 5] ^ rotl(parity[(x + 1) % 5], 1);
            for (std::size_t i = x; i < state.size(); i += 5) {
                state[i] ^= delta;
            }
        }

        // Rho and pi act as a 24-lane cycle and leave lane zero in place.
        apply_rho_pi(state, std::make_index_sequence<rho_pi.size()>{});

        // Chi operates on one saved row at a time.
        for (std::size_t offset = 0; offset < state.size(); offset += 5) {
            const auto a = state[offset], b = state[offset + 1], c = state[offset + 2];
            const auto d = state[offset + 3], e = state[offset + 4];
            state[offset] = a ^ (~b & c);
            state[offset + 1] = b ^ (~c & d);
            state[offset + 2] = c ^ (~d & e);
            state[offset + 3] = d ^ (~e & a);
            state[offset + 4] = e ^ (~a & b);
        }

        // Iota.
        state[0] ^= constant;
    }
}

Status Sponge::absorb(const std::uint8_t* input, std::size_t length) noexcept {
    if (length == 0) {
        return Status::ok;
    }
    if (input == nullptr) {
        return Status::invalid_argument;
    }

    if (offset_ != 0) {
        const auto count = std::min(length, rate - offset_);
        for (std::size_t i = 0; i < count; ++i) {
            xor_byte(state_, offset_ + i, input[i]);
        }
        offset_ += count;
        if (offset_ < rate) {
            return Status::ok;
        }
        permute(state_);
        input += count;
        length -= count;
    }
    while (length >= rate) {
        for (std::size_t lane = 0; lane < rate / 8; ++lane) {
            state_[lane] ^= load_lane(input + lane * 8);
        }
        permute(state_);
        input += rate;
        length -= rate;
    }
    for (std::size_t i = 0; i < length; ++i) {
        xor_byte(state_, i, input[i]);
    }
    offset_ = length;
    return Status::ok;
}

Reader Sponge::finish(Domain domain) const noexcept {
    Reader reader(state_);
    xor_byte(reader.state_, offset_, static_cast<std::uint8_t>(domain));
    xor_byte(reader.state_, rate - 1, 0x80);
    permute(reader.state_);
    return reader;
}

void Sponge::reset() noexcept { *this = Sponge{}; }

Status Reader::read(std::uint8_t* output, std::size_t length) noexcept {
    if (output == nullptr && length != 0) {
        return Status::invalid_argument;
    }
    while (length != 0) {
        if (offset_ == rate) {
            permute(state_);
            offset_ = 0;
        }
        const auto count = std::min(length, rate - offset_);
        std::size_t i = 0;
        while (i < count && (offset_ + i) % 8 != 0) {
            output[i] = read_byte(state_, offset_ + i);
            ++i;
        }
        for (; count - i >= 8; i += 8) {
            store_lane(output + i, state_[(offset_ + i) / 8]);
        }
        for (; i < count; ++i) {
            output[i] = read_byte(state_, offset_ + i);
        }
        offset_ += count;
        output += count;
        length -= count;
    }
    return Status::ok;
}

}  // namespace abc::native_keccak_p1600
