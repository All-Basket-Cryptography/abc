#include "scrypt.hpp"
#include "pbkdf2_sha256.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace abc::native_scrypt {
namespace {

namespace pbkdf2 = native_pbkdf2_sha256;
using Words = std::array<std::uint32_t, 16>;

struct Layout {
    std::size_t lane;
    std::size_t lanes;
    std::size_t table;
    std::size_t total;
};

Status plan(Parameters params, Layout& result) noexcept {
    static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));
    const auto [n, r, p] = params;
    if (n < 2 || (n & (n - 1)) != 0 || r == 0 || p == 0
        || std::uint64_t{r} * p >= (std::uint64_t{1} << 30)
        || (r < 4 && n >= (std::uint64_t{1} << (16 * r)))) {
        return Status::bad_parameters;
    }
    constexpr auto max = std::numeric_limits<std::ptrdiff_t>::max();
    const auto lane = std::uint64_t{128} * r;
    const auto max_lanes = static_cast<std::size_t>(max / lane);
    if (p >= max_lanes || n >= max_lanes - p) {
        return Status::length_limit;
    }
    result.lane = static_cast<std::size_t>(lane);
    result.lanes = result.lane * p;
    result.table = result.lane * n;
    result.total = result.lanes + result.table + result.lane;
    return Status::ok;
}

std::uint32_t load_le(const std::uint8_t* bytes) noexcept {
    std::uint32_t value = 0;
    for (unsigned i = 0; i < 4; ++i) {
        value |= std::uint32_t{bytes[i]} << (8 * i);
    }
    return value;
}

void store_le(std::uint8_t* bytes, std::uint32_t value) noexcept {
    for (unsigned i = 0; i < 4; ++i) {
        bytes[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

template<unsigned Bits>
constexpr std::uint32_t rotate(std::uint32_t word) noexcept {
    return (word << Bits) | (word >> (32 - Bits));
}

void quarter(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) noexcept {
    b ^= rotate<7>(a + d);
    c ^= rotate<9>(b + a);
    d ^= rotate<13>(c + b);
    a ^= rotate<18>(d + c);
}

void salsa8(Words& input) noexcept {
    auto x = input;
    for (unsigned pair = 0; pair < 4; ++pair) {
        quarter(x[0],  x[4],  x[8],  x[12]);
        quarter(x[5],  x[9],  x[13], x[1]);
        quarter(x[10], x[14], x[2],  x[6]);
        quarter(x[15], x[3],  x[7],  x[11]);
        quarter(x[0],  x[1],  x[2],  x[3]);
        quarter(x[5],  x[6],  x[7],  x[4]);
        quarter(x[10], x[11], x[8],  x[9]);
        quarter(x[15], x[12], x[13], x[14]);
    }
    for (std::size_t i = 0; i < input.size(); ++i) {
        input[i] += x[i];
    }
}

void block_mix(const std::uint8_t* lane, std::size_t width, std::uint8_t* temp) noexcept {
    Words chain;
    const auto last = lane + width - 64;
    for (std::size_t i = 0; i < chain.size(); ++i) {
        chain[i] = load_le(last + 4 * i);
    }
    for (std::size_t position = 0; position < width / 64; ++position) {
        const auto source = lane + position * 64;
        const auto destination = temp + (position / 2) * 64 + (position % 2) * (width / 2);
        for (std::size_t i = 0; i < chain.size(); ++i) {
            chain[i] ^= load_le(source + 4 * i);
        }
        salsa8(chain);
        for (std::size_t i = 0; i < chain.size(); ++i) {
            store_le(destination + 4 * i, chain[i]);
        }
    }
}

void mix_lane(std::uint8_t* lane, std::size_t width, std::uint8_t* table, std::uint8_t* temp,
              std::size_t n) noexcept {
    for (std::size_t row = 0; row < n; ++row) {
        std::copy_n(lane, width, table + row * width);
        block_mix(lane, width, temp);
        std::swap(lane, temp);
    }
    for (std::size_t visit = 0; visit < n; ++visit) {
        const auto last = lane + width - 64;
        const auto integer = std::uint64_t{load_le(last)} | (std::uint64_t{load_le(last + 4)} << 32);
        const auto row = static_cast<std::size_t>(integer & (n - 1));
        const auto selected = table + row * width;
        for (std::size_t i = 0; i < width; ++i) {
            lane[i] ^= selected[i];
        }
        block_mix(lane, width, temp);
        std::swap(lane, temp);
    }
    // The two passes perform 2*N swaps, returning the result to the caller's lane.
}

bool overlap(const std::uint8_t* left, std::size_t left_size,
             const std::uint8_t* right, std::size_t right_size) noexcept {
    const auto a = reinterpret_cast<std::uintptr_t>(left), b = reinterpret_cast<std::uintptr_t>(right);
    return left_size != 0 && right_size != 0 && (a <= b ? b - a < left_size : a - b < right_size);
}

void clear(std::uint8_t* buffer, std::size_t size) noexcept {
    volatile std::uint8_t* bytes = buffer;
    for (std::size_t i = 0; i < size; ++i) {
        bytes[i] = 0;
    }
}

}  // namespace

Status workspace_bytes(Parameters parameters, std::size_t& bytes) noexcept {
    Layout layout;
    const auto status = plan(parameters, layout);
    if (status == Status::ok) {
        bytes = layout.total;
    }
    return status;
}

Status derive(const std::uint8_t* password, std::size_t password_length,
    const std::uint8_t* salt, std::size_t salt_length, Parameters parameters,
    std::uint8_t* workspace, std::size_t workspace_length,
    std::uint8_t* output, std::size_t output_length) noexcept {
    Layout work;
    const auto status = plan(parameters, work);
    if (status != Status::ok) {
        return status;
    }
    if (output_length == 0 || output_length > pbkdf2::max_output_bytes
        || password_length > native_hmac_sha256::max_key_bytes || salt_length > pbkdf2::max_salt_bytes) {
        return Status::length_limit;
    }
    if (workspace_length < work.total) {
        return Status::workspace_too_small;
    }
    if (workspace == nullptr || output == nullptr || (password == nullptr && password_length != 0)
        || (salt == nullptr && salt_length != 0) || overlap(workspace, work.total, password, password_length)
        || overlap(workspace, work.total, salt, salt_length) || overlap(workspace, work.total, output, output_length)) {
        return Status::invalid_buffer;
    }

    auto backend = pbkdf2::derive(password, password_length, salt, salt_length, 1, workspace, work.lanes);
    if (backend == pbkdf2::Status::ok) {
        const auto table = workspace + work.lanes;
        const auto temp = table + work.table;
        for (std::size_t lane = 0; lane < parameters.p; ++lane) {
            mix_lane(workspace + lane * work.lane, work.lane, table, temp, parameters.n);
        }
        backend = pbkdf2::derive(password, password_length, workspace, work.lanes, 1, output, output_length);
    }
    clear(workspace, work.total);
    return backend == pbkdf2::Status::ok ? Status::ok : Status::backend_error;
}

}  // namespace abc::native_scrypt
