#include "blake2b.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace abc::native_blake2b;
using Bytes = std::vector<std::uint8_t>;

void require(bool success, const char* description) {
    if (!success) {
        throw std::runtime_error(description);
    }
}

unsigned nibble(char digit) {
    if (digit >= '0' && digit <= '9') return static_cast<unsigned>(digit - '0');
    if (digit >= 'a' && digit <= 'f') return static_cast<unsigned>(digit - 'a' + 10);
    throw std::runtime_error("invalid hex fixture");
}

Bytes decode(const std::string& hex) {
    require(hex.size() % 2 == 0, "odd hex fixture length");
    Bytes result(hex.size() / 2);
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return result;
}

const std::uint8_t* offset(const Bytes& bytes, std::size_t index) {
    return bytes.empty() ? nullptr : bytes.data() + index;
}

bool take_snapshot(const Hasher& stream, const Bytes& expected) {
    std::array<std::uint8_t, max_digest_size + 2> buffer;
    buffer.fill(0xa5);
    return stream.digest(buffer.data() + 1, expected.size()) == Status::ok
        && buffer.front() == 0xa5 && buffer[expected.size() + 1] == 0xa5
        && std::equal(expected.begin(), expected.end(), buffer.begin() + 1);
}

void check_context() {
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();
    detail::Counter carry{max - 127, max - 1};
    require(carry.add(128) && carry.low == 0 && carry.high == max, "counter carry");
    require(carry.add(max) && carry.low == max && carry.high == max, "max counter");
    require(!carry.add(1) && carry.low == max && carry.high == max, "counter overflow rollback");
    require(carry.add(0) && carry.low == max && carry.high == max, "full counter empty update");

    Hasher stream;
    Bytes input(129);
    for (std::size_t i = 0; i < input.size(); ++i) input[i] = static_cast<std::uint8_t>(i);
    Bytes expected(31), output(31, 0xa5);
    require(stream.digest_size() == 64, "default digest size");
    require(stream.reset(expected.size()) == Status::ok, "custom digest size");
    require(stream.update(input.data(), 128) == Status::ok, "absorb exact block");
    require(hash(input.data(), 128, expected.data(), expected.size()) == Status::ok, "exact block reference");
    const auto original_input = input;
    std::fill(input.begin(), input.begin() + 128, 0);
    require(take_snapshot(stream, expected), "absorber owns pending bytes");
    require(stream.reset(0) == Status::invalid_digest_size, "zero digest length");
    require(stream.reset(65) == Status::invalid_digest_size, "large digest length");
    require(stream.update(nullptr, 1) == Status::invalid_buffer, "null nonempty input");
    require(stream.update(nullptr, 0) == Status::ok, "null empty input");
    require(stream.digest(nullptr, expected.size()) == Status::invalid_buffer, "null output");
    require(stream.digest(output.data(), output.size() - 1) == Status::invalid_digest_size, "short output");
    require(hash(nullptr, 0, output.data(), 0) == Status::invalid_digest_size, "invalid one-shot length");
    require(hash(nullptr, 0, nullptr, output.size()) == Status::invalid_buffer, "invalid one-shot output");
    require(hash(nullptr, 1, output.data(), output.size()) == Status::invalid_buffer, "invalid one-shot input");
    require(std::all_of(output.begin(), output.end(), [](auto byte) { return byte == 0xa5; }), "error overwrites digest");
    require(take_snapshot(stream, expected), "error changes context");
    require(stream.update(input.data() + 128, 1) == Status::ok, "continue after errors and snapshot");
    input = original_input;
    require(hash(input.data(), input.size(), input.data() + 7, expected.size()) == Status::ok, "overlap hash");
    require(stream.digest(output.data(), output.size()) == Status::ok
            && std::equal(output.begin(), output.end(), input.begin() + 7), "overlap digest");
    stream.reset();
    require(stream.digest_size() == expected.size(), "reset preserves size");
    require(hash(nullptr, 0, expected.data(), expected.size()) == Status::ok, "empty one-shot");
    require(take_snapshot(stream, expected), "reset state");
}

void check_fixtures() {
    std::size_t known = 0, openssl = 0, variable = 0, snapshots = 0, splits = 0;
    std::string role, encoded_input, encoded_digest, encoded_prefix;
    while (std::getline(std::cin, role)) {
        require(static_cast<bool>(std::getline(std::cin, encoded_input)
                && std::getline(std::cin, encoded_digest) && std::getline(std::cin, encoded_prefix)), "truncated fixture");
        const auto input = decode(encoded_input);
        const auto expected = decode(encoded_digest);
        const auto prefix = decode(encoded_prefix);
        if (role == "known") ++known;
        else if (role == "openssl") ++openssl;
        else if (role == "variable") ++variable;
        else throw std::runtime_error("unknown fixture role");

        const auto size = expected.size();
        Bytes digest(size);
        require(hash(input.data(), input.size(), digest.data(), size) == Status::ok
                && digest == expected, "one-shot vector");

        Hasher stream;
        require(stream.reset(size) == Status::ok, "vector digest size");
        const auto middle = input.size() / 2;
        require(stream.update(input.data(), middle) == Status::ok && take_snapshot(stream, prefix), "prefix snapshot");
        require(stream.update(offset(input, middle), input.size() - middle) == Status::ok
                && take_snapshot(stream, expected), "continue after prefix snapshot");
        ++snapshots;

        if (input.size() <= 257 && (size == 1 || size == 31 || size == max_digest_size)) {
            for (std::size_t split = 0; split <= input.size(); ++split) {
                stream.reset();
                require(stream.update(input.data(), split) == Status::ok
                        && stream.update(nullptr, 0) == Status::ok
                        && stream.update(offset(input, split), input.size() - split) == Status::ok
                        && take_snapshot(stream, expected), "two-chunk split");
                ++splits;
            }
        }
    }
    require(known > 0 && openssl > 0 && variable > 0, "missing fixtures");
    std::cout << "{\"known_answers\":" << known << ",\"openssl_comparisons\":" << openssl
              << ",\"hashlib_comparisons\":" << variable << ",\"snapshots\":" << snapshots
              << ",\"streaming_splits\":" << splits << "}\n";
}

void benchmark() {
    Bytes input(1U << 20);
    for (std::size_t i = 0; i < input.size(); ++i) {
        input[i] = static_cast<std::uint8_t>(i * 73 + 11);
    }
    std::array<std::uint8_t, max_digest_size> digest{};
    const auto run = [&]() {
        require(hash(input.data(), input.size(), digest.data(), digest.size()) == Status::ok, "benchmark hash");
    };
    for (unsigned warmup = 0; warmup < 4; ++warmup) run();
    std::cout << '[';
    for (unsigned batch = 0; batch < 7; ++batch) {
        const auto start = std::chrono::steady_clock::now();
        for (unsigned i = 0; i < 16; ++i) run();
        const auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        if (batch != 0) std::cout << ',';
        std::cout << 16 / seconds;
    }
    std::cout << "]\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--benchmark") {
            benchmark();
        } else {
            check_context();
            check_fixtures();
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
