#ifndef ABC_NATIVE_CPP_KECCAK_TEST_SUPPORT_HPP
#define ABC_NATIVE_CPP_KECCAK_TEST_SUPPORT_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace abc::keccak_tests {

using Bytes = std::vector<std::uint8_t>;

inline void require(bool valid, const char* detail) {
    if (!valid) {
        throw std::runtime_error(detail);
    }
}

inline unsigned hex_digit(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
    throw std::runtime_error("invalid hex digit");
}

inline Bytes decode(const std::string& text) {
    require(text.size() % 2 == 0, "odd fixture hex length");
    Bytes result(text.size() / 2);
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = static_cast<std::uint8_t>((hex_digit(text[2 * i]) << 4) | hex_digit(text[2 * i + 1]));
    }
    return result;
}

struct Case {
    bool known;
    Bytes input;
    Bytes expected;
    Bytes prefix;
};

inline bool next(Case& item) {
    std::string role, input, expected, prefix;
    if (!std::getline(std::cin, role)) return false;
    require(role == "known" || role == "comparison", "unexpected fixture role");
    require(static_cast<bool>(std::getline(std::cin, input) && std::getline(std::cin, expected)
            && std::getline(std::cin, prefix)), "incomplete fixture");
    item = {role == "known", decode(input), decode(expected), decode(prefix)};
    return true;
}

inline const std::uint8_t* suffix(const Bytes& bytes, std::size_t offset) {
    return bytes.empty() ? nullptr : bytes.data() + offset;
}

struct Counts {
    std::size_t known = 0, comparisons = 0, snapshots = 0, splits = 0;

    void record(const Case& item) {
        if (item.known) ++known;
        else ++comparisons;
    }

    void print() const {
        require(known != 0 && comparisons != 0, "fixtures missing");
        std::cout << "{\"known_answers\":" << known << ",\"comparisons\":" << comparisons
                  << ",\"snapshots\":" << snapshots << ",\"streaming_splits\":" << splits << "}\n";
    }
};

template<class Operation> void benchmark(Operation operation) {
    Bytes input(1U << 20);
    for (std::size_t i = 0; i < input.size(); ++i) {
        input[i] = static_cast<std::uint8_t>(i * 73 + 11);
    }
    for (unsigned warmup = 0; warmup < 4; ++warmup) operation(input);
    std::cout << '[';
    for (unsigned batch = 0; batch < 7; ++batch) {
        const auto start = std::chrono::steady_clock::now();
        for (unsigned i = 0; i < 16; ++i) operation(input);
        const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        if (batch != 0) std::cout << ',';
        std::cout << 16 / elapsed;
    }
    std::cout << "]\n";
}

}  // namespace abc::keccak_tests

#endif
