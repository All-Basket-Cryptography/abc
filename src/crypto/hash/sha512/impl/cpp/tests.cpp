#include "sha512.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace abc::native_sha512;

namespace {

void require(bool result, const char* failure) {
    if (!result) {
        throw std::runtime_error(failure);
    }
}

std::vector<std::uint8_t> decode(const std::string& text) {
    require(text.size() % 2 == 0, "odd fixture encoding");
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 0; i < text.size(); i += 2) {
        bytes.push_back(static_cast<std::uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

Digest expected_digest(const std::string& text) {
    const auto bytes = decode(text);
    require(bytes.size() == digest_size, "fixture digest size");
    Digest digest{};
    std::copy(bytes.begin(), bytes.end(), digest.begin());
    return digest;
}

const std::uint8_t* suffix(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return bytes.empty() ? nullptr : bytes.data() + offset;
}

void streaming(const std::vector<std::uint8_t>& input, std::size_t split,
               const Digest& expected, const Digest* prefix) {
    Hasher stream;
    require(stream.update(input.data(), split) == Status::ok, "prefix update");
    if (prefix != nullptr) {
        require(stream.digest() == *prefix, "prefix snapshot");
    }
    require(stream.update(nullptr, 0) == Status::ok, "empty update");
    require(stream.update(suffix(input, split), input.size() - split) == Status::ok, "suffix update");
    require(stream.digest() == expected, "streaming digest");
    require(stream.digest() == expected, "repeated snapshot");
}

void check_errors() {
    const std::array<std::uint8_t, 3> message{0x61, 0x62, 0x63};
    const auto expected = expected_digest("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    Hasher stream;
    require(stream.update(message.data(), message.size()) == Status::ok, "state initialization");
    require(stream.update(nullptr, 1) == Status::invalid_argument, "null rejection");
    require(stream.digest() == expected, "null rejection changed context");
    stream.reset();
    require(stream.digest() == Hasher{}.digest(), "reset");

    Digest destination{};
    destination.fill(0xa5);
    const Digest before = destination;
    require(hash(nullptr, 1, destination) == Status::invalid_argument, "one-shot null rejection");
    require(destination == before, "rejected hash changed destination");
    std::copy(message.begin(), message.end(), destination.begin());
    require(hash(destination.data(), message.size(), destination) == Status::ok, "overlapping input and output");
    require(destination == expected, "overlapping result");
}

void check_cases() {
    std::size_t known_answers = 0, comparisons = 0, snapshots = 0, splits = 0;
    std::string role, data, expected, prefix;
    while (std::getline(std::cin, role)) {
        require(static_cast<bool>(std::getline(std::cin, data) && std::getline(std::cin, expected)
            && std::getline(std::cin, prefix)), "truncated fixture");
        const auto bytes = decode(data);
        const auto digest = expected_digest(expected);
        const auto prefix_digest = expected_digest(prefix);
        Digest actual{};
        require(hash(bytes.data(), bytes.size(), actual) == Status::ok, "one-shot status");
        require(actual == digest, "one-shot digest");
        if (role == "known-answer") {
            ++known_answers;
        } else {
            require(role == "comparison", "unknown fixture role");
            ++comparisons;
        }
        streaming(bytes, bytes.size() / 2, digest, &prefix_digest);
        ++snapshots;
        if (bytes.size() <= 257) {
            for (std::size_t split = 0; split <= bytes.size(); ++split) {
                streaming(bytes, split, digest, nullptr);
                ++splits;
            }
        }
    }
    require(known_answers > 0 && comparisons > 0, "no fixture cases");
    check_errors();
    std::cout << "{\"known_answers\":" << known_answers << ",\"comparisons\":" << comparisons
              << ",\"prefix_snapshots\":" << snapshots << ",\"streaming_splits\":" << splits << "}\n";
}

void benchmark() {
    std::vector<std::uint8_t> input(1U << 20);
    for (std::size_t i = 0; i < input.size(); ++i) {
        input[i] = static_cast<std::uint8_t>(i * 73 + 11);
    }
    Digest result{};
    for (unsigned i = 0; i < 4; ++i) {
        require(hash(input.data(), input.size(), result) == Status::ok, "benchmark warm-up");
    }
    std::cout << "[";
    for (unsigned sample = 0; sample < 7; ++sample) {
        const auto start = std::chrono::steady_clock::now();
        for (unsigned i = 0; i < 16; ++i) {
            require(hash(input.data(), input.size(), result) == Status::ok, "benchmark hash");
        }
        const auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        if (sample != 0) {
            std::cout << ',';
        }
        std::cout << 16.0 / seconds;
    }
    std::cout << "]\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--benchmark") {
            benchmark();
        } else {
            require(argc == 1, "unexpected test argument");
            check_cases();
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
