#include "hmac_sha256.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace abc::native_hmac_sha256;

namespace {

void require(bool pass, const char* message) {
    if (!pass) {
        throw std::runtime_error(message);
    }
}

std::vector<std::uint8_t> decode(const std::string& hex) {
    require(hex.size() % 2 == 0, "hex size");
    std::vector<std::uint8_t> result;
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        result.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return result;
}

void check_errors() {
    Hmac stream;
    const std::uint8_t byte = 42;
    Tag output{};
    output.fill(42);
    const auto before = output;
    const auto snapshot = stream.digest();
    require(stream.set_key(nullptr, 1) == Status::invalid_argument, "null key");
    require(stream.update(nullptr, 1) == Status::invalid_argument, "null input");
    require(stream.digest() == snapshot, "rejection changed context");
    require(authenticate(nullptr, 0, nullptr, 1, output) == Status::invalid_argument, "null message");
    require(output == before, "rejection changed output");
    if (max_key_bytes < SIZE_MAX) {
        require(stream.set_key(&byte, static_cast<std::size_t>(max_key_bytes + 1)) ==
                Status::message_too_long, "key bound");
        require(stream.update(&byte, static_cast<std::size_t>(max_message_bytes + 1)) ==
                Status::message_too_long, "message bound");
        require(stream.digest() == snapshot, "length rejection changed context");
    }
}

}  // namespace

int main() {
    try {
        std::size_t count = 0;
        std::string key_hex, input_hex, expected_hex, partial_hex;
        while (std::getline(std::cin, key_hex) && std::getline(std::cin, input_hex) &&
               std::getline(std::cin, expected_hex) && std::getline(std::cin, partial_hex)) {
            auto key = decode(key_hex);
            const auto input = decode(input_hex);
            const auto expected = decode(expected_hex);
            const auto partial = decode(partial_hex);
            Tag result{};
            require(authenticate(key.data(), key.size(), input.data(), input.size(), result) == Status::ok,
                    "one-shot status");
            require(std::equal(expected.begin(), expected.end(), result.begin()), "one-shot tag");
            Hmac stream;
            require(stream.set_key(key.data(), key.size()) == Status::ok, "key import");
            std::fill(key.begin(), key.end(), 0xff);
            const auto half = input.size() / 2;
            require(stream.update(input.data(), half) == Status::ok, "stream prefix");
            result = stream.digest();
            require(std::equal(partial.begin(), partial.end(), result.begin()), "prefix snapshot");
            const auto tail = input.empty() ? nullptr : input.data() + half;
            require(stream.update(tail, input.size() - half) == Status::ok, "stream suffix");
            result = stream.digest();
            require(std::equal(expected.begin(), expected.end(), result.begin()), "streaming tag");
            require(stream.digest() == result, "repeated snapshot");
            ++count;
        }
        check_errors();
        std::cout << "{\"cases\":" << count << ",\"null_length_atomicity\":true}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
