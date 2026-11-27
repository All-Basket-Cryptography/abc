#include "pbkdf2_sha256.hpp"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace abc::native_pbkdf2_sha256;

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
    std::uint8_t sentinel = 42;
    require(derive(nullptr, 0, nullptr, 0, 0, &sentinel, 1) == Status::invalid_iterations, "zero rounds");
    require(derive(nullptr, 0, nullptr, 0, 1, &sentinel, 0) == Status::invalid_output_length, "empty output");
    require(derive(nullptr, 1, nullptr, 0, 1, &sentinel, 1) == Status::invalid_argument, "null key");
    if (max_salt_bytes < SIZE_MAX) {
        require(derive(nullptr, 0, &sentinel, static_cast<std::size_t>(max_salt_bytes + 1), 1, &sentinel, 1)
                == Status::input_too_long, "salt bound");
        require(derive(nullptr, 0, nullptr, 0, 1, &sentinel, static_cast<std::size_t>(max_output_bytes + 1))
                == Status::invalid_output_length, "block index bound");
    }
    require(sentinel == 42, "rejection changed output");
}

}  // namespace

int main() {
    try {
        std::size_t count = 0;
        std::string password_hex, salt_hex, rounds, expected_hex;
        while (std::getline(std::cin, password_hex) && std::getline(std::cin, salt_hex) &&
               std::getline(std::cin, rounds) && std::getline(std::cin, expected_hex)) {
            const auto password = decode(password_hex), salt = decode(salt_hex), expected = decode(expected_hex);
            std::vector<std::uint8_t> output(expected.size());
            const auto iterations = static_cast<std::uint32_t>(std::stoul(rounds));
            require(derive(password.data(), password.size(), salt.data(), salt.size(), iterations,
                           output.data(), output.size()) == Status::ok, "derive status");
            require(output == expected, "derived bytes");
            ++count;
        }
        check_errors();
        std::cout << "{\"cases\":" << count << ",\"rejection_atomicity\":true}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
