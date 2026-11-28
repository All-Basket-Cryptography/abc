#include "hkdf_sha256.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace abc::native_hkdf_sha256;

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
    Prk key{};
    std::uint8_t sentinel = 42;
    require(expand(key.data(), key.size() - 1, nullptr, 0, &sentinel, 1) ==
            Status::prk_too_short, "short PRK");
    require(expand(key.data(), key.size(), nullptr, 0, &sentinel, max_output_bytes + 1) ==
            Status::output_too_long, "output bound");
    require(expand(key.data(), key.size(), nullptr, 1, &sentinel, 1) ==
            Status::invalid_argument, "null info");
    require(expand(key.data(), key.size(), nullptr, 0, nullptr, 1) ==
            Status::invalid_argument, "null output");
    if (max_info_bytes < SIZE_MAX) {
        require(expand(key.data(), key.size(), &sentinel, static_cast<std::size_t>(max_info_bytes + 1),
                       &sentinel, 1) == Status::input_too_long, "info bound");
    }
    require(sentinel == 42, "output mutation on rejection");
}

}  // namespace

int main() {
    try {
        std::size_t count = 0;
        std::string salt_hex, ikm_hex, info_hex, prk_hex, okm_hex;
        while (std::getline(std::cin, salt_hex) && std::getline(std::cin, ikm_hex) &&
               std::getline(std::cin, info_hex) && std::getline(std::cin, prk_hex) &&
               std::getline(std::cin, okm_hex)) {
            const auto salt = decode(salt_hex), ikm = decode(ikm_hex), info = decode(info_hex);
            const auto expected_prk = decode(prk_hex), expected = decode(okm_hex);
            std::vector<std::uint8_t> output(expected.size());
            if (!salt.empty() || !ikm.empty() || expected_prk.size() == Prk{}.size()) {
                Prk prk{};
                require(extract(salt.data(), salt.size(), ikm.data(), ikm.size(), prk) ==
                        Status::ok, "extract");
                require(std::equal(prk.begin(), prk.end(), expected_prk.begin(), expected_prk.end()),
                        "extract value");
                require(derive(salt.data(), salt.size(), ikm.data(), ikm.size(), info.data(), info.size(),
                               output.data(), output.size()) == Status::ok && output == expected, "derive");
            }
            std::fill(output.begin(), output.end(), 0);
            require(expand(expected_prk.data(), expected_prk.size(), info.data(), info.size(),
                           output.data(), output.size()) == Status::ok && output == expected, "expand");
            ++count;
        }
        check_errors();
        std::cout << "{\"cases\":" << count << ",\"rejection_atomicity\":true}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
