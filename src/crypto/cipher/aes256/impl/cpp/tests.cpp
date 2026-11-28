#include "aes256.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using namespace abc::native_aes256;

void require(bool success, const char* detail) {
    if (!success) {
        throw std::runtime_error(detail);
    }
}

unsigned digit(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
    throw std::runtime_error("invalid fixture digit");
}

template<std::size_t N>
std::array<std::uint8_t, N> decode(std::string_view& row, bool last = false) {
    require(row.size() >= 2 * N && (last ? row.size() == 2 * N : row[2 * N] == ':'), "invalid fixture shape");
    std::array<std::uint8_t, N> result;
    for (std::size_t i = 0; i < N; ++i) {
        result[i] = static_cast<std::uint8_t>((digit(row[2 * i]) << 4) | digit(row[2 * i + 1]));
    }
    row.remove_prefix(last ? 2 * N : 2 * N + 1);
    return result;
}

void check() {
    require(available(), "AES-NI is required for this conformance run");
    Cipher cipher;
    Block empty{}, result;
    result.fill(0xa5);
    const auto untouched = result;
    require(cipher.encrypt(empty, result) == Status::uninitialized && result == untouched, "uninitialized encrypt");
    require(cipher.decrypt(empty, result) == Status::uninitialized && result == untouched, "uninitialized decrypt");

    std::size_t cases = 0;
    std::string input;
    while (std::getline(std::cin, input)) {
        std::string_view row = input;
        const auto key = decode<32>(row);
        const auto plaintext = decode<16>(row);
        const auto ciphertext = decode<16>(row);
        const auto expected_enc = decode<16>(row);
        const auto expected_dec = decode<16>(row, true);
        require(cipher.initialize(key) == Status::ok, "key expansion");
        require(cipher.encrypt(plaintext, result) == Status::ok && result == expected_enc, "encryption reference");
        require(cipher.decrypt(ciphertext, result) == Status::ok && result == expected_dec, "decryption reference");
        result = plaintext;
        require(cipher.encrypt(result, result) == Status::ok && result == expected_enc, "in-place encryption");
        result = ciphertext;
        require(cipher.decrypt(result, result) == Status::ok && result == expected_dec, "in-place decryption");
        ++cases;
    }
    cipher.clear();
    result = untouched;
    require(cipher.encrypt(empty, result) == Status::uninitialized && result == untouched, "cleared context");
    require(cases == 514, "incomplete cases");
    std::cout << cases << '\n';
}

}  // namespace

int main() {
    try {
        check();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
