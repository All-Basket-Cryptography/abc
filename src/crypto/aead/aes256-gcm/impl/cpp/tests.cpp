#include "aes256_gcm.hpp"

#include <algorithm>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace abc::native_aes256_gcm;
using Bytes = std::vector<std::uint8_t>;

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

Bytes read(std::istream& line) {
    std::string hex;
    require(static_cast<bool>(std::getline(line, hex, ':')) && hex.size() % 2 == 0, "invalid fixture field");
    Bytes result(hex.size() / 2);
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = static_cast<std::uint8_t>((digit(hex[2 * i]) << 4) | digit(hex[2 * i + 1]));
    }
    return result;
}

template<class Fixed> Fixed exact(std::istream& line) {
    const auto input = read(line);
    Fixed result;
    require(input.size() == result.size(), "fixture fixed size");
    std::copy(input.begin(), input.end(), result.begin());
    return result;
}

void negative(Gcm& cipher, const Nonce& nonce, const Bytes& aad, const Bytes& encrypted, Tag tag) {
    Bytes output(encrypted.size(), 0xa5);
    const auto untouched = output;
    for (auto& byte : tag) {
        byte ^= 1;
        require(cipher.open(nonce, aad.data(), aad.size(), encrypted.data(), encrypted.size(), tag,
                output.data(), output.size()) == Status::authentication_failed && output == untouched, "reject changed tag");
        byte ^= 1;
    }
    auto changed = aad;
    changed.front() ^= 1;
    require(cipher.open(nonce, changed.data(), changed.size(), encrypted.data(), encrypted.size(), tag,
            output.data(), output.size()) == Status::authentication_failed && output == untouched, "reject changed AAD");
    changed = encrypted;
    changed.front() ^= 1;
    require(cipher.open(nonce, aad.data(), aad.size(), changed.data(), changed.size(), tag,
            output.data(), output.size()) == Status::authentication_failed && output == untouched, "reject changed body");
    require(cipher.seal(nonce, aad.data(), aad.size(), encrypted.data(), encrypted.size(),
            tag.data(), encrypted.size(), tag) == Status::invalid_argument, "reject overlapping tag and body output");
    require(cipher.seal(nonce, aad.data(), aad.size(), encrypted.data(), encrypted.size(),
            output.data(), output.size() - 1, tag) == Status::invalid_argument && output == untouched, "reject short output");
    const auto huge = std::numeric_limits<std::size_t>::max();
    require(cipher.open(nonce, aad.data(), aad.size(), encrypted.data(), huge, tag,
            output.data(), huge) == Status::invalid_argument && output == untouched, "reject counter exhaustion");
    require(cipher.open(nonce, aad.data(), huge, encrypted.data(), encrypted.size(), tag,
            output.data(), output.size()) == Status::invalid_argument && output == untouched, "reject AAD length overflow");
}

void check() {
    Gcm cipher;
    Nonce nonce{};
    Tag tag{};
    require(cipher.seal(nonce, nullptr, 0, nullptr, 0, nullptr, 0, tag) == Status::uninitialized,
            "uninitialized seal");
    std::size_t cases = 0;
    bool exercised_negative = false, exercised_aad_overlap = false;
    std::string input;
    while (std::getline(std::cin, input)) {
        std::istringstream fixture(input);
        const auto key = exact<Key>(fixture);
        nonce = exact<Nonce>(fixture);
        const auto aad = read(fixture), plaintext = read(fixture), encrypted = read(fixture);
        const auto expected_tag = exact<Tag>(fixture);
        require(plaintext.size() == encrypted.size(), "fixture body length");
        require(cipher.initialize(key) == Status::ok, "initialize key");
        Bytes output(plaintext.size() + 2, 0xa5);
        auto target = output.begin() + 1;
        require(cipher.seal(nonce, aad.data(), aad.size(), plaintext.data(), plaintext.size(),
                output.data() + 1, plaintext.size(), tag) == Status::ok && tag == expected_tag
                && std::equal(encrypted.begin(), encrypted.end(), target), "detached seal");
        require(cipher.open(nonce, aad.data(), aad.size(), encrypted.data(), encrypted.size(), expected_tag,
                output.data() + 1, plaintext.size()) == Status::ok && std::equal(plaintext.begin(), plaintext.end(), target),
                "detached open");
        require(output.front() == 0xa5 && output.back() == 0xa5, "body canaries");

        Bytes overlap = plaintext;
        overlap.resize(plaintext.size() + 7);
        require(cipher.seal(nonce, aad.data(), aad.size(), overlap.data(), plaintext.size(), overlap.data() + 7,
                plaintext.size(), tag) == Status::ok && tag == expected_tag
                && std::equal(encrypted.begin(), encrypted.end(), overlap.begin() + 7), "shifted seal");
        require(cipher.open(nonce, aad.data(), aad.size(), overlap.data() + 7, encrypted.size(), tag,
                overlap.data(), plaintext.size()) == Status::ok
                && std::equal(plaintext.begin(), plaintext.end(), overlap.begin()), "shifted open");
        if (aad.size() >= 1 && aad.size() <= plaintext.size() && !exercised_aad_overlap) {
            std::copy(aad.begin(), aad.end(), target);
            require(cipher.seal(nonce, output.data() + 1, aad.size(), plaintext.data(), plaintext.size(), output.data() + 1,
                    plaintext.size(), tag) == Status::ok && tag == expected_tag
                    && std::equal(encrypted.begin(), encrypted.end(), target), "AAD aliases output");
            exercised_aad_overlap = true;
        }
        if (plaintext.size() > 16 && !aad.empty() && !exercised_negative) {
            negative(cipher, nonce, aad, encrypted, expected_tag);
            exercised_negative = true;
        }
        ++cases;
    }
    cipher.clear();
    require(cipher.open(nonce, nullptr, 0, nullptr, 0, tag, nullptr, 0) == Status::uninitialized, "cleared context");
    require(cases == 274 && exercised_negative && exercised_aad_overlap, "incomplete corpus");
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
