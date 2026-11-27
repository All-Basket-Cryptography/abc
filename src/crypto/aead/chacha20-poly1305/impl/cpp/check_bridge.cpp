// This C ABI belongs to the test consumer. The C++ core exposes its C++ API.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#if defined(_WIN32)
#define TEST_EXPORT extern "C" __declspec(dllexport)
#else
#define TEST_EXPORT extern "C" __attribute__((visibility("default")))
#endif

#ifdef ABC_TEST_C
#ifdef ABC_TEST_CHACHA
#include "abc_chacha20_c.h"
#endif
#ifdef ABC_TEST_POLY
#include "abc_poly1305_c.h"
#endif
#ifdef ABC_TEST_AEAD
#include "abc_chacha20_poly1305_c.h"
#endif
#else
#ifdef ABC_TEST_CHACHA
#include "chacha20.hpp"
namespace chacha = abc::native_chacha20;
#endif
#ifdef ABC_TEST_POLY
#include "poly1305.hpp"
namespace poly = abc::native_poly1305;
#endif
#ifdef ABC_TEST_AEAD
#include "chacha20_poly1305.hpp"
namespace aead = abc::native_chacha20_poly1305;
#endif

template<class Array>
Array fixed(const std::uint8_t* bytes) {
    Array result{};
    std::copy_n(bytes, result.size(), result.begin());
    return result;
}
#endif

#ifdef ABC_TEST_CHACHA
TEST_EXPORT int test_fits(std::uint64_t width, std::uint32_t counter) {
#ifdef ABC_TEST_C
    return abc_chacha20_c_fits_counter(width, counter);
#else
    return chacha::fits_counter(width, counter);
#endif
}

TEST_EXPORT int test_block(const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter,
                           std::uint8_t* output, std::size_t capacity) {
#ifdef ABC_TEST_C
    return abc_chacha20_c_block(key, nonce, counter, output, capacity);
#else
    if (key == nullptr || nonce == nullptr || output == nullptr) return 1;
    if (capacity < chacha::block_size) return 2;
    const auto result = chacha::stream_block(fixed<chacha::Key>(key), fixed<chacha::Nonce>(nonce), counter);
    std::copy(result.begin(), result.end(), output);
    return 0;
#endif
}

TEST_EXPORT int test_stream(const std::uint8_t* key, const std::uint8_t* nonce, std::uint32_t counter,
                            const std::uint8_t* input, std::size_t length, std::uint8_t* output,
                            std::size_t capacity) {
#ifdef ABC_TEST_C
    return abc_chacha20_c_xor(key, nonce, counter, input, length, output, capacity);
#else
    if (key == nullptr || nonce == nullptr) return 1;
    return static_cast<int>(chacha::apply(fixed<chacha::Key>(key), fixed<chacha::Nonce>(nonce),
                                          counter, input, length, output, capacity));
#endif
}
#endif

#ifdef ABC_TEST_POLY
TEST_EXPORT int test_poly(const std::uint8_t* key, const std::uint8_t* input, std::size_t length,
                          std::uint8_t* output, std::size_t capacity) {
#ifdef ABC_TEST_C
    return abc_poly1305_c_authenticate(key, input, length, output, capacity);
#else
    if (key == nullptr || output == nullptr || (input == nullptr && length != 0)) return 1;
    if (capacity < poly::tag_size) return 2;
    poly::Tag tag{};
    const auto status = poly::authenticate(fixed<poly::Key>(key), input, length, tag);
    if (status == poly::Status::ok) std::copy(tag.begin(), tag.end(), output);
    return static_cast<int>(status);
#endif
}

TEST_EXPORT int test_poly_split(const std::uint8_t* key, const std::uint8_t* input, std::size_t length,
                                std::size_t split, std::uint8_t* output) {
    if (split > length) return 1;
    std::vector<std::uint8_t> temporary;
    if (split != 0) temporary.assign(input, input + split);
    const auto tail = split == length ? nullptr : input + split;
#ifdef ABC_TEST_C
    abc_poly1305_c_mac mac{};
    std::array<std::uint8_t, 16> previous{};
    int status = 5;
    if (abc_poly1305_c_finish(&mac, previous.data(), previous.size()) == ABC_POLY1305_C_STATE &&
        abc_poly1305_c_init(&mac, key) == 0 &&
        abc_poly1305_c_update(&mac, temporary.data(), split) == 0) {
        std::fill(temporary.begin(), temporary.end(), 0);
        if (abc_poly1305_c_update(&mac, nullptr, 0) == 0 &&
            abc_poly1305_c_update(&mac, tail, length - split) == 0 &&
            abc_poly1305_c_finish(&mac, previous.data(), previous.size()) == 0 &&
            abc_poly1305_c_update(&mac, nullptr, 0) == ABC_POLY1305_C_STATE &&
            abc_poly1305_c_finish(&mac, output, previous.size()) == 0 &&
            std::equal(previous.begin(), previous.end(), output)) {
            status = 0;
        }
    }
    abc_poly1305_c_clear(&mac);
    return status;
#else
    poly::Mac mac(fixed<poly::Key>(key));
    if (mac.update(temporary.data(), split) != poly::Status::ok) return 5;
    std::fill(temporary.begin(), temporary.end(), 0);
    if (mac.update(nullptr, 0) != poly::Status::ok ||
        mac.update(tail, length - split) != poly::Status::ok) return 5;
    const auto tag = mac.finish();
    if (mac.update(nullptr, 0) != poly::Status::state || mac.finish() != tag) return 5;
    std::copy(tag.begin(), tag.end(), output);
    return 0;
#endif
}
#endif

#ifdef ABC_TEST_AEAD
TEST_EXPORT int test_seal(const std::uint8_t* key, const std::uint8_t* nonce, const std::uint8_t* aad,
                          std::size_t aad_length, const std::uint8_t* input, std::size_t length,
                          std::uint8_t* output, std::size_t capacity, std::uint8_t* tag,
                          std::size_t tag_capacity) {
#ifdef ABC_TEST_C
    return abc_chacha20_poly1305_c_seal(key, nonce, aad, aad_length, input, length, output,
                                       capacity, tag, tag_capacity);
#else
    if (key == nullptr || nonce == nullptr || tag == nullptr) return 1;
    if (tag_capacity < aead::Tag{}.size()) return 2;
    aead::Tag result{};
    const auto status = aead::seal_detached(fixed<aead::Key>(key), fixed<aead::Nonce>(nonce),
                                            aad, aad_length, input, length, output, capacity, result);
    if (status == aead::Status::ok) std::copy(result.begin(), result.end(), tag);
    return static_cast<int>(status);
#endif
}

TEST_EXPORT int test_open(const std::uint8_t* key, const std::uint8_t* nonce, const std::uint8_t* aad,
                          std::size_t aad_length, const std::uint8_t* input, std::size_t length,
                          std::uint8_t* output, std::size_t capacity, const std::uint8_t* tag,
                          std::size_t tag_size) {
#ifdef ABC_TEST_C
    return abc_chacha20_poly1305_c_open(key, nonce, aad, aad_length, input, length, output,
                                       capacity, tag, tag_size);
#else
    if (key == nullptr || nonce == nullptr || tag == nullptr || tag_size != aead::Tag{}.size()) return 1;
    return static_cast<int>(aead::open_detached(fixed<aead::Key>(key), fixed<aead::Nonce>(nonce),
                                               aad, aad_length, input, length, output, capacity,
                                               fixed<aead::Tag>(tag)));
#endif
}

TEST_EXPORT int test_overlapping_tag() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 16> storage{};
    storage.fill(0xe5);
    const auto previous = storage;
#ifdef ABC_TEST_C
    const int status = abc_chacha20_poly1305_c_seal(key.data(), nonce.data(), nullptr, 0,
        storage.data(), storage.size(), storage.data(), storage.size(), storage.data(), storage.size());
#else
    const auto status = static_cast<int>(aead::seal_detached(key, nonce, nullptr, 0,
        storage.data(), storage.size(), storage.data(), storage.size(), storage));
#endif
    return status == 1 && storage == previous;
}
#endif

TEST_EXPORT std::uint64_t test_time(int method, std::size_t width, std::size_t calls) {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 16> tag{};
    std::array<std::uint8_t, 16> aad{};
    std::vector<std::uint8_t> buffer(width, 43);
    if (width == 0 || calls == 0) return 0;
    volatile std::uint8_t sink = 0;
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < calls; ++i) {
        for (std::size_t byte = 0; byte < 8; ++byte) {
            nonce[byte] = static_cast<std::uint8_t>(std::uint64_t{i} >> (8 * byte));
            key[byte] = nonce[byte];
        }
        int status = 1;
#ifdef ABC_TEST_CHACHA
        if (method == 1) {
            status = test_stream(key.data(), nonce.data(), 1, buffer.data(), width, buffer.data(), width);
            sink = buffer[0];
        }
#endif
#ifdef ABC_TEST_POLY
        if (method == 2) {
            status = test_poly(key.data(), buffer.data(), width, tag.data(), tag.size());
            sink = tag[0];
        }
#endif
#ifdef ABC_TEST_AEAD
        if (method == 3) {
            status = test_seal(key.data(), nonce.data(), aad.data(), aad.size(), buffer.data(), width,
                               buffer.data(), width, tag.data(), tag.size());
            sink = tag[0];
        }
#else
        (void)aad;
#endif
#ifndef ABC_TEST_POLY
        (void)tag;
#endif
        if (status != 0) return 0;
    }
    (void)sink;
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start)
        .count() / calls;
}
