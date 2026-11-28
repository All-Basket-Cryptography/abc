#include "columns/poly1305.hpp"
#undef ABC_NATIVE_CPP_POLY1305_HPP
#define native_poly1305 native_poly1305_baseline
#include "baseline/poly1305.hpp"
#undef native_poly1305
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

using Key = abc::native_poly1305::Key;
using Tag = abc::native_poly1305::Tag;
using Clock = std::chrono::steady_clock;
using Call = Tag (*)(const Key&, const std::uint8_t*, std::size_t);
volatile std::uint64_t result = 0;

Tag base(const Key& key, const std::uint8_t* input, std::size_t size) {
    Tag out;
    if (abc::native_poly1305_baseline::authenticate(key, input, size, out) != abc::native_poly1305_baseline::Status::ok)
        std::abort();
    return out;
}
Tag columns(const Key& key, const std::uint8_t* input, std::size_t size) {
    Tag out;
    if (abc::native_poly1305::authenticate(key, input, size, out) != abc::native_poly1305::Status::ok)
        std::abort();
    return out;
}

double measure(Call entry, const Key& key, const std::vector<std::uint8_t>& bytes, std::size_t size) {
    const auto count = std::max<std::size_t>(48, (24 * 1024 * 1024) / size);
    std::uint64_t check = 0;
    const auto begin = Clock::now();
    for (std::size_t i = 0; i < count; ++i) {
        const auto out = entry(key, bytes.data() + (i & 15), size);
        check += out[i & 15];
    }
    const auto finish = Clock::now();
    result = check;
    return std::chrono::duration<double>(finish - begin).count() * 1e9 / static_cast<double>(count);
}

int main() {
    Key key;
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i * 43 + 117);
    std::vector<std::uint8_t> input((1 << 20) + 16);
    for (std::size_t i = 0; i < input.size(); ++i) input[i] = static_cast<std::uint8_t>(i * 17 + (i >> 8));
    for (const auto size : {64u, 1024u, 16384u, 1048576u}) {
        for (unsigned offset = 0; offset < 16; ++offset)
            if (base(key, input.data() + offset, size) != columns(key, input.data() + offset, size)) std::abort();
        (void)measure(base, key, input, size);
        (void)measure(columns, key, input, size);
        std::array<double, 9> left, right, ratio;
        for (unsigned i = 0; i < left.size(); ++i) {
            if (i % 2 == 0) {
                left[i] = measure(base, key, input, size);
                right[i] = measure(columns, key, input, size);
            } else {
                right[i] = measure(columns, key, input, size);
                left[i] = measure(base, key, input, size);
            }
            ratio[i] = left[i] / right[i];
        }
        std::sort(left.begin(), left.end());
        std::sort(right.begin(), right.end());
        std::sort(ratio.begin(), ratio.end());
        std::printf("%u %f %f %.6f %.6f %.6f\n", size, left[4], right[4], ratio[4], ratio.front(), ratio.back());
    }
}
