#include "aes256.hpp"

#if defined(__x86_64__) || defined(_M_X64)
#define ABC_X64 1
#include <cstring>
#include <wmmintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#if defined(__clang__) || defined(__GNUC__)
#define ABC_AES __attribute__((target("aes,sse2")))
#else
#define ABC_AES
#endif
#endif

namespace abc::native_aes256 {
namespace {

#ifdef ABC_X64
using Schedule = std::array<Block, 15>;

ABC_AES __m128i load(const std::uint8_t* source) noexcept {
    __m128i word;
    std::memcpy(&word, source, sizeof word);
    return word;
}

ABC_AES void store(Block& destination, __m128i word) noexcept {
    std::memcpy(destination.data(), &word, sizeof word);
}

ABC_AES __m128i cascade(__m128i current) noexcept {
    const auto once = _mm_slli_si128(current, 4);
    const auto twice = _mm_slli_si128(once, 4);
    const auto thrice = _mm_slli_si128(twice, 4);
    return _mm_xor_si128(_mm_xor_si128(current, once), _mm_xor_si128(twice, thrice));
}

template<int Rcon>
ABC_AES __m128i next_left(__m128i left, __m128i right) noexcept {
    return _mm_xor_si128(cascade(left), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(right, Rcon), 0xff));
}

template<int Rcon>
ABC_AES void next_pair(__m128i& left, __m128i& right, Block& even, Block& odd) noexcept {
    left = next_left<Rcon>(left, right);
    right = _mm_xor_si128(cascade(right), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(left, 0), 0xaa));
    store(even, left);
    store(odd, right);
}

ABC_AES void schedules(const Key& key, Schedule& encryption, Schedule& decryption) noexcept {
    auto left = load(key.data());
    auto right = load(key.data() + 16);
    store(encryption[0], left);
    store(encryption[1], right);
    next_pair<0x01>(left, right, encryption[2], encryption[3]);
    next_pair<0x02>(left, right, encryption[4], encryption[5]);
    next_pair<0x04>(left, right, encryption[6], encryption[7]);
    next_pair<0x08>(left, right, encryption[8], encryption[9]);
    next_pair<0x10>(left, right, encryption[10], encryption[11]);
    next_pair<0x20>(left, right, encryption[12], encryption[13]);
    store(encryption[14], next_left<0x40>(left, right));

    decryption.front() = encryption.back();
    for (std::size_t round = 1; round < 14; ++round) {
        store(decryption[round], _mm_aesimc_si128(load(encryption[14 - round].data())));
    }
    decryption.back() = encryption.front();
}

template<bool Decrypt>
ABC_AES void run_block(const Schedule& keys, const Block& input, Block& output) noexcept {
    auto value = _mm_xor_si128(load(input.data()), load(keys.front().data()));
    for (std::size_t round = 1; round < 14; ++round) {
        const auto key = load(keys[round].data());
        if constexpr (Decrypt) {
            value = _mm_aesdec_si128(value, key);
        } else {
            value = _mm_aesenc_si128(value, key);
        }
    }
    const auto last_key = load(keys.back().data());
    if constexpr (Decrypt) {
        store(output, _mm_aesdeclast_si128(value, last_key));
    } else {
        store(output, _mm_aesenclast_si128(value, last_key));
    }
}
#endif

void erase(std::array<Block, 15>& keys) noexcept {
    for (auto& block : keys) {
        volatile std::uint8_t* bytes = block.data();
        for (std::size_t i = 0; i < block.size(); ++i) {
            bytes[i] = 0;
        }
    }
}

}  // namespace

bool available() noexcept {
#if defined(ABC_X64) && defined(_MSC_VER)
    int cpu[4];
    __cpuid(cpu, 1);
    return (static_cast<unsigned>(cpu[2]) & (1U << 25)) != 0;
#elif defined(ABC_X64)
    unsigned a, b, c, d;
    return __get_cpuid(1, &a, &b, &c, &d) && (c & bit_AES) != 0;
#else
    return false;
#endif
}

Cipher::~Cipher() {
    clear();
}

Status Cipher::initialize(const Key& key) noexcept {
#ifdef ABC_X64
    if (available()) {
        schedules(key, encryption_, decryption_);
        initialized_ = true;
        return Status::ok;
    }
#else
    static_cast<void>(key);
#endif
    return Status::unsupported;
}

Status Cipher::encrypt(const Block& input, Block& output) const noexcept {
#ifdef ABC_X64
    if (initialized_) {
        run_block<false>(encryption_, input, output);
        return Status::ok;
    }
    return Status::uninitialized;
#else
    static_cast<void>(input);
    static_cast<void>(output);
    return Status::unsupported;
#endif
}

Status Cipher::decrypt(const Block& input, Block& output) const noexcept {
#ifdef ABC_X64
    if (initialized_) {
        run_block<true>(decryption_, input, output);
        return Status::ok;
    }
    return Status::uninitialized;
#else
    static_cast<void>(input);
    static_cast<void>(output);
    return Status::unsupported;
#endif
}

void Cipher::clear() noexcept {
    erase(encryption_);
    erase(decryption_);
    initialized_ = false;
}

}  // namespace abc::native_aes256
