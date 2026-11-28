#include "aes256_gcm.hpp"

#include <algorithm>
#include <limits>

namespace abc::native_aes256_gcm {
namespace {

using Block = native_aes256::Block;
using Cipher = native_aes256::Cipher;
using Field = std::array<std::uint64_t, 2>;

constexpr std::uint64_t max_payload = UINT64_C(0xfffffffe) * 16;
constexpr std::uint64_t max_aad = std::numeric_limits<std::uint64_t>::max() / 8;

std::uint64_t load_be(const std::uint8_t* input) noexcept {
    std::uint64_t word = 0;
    for (unsigned i = 0; i < 8; ++i) {
        word = (word << 8) | input[i];
    }
    return word;
}

void store_be(std::uint8_t* output, std::uint64_t word) noexcept {
    for (unsigned i = 0; i < 8; ++i) {
        output[i] = static_cast<std::uint8_t>(word >> (56 - 8 * i));
    }
}

void absorb(Field& chain, Field h, const std::uint8_t* block) noexcept {
    const Field x{chain[0] ^ load_be(block), chain[1] ^ load_be(block + 8)};
    Field product{};
    for (auto word : x) {
        for (unsigned bit = 0; bit < 64; ++bit) {
            const auto select = std::uint64_t{0} - (word >> 63);
            const auto reduce = std::uint64_t{0} - (h[1] & 1);
            product[0] ^= h[0] & select;
            product[1] ^= h[1] & select;
            h[1] = (h[1] >> 1) | (h[0] << 63);
            h[0] = (h[0] >> 1) ^ (UINT64_C(0xe100000000000000) & reduce);
            word <<= 1;
        }
    }
    chain = product;
}

void absorb_bytes(Field& chain, const Field& hash, const std::uint8_t* input, std::size_t length) noexcept {
    while (length >= 16) {
        absorb(chain, hash, input);
        input += 16;
        length -= 16;
    }
    if (length != 0) {
        Block block{};
        std::copy_n(input, length, block.begin());
        absorb(chain, hash, block.data());
    }
}

Block counter(const Nonce& nonce, std::uint32_t index) noexcept {
    Block result{};
    std::copy(nonce.begin(), nonce.end(), result.begin());
    for (unsigned i = 0; i < 4; ++i) {
        result[12 + i] = static_cast<std::uint8_t>(index >> (24 - 8 * i));
    }
    return result;
}

void transform(const Cipher& key, const Nonce& nonce, const std::uint8_t* input,
               std::uint8_t* output, std::size_t length) noexcept {
    const auto src = reinterpret_cast<std::uintptr_t>(input);
    const auto dst = reinterpret_cast<std::uintptr_t>(output);
    const bool backwards = dst > src && dst - src < length;
    const auto blocks = length / 16 + (length % 16 != 0);
    for (std::size_t visited = 0; visited < blocks; ++visited) {
        const auto index = backwards ? blocks - 1 - visited : visited;
        const auto offset = 16 * index;
        const auto count = std::min<std::size_t>(length - offset, 16);
        auto pad = counter(nonce, static_cast<std::uint32_t>(index) + 2);
        static_cast<void>(key.encrypt(pad, pad));
        Block source;
        std::copy_n(input + offset, count, source.begin());
        for (std::size_t i = 0; i < count; ++i) {
            output[offset + i] = source[i] ^ pad[i];
        }
    }
}

Tag finish(const Field& h, Field chain, std::size_t aad_length, std::size_t length, const Block& mask) noexcept {
    Block block;
    store_be(block.data(), static_cast<std::uint64_t>(aad_length) * 8);
    store_be(block.data() + 8, static_cast<std::uint64_t>(length) * 8);
    absorb(chain, h, block.data());
    store_be(block.data(), chain[0] ^ load_be(mask.data()));
    store_be(block.data() + 8, chain[1] ^ load_be(mask.data() + 8));
    return block;
}

bool valid(const std::uint8_t* aad, std::size_t aad_length, const std::uint8_t* input,
           std::size_t length, const std::uint8_t* output, std::size_t output_length) noexcept {
    return (aad_length == 0 || aad != nullptr) && (length == 0 || (input != nullptr && output != nullptr))
        && length == output_length && length <= max_payload && aad_length <= max_aad;
}

bool overlaps_tag(const std::uint8_t* output, std::size_t length, const Tag& tag) noexcept {
    if (length == 0) {
        return false;
    }
    const auto left = reinterpret_cast<std::uintptr_t>(output);
    const auto right = reinterpret_cast<std::uintptr_t>(tag.data());
    return left <= right ? right - left < length : left - right < tag.size();
}

Status map_status(native_aes256::Status status) noexcept {
    switch (status) {
        case native_aes256::Status::ok: return Status::ok;
        case native_aes256::Status::uninitialized: return Status::uninitialized;
        case native_aes256::Status::unsupported: return Status::unsupported;
    }
    return Status::unsupported;
}

}  // namespace

Gcm::~Gcm() {
    clear_hash();
}

void Gcm::clear_hash() noexcept {
    for (auto& half : hash_) {
        volatile std::uint64_t* word = &half;
        *word = 0;
    }
}

void Gcm::clear() noexcept {
    clear_hash();
    cipher_.clear();
}

Status Gcm::initialize(const Key& key) noexcept {
    const auto status = map_status(cipher_.initialize(key));
    if (status != Status::ok) {
        return status;
    }
    Block block{};
    static_cast<void>(cipher_.encrypt(block, block));
    hash_ = {load_be(block.data()), load_be(block.data() + 8)};
    return Status::ok;
}

Status Gcm::seal(const Nonce& nonce, const std::uint8_t* aad, std::size_t aad_length,
                 const std::uint8_t* input, std::size_t length, std::uint8_t* output,
                 std::size_t output_length, Tag& tag) const noexcept {
    if (!valid(aad, aad_length, input, length, output, output_length) || overlaps_tag(output, length, tag)) {
        return Status::invalid_argument;
    }
    const auto nonce_copy = nonce;
    auto mask = counter(nonce_copy, 1);
    if (const auto status = map_status(cipher_.encrypt(mask, mask)); status != Status::ok) {
        return status;
    }
    Field chain{};
    absorb_bytes(chain, hash_, aad, aad_length);
    transform(cipher_, nonce_copy, input, output, length);
    absorb_bytes(chain, hash_, output, length);
    tag = finish(hash_, chain, aad_length, length, mask);
    return Status::ok;
}

Status Gcm::open(const Nonce& nonce, const std::uint8_t* aad, std::size_t aad_length,
                 const std::uint8_t* input, std::size_t length, const Tag& tag,
                 std::uint8_t* output, std::size_t output_length) const noexcept {
    if (!valid(aad, aad_length, input, length, output, output_length)) {
        return Status::invalid_argument;
    }
    const auto nonce_copy = nonce;
    auto mask = counter(nonce_copy, 1);
    if (const auto status = map_status(cipher_.encrypt(mask, mask)); status != Status::ok) {
        return status;
    }
    Field chain{};
    absorb_bytes(chain, hash_, aad, aad_length);
    absorb_bytes(chain, hash_, input, length);
    const auto wanted = finish(hash_, chain, aad_length, length, mask);
    std::uint8_t differences = 0;
    for (std::size_t i = 0; i < tag.size(); ++i) {
        differences |= tag[i] ^ wanted[i];
    }
    if (differences != 0) {
        return Status::authentication_failed;
    }
    transform(cipher_, nonce_copy, input, output, length);
    return Status::ok;
}

}  // namespace abc::native_aes256_gcm
