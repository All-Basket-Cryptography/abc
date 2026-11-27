#ifndef ABC_NATIVE_CPP_KECCAK_P1600_HPP
#define ABC_NATIVE_CPP_KECCAK_P1600_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace abc::native_keccak_p1600 {

using State = std::array<std::uint64_t, 25>;
inline constexpr std::size_t rate = 136;

enum class Status { ok, invalid_argument };
enum class Domain : std::uint8_t { sha3 = 0x06, shake = 0x1f };

// Apply the 24-round permutation to lanes ordered by x + 5*y.
void permute(State& state) noexcept;

class Reader {
public:
    // Empty destinations may be null. A rejected read leaves the cursor intact.
    [[nodiscard]] Status read(std::uint8_t* output, std::size_t length) noexcept;

private:
    friend class Sponge;
    explicit Reader(const State& state) noexcept : state_(state) {}
    State state_;
    std::size_t offset_ = 0;
};

class Sponge {
public:
    // Empty inputs may be null. Nonempty inputs are consumed before return.
    [[nodiscard]] Status absorb(const std::uint8_t* input, std::size_t length) noexcept;
    [[nodiscard]] Reader finish(Domain domain) const noexcept;
    void reset() noexcept;

private:
    State state_{};
    std::size_t offset_ = 0;
};

}  // namespace abc::native_keccak_p1600

#endif
