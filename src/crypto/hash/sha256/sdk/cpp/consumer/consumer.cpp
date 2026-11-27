#include <abc/sha256.hpp>

#undef NDEBUG
#include <cassert>
#include <type_traits>
#include <utility>

int main() {
    static_assert(std::is_nothrow_move_constructible_v<abc::sha256_stream>);
    static_assert(std::is_nothrow_move_assignable_v<abc::sha256_stream>);
    static_assert(!std::is_copy_constructible_v<abc::sha256_stream>);
    static_assert(!std::is_copy_assignable_v<abc::sha256_stream>);

    const abc::digest256 expected{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    const std::uint8_t input[]{'a', 'b', 'c'};
    assert(abc_abi_version() == ABC_ABI_VERSION);
    assert(abc::sha256(input, sizeof input) == expected);

    abc::sha256_stream stream;
    stream.update(input, 1);
    auto moved = std::move(stream);
    try {
        stream.reset();
        assert(false);
    } catch (const abc::error &error) {
        assert(error.status() == ABC_ERROR_STATE);
    }
    try {
        moved.update(nullptr, 1);
        assert(false);
    } catch (const abc::error &error) {
        assert(error.status() == ABC_ERROR_NULL);
    }
    moved.update(nullptr, 0);
    moved.update(input + 1, 2);
    stream = std::move(moved);
    assert(stream.finalize() == expected);
    try {
        stream.finalize();
        assert(false);
    } catch (const abc::error &error) {
        assert(error.status() == ABC_ERROR_STATE);
    }
    stream.reset();
    stream.update(input, sizeof input);
    assert(stream.finalize() == expected);
}
