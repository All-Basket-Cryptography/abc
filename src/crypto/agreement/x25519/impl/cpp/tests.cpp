#include "x25519.hpp"

#include <algorithm>

using namespace abc::native_x25519;

extern "C" __declspec(dllexport) int abc_x25519_c_public_key(const std::uint8_t* key, std::size_t key_len,
    std::uint8_t* out, std::size_t out_len) {
    if (key == nullptr || key_len != 32 || out == nullptr || out_len != 32) return 1;
    Key scalar;
    std::copy_n(key, scalar.size(), scalar.begin());
    auto result = public_key(scalar, scalar);
    if (result == Status::ok) std::copy(scalar.begin(), scalar.end(), out);
    return result == Status::ok ? 0 : 3;
}

extern "C" __declspec(dllexport) int abc_x25519_c_shared_secret(const std::uint8_t* key, std::size_t key_len,
    const std::uint8_t* peer, std::size_t peer_len, std::uint8_t* out, std::size_t out_len) {
    if (key == nullptr || key_len != 32 || peer == nullptr || peer_len != 32 || out == nullptr || out_len != 32) return 1;
    Key scalar, public_point;
    std::copy_n(key, scalar.size(), scalar.begin());
    std::copy_n(peer, public_point.size(), public_point.begin());
    auto result = shared_secret(scalar, public_point, scalar);
    if (result == Status::ok) std::copy(scalar.begin(), scalar.end(), out);
    return result == Status::ok ? 0 : result == Status::invalid_peer ? 2 : 3;
}
