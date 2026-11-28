#include "ed25519.hpp"

#include <algorithm>

using namespace abc::native_ed25519;

extern "C" __declspec(dllexport) int abc_ed25519_c_public_key(const std::uint8_t* seed, std::uint8_t* output) {
    if (seed == nullptr || output == nullptr) return 1;
    Key bytes;
    std::copy_n(seed, bytes.size(), bytes.begin());
    const auto result = public_key(bytes, bytes);
    if (result == Status::ok) std::copy(bytes.begin(), bytes.end(), output);
    return static_cast<int>(result);
}

extern "C" __declspec(dllexport) int abc_ed25519_c_sign(const std::uint8_t* seed, const std::uint8_t* message,
                                                       std::size_t size, std::uint8_t* output) {
    if (seed == nullptr || output == nullptr) return 1;
    Key bytes;
    Signature signature;
    std::copy_n(seed, bytes.size(), bytes.begin());
    const auto result = sign(bytes, message, size, signature);
    if (result == Status::ok) std::copy(signature.begin(), signature.end(), output);
    return static_cast<int>(result);
}

extern "C" __declspec(dllexport) int abc_ed25519_c_verify_strict(const std::uint8_t* pub, const std::uint8_t* message,
                                                                std::size_t size, const std::uint8_t* signature) {
    if (pub == nullptr || signature == nullptr) return 1;
    Key key;
    Signature sig;
    std::copy_n(pub, key.size(), key.begin());
    std::copy_n(signature, sig.size(), sig.begin());
    return static_cast<int>(verify_strict(key, message, size, sig));
}
