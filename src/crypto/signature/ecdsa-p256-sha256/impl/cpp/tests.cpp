#include "ecdsa_p256_sha256.hpp"

#include <algorithm>

using namespace abc::native_ecdsa_p256_sha256;

extern "C" __declspec(dllexport) int abc_ecdsa_p256_sha256_cpp_public_key(const std::uint8_t* private_key, std::uint8_t* out) {
    if (private_key == nullptr || out == nullptr) return 1;
    Scalar scalar;
    PublicKey point;
    std::copy_n(private_key, scalar.size(), scalar.begin());
    const auto status = public_key(scalar, point);
    if (status == Status::ok) std::copy(point.begin(), point.end(), out);
    return static_cast<int>(status);
}

extern "C" __declspec(dllexport) int abc_ecdsa_p256_sha256_cpp_sign(const std::uint8_t* private_key, const std::uint8_t* message,
                                                                   std::size_t length, std::uint8_t* out) {
    if (private_key == nullptr || out == nullptr) return 1;
    Scalar scalar;
    Signature signature;
    std::copy_n(private_key, scalar.size(), scalar.begin());
    const auto status = sign(scalar, message, length, signature);
    if (status == Status::ok) std::copy(signature.begin(), signature.end(), out);
    return status == Status::retry_exhausted ? 5 : static_cast<int>(status);
}

extern "C" __declspec(dllexport) int abc_ecdsa_p256_sha256_cpp_verify(const std::uint8_t* key, std::size_t key_length,
    const std::uint8_t* message, std::size_t length, const std::uint8_t* input) {
    if (input == nullptr) return 1;
    Signature signature;
    std::copy_n(input, signature.size(), signature.begin());
    return static_cast<int>(verify(key, key_length, message, length, signature));
}
