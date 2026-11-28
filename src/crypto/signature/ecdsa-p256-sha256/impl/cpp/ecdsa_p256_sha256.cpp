#include "ecdsa_p256_sha256.hpp"
#include "../c/abc_ecdsa_p256_sha256_c.h"

namespace abc::native_ecdsa_p256_sha256 {
namespace {

Status status(int value) noexcept {
    switch (value) {
        case ABC_P256_C_OK: return Status::ok;
        case ABC_P256_C_INVALID_ARGUMENT: return Status::invalid_argument;
        case ABC_P256_C_REJECTED: return Status::rejected;
        case ABC_P256_C_RETRY_EXHAUSTED: return Status::retry_exhausted;
        default: return Status::provider_failure;
    }
}

}  // namespace

Status public_key(const Scalar& scalar, PublicKey& output) noexcept {
    return status(abc_ecdsa_p256_sha256_c_public_key(scalar.data(), output.data()));
}

Status sign(const Scalar& scalar, const std::uint8_t* message, std::size_t length, Signature& output) noexcept {
    return status(abc_ecdsa_p256_sha256_c_sign(scalar.data(), message, length, output.data()));
}

Status verify(const std::uint8_t* key, std::size_t key_length, const std::uint8_t* message,
              std::size_t length, const Signature& signature) noexcept {
    return status(abc_ecdsa_p256_sha256_c_verify(key, key_length, message, length, signature.data()));
}

}  // namespace abc::native_ecdsa_p256_sha256
