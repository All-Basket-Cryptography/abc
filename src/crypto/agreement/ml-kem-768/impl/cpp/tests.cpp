#include "ml_kem_768.hpp"

#include <algorithm>

using namespace abc::native_ml_kem_768;

template<class Buffer>
Buffer load(const std::uint8_t* data) {
    Buffer result;
    std::copy_n(data, result.size(), result.begin());
    return result;
}

extern "C" __declspec(dllexport) int abc_mlkem768_cpp_keygen(std::uint8_t* pub, std::uint8_t* priv) {
    KeyPair result;
    const auto status = generate(result);
    if (status == Status::ok) {
        std::copy(result.public_key.begin(), result.public_key.end(), pub);
        std::copy(result.private_key.begin(), result.private_key.end(), priv);
    }
    return static_cast<int>(status);
}

extern "C" __declspec(dllexport) int abc_mlkem768_cpp_encap(const std::uint8_t* pub, std::uint8_t* ct, std::uint8_t* sk) {
    Encapsulation result;
    const auto status = encapsulate(load<PublicKey>(pub), result);
    if (status == Status::ok) {
        std::copy(result.ciphertext.begin(), result.ciphertext.end(), ct);
        std::copy(result.shared_secret.begin(), result.shared_secret.end(), sk);
    }
    return static_cast<int>(status);
}

extern "C" __declspec(dllexport) int abc_mlkem768_cpp_decap(const std::uint8_t* priv, const std::uint8_t* ct, std::uint8_t* sk) {
    Secret result;
    const auto status = decapsulate(load<PrivateKey>(priv), load<Ciphertext>(ct), result);
    if (status == Status::ok) std::copy(result.begin(), result.end(), sk);
    return static_cast<int>(status);
}

#ifdef ABC_MLKEM768_TESTING
extern "C" __declspec(dllexport) int abc_mlkem768_cpp_test_keygen(const std::uint8_t* seed, std::uint8_t* pub, std::uint8_t* priv) {
    KeyPair result;
    const auto status = generate_for_test(load<TestSeed>(seed), result);
    if (status == Status::ok) {
        std::copy(result.public_key.begin(), result.public_key.end(), pub);
        std::copy(result.private_key.begin(), result.private_key.end(), priv);
    }
    return static_cast<int>(status);
}

extern "C" __declspec(dllexport) int abc_mlkem768_cpp_test_encap(const std::uint8_t* pub, const std::uint8_t* nonce,
                                                                std::uint8_t* ct, std::uint8_t* sk) {
    Encapsulation result;
    const auto status = encapsulate_for_test(load<PublicKey>(pub), load<Secret>(nonce), result);
    if (status == Status::ok) {
        std::copy(result.ciphertext.begin(), result.ciphertext.end(), ct);
        std::copy(result.shared_secret.begin(), result.shared_secret.end(), sk);
    }
    return static_cast<int>(status);
}
#endif
