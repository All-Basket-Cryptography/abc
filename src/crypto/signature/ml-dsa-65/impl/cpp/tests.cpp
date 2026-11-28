#include "ml_dsa_65.hpp"

#include <algorithm>

using namespace abc::native_ml_dsa_65;

template<class Buffer>
Buffer load(const std::uint8_t* data) {
    Buffer result;
    std::copy_n(data, result.size(), result.begin());
    return result;
}

extern "C" __declspec(dllexport) int abc_mldsa65_cpp_public(const std::uint8_t* seed, std::uint8_t* out) {
    PublicKey result;
    const auto status = public_key(load<Seed>(seed), result);
    if (status == Status::ok) std::copy(result.begin(), result.end(), out);
    return static_cast<int>(status);
}

extern "C" __declspec(dllexport) int abc_mldsa65_cpp_sign(const std::uint8_t* seed, Bytes input, Bytes context, std::uint8_t* out) {
    Signature result;
    const auto status = sign(load<Seed>(seed), input, context, result);
    if (status == Status::ok) std::copy(result.begin(), result.end(), out);
    return static_cast<int>(status);
}

extern "C" __declspec(dllexport) int abc_mldsa65_cpp_verify(const std::uint8_t* pub, Bytes input, Bytes context, const std::uint8_t* sig) {
    return static_cast<int>(verify(load<PublicKey>(pub), input, context, load<Signature>(sig)));
}

#ifdef ABC_MLDSA65_TESTING
extern "C" __declspec(dllexport) int abc_mldsa65_cpp_sign_expanded(const std::uint8_t* key, Bytes input,
                                                                  Bytes context, std::uint8_t* out) {
    Signature result;
    const auto status = sign_expanded_for_test(load<ExpandedKey>(key), input, context, result);
    if (status == Status::ok) std::copy(result.begin(), result.end(), out);
    return static_cast<int>(status);
}
#endif
