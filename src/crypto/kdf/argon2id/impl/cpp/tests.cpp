#include "argon2id.hpp"

using namespace abc::native_argon2id;

extern "C" __declspec(dllexport) int abc_argon2id_c_derive(Parameters params, Bytes password, Bytes salt, Bytes secret,
    Bytes data, std::size_t budget, std::uint8_t* out, std::size_t out_length) {
    return static_cast<int>(derive(params, password, salt, secret, data, budget, out, out_length));
}
