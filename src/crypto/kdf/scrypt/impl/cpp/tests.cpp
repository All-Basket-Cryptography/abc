#include "scrypt.hpp"

#if defined(_WIN32)
#define ABC_TEST_API __declspec(dllexport)
#else
#define ABC_TEST_API __attribute__((visibility("default")))
#endif

using namespace abc::native_scrypt;

extern "C" ABC_TEST_API int abc_scrypt_test_workspace_bytes(std::size_t n, std::uint32_t r, std::uint32_t p,
                                                            std::size_t* bytes) {
    return static_cast<int>(bytes ? workspace_bytes({n, r, p}, *bytes) : Status::invalid_buffer);
}

extern "C" ABC_TEST_API int abc_scrypt_test_derive(const std::uint8_t* password, std::size_t password_length,
    const std::uint8_t* salt, std::size_t salt_length, std::size_t n, std::uint32_t r, std::uint32_t p,
    std::uint8_t* workspace, std::size_t workspace_length, std::uint8_t* output, std::size_t output_length) {
    return static_cast<int>(derive(password, password_length, salt, salt_length, {n, r, p},
                                  workspace, workspace_length, output, output_length));
}
