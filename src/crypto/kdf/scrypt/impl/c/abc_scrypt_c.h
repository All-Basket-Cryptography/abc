#ifndef ABC_SCRYPT_C_H
#define ABC_SCRYPT_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_SCRYPT_C_BUILD_DLL)
#define ABC_SCRYPT_C_API __declspec(dllexport)
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_SCRYPT_C_API __attribute__((visibility("default")))
#else
#define ABC_SCRYPT_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ABC_SCRYPT_C_OK,
    ABC_SCRYPT_C_BAD_PARAMETERS,
    ABC_SCRYPT_C_INVALID_BUFFER,
    ABC_SCRYPT_C_LENGTH_LIMIT,
    ABC_SCRYPT_C_WORKSPACE_TOO_SMALL,
    ABC_SCRYPT_C_BACKEND_ERROR
};

/* On success writes the workspace size for serial lane processing. */
ABC_SCRYPT_C_API int abc_scrypt_c_workspace_bytes(size_t n, uint32_t r, uint32_t p, size_t *bytes);

/* The used workspace prefix must be disjoint from the other buffers. Empty
 * password and salt may be NULL. Output may overlap either input. Preflight
 * rejection preserves the output and workspace. Execution clears the used
 * workspace before returning. */
ABC_SCRYPT_C_API int abc_scrypt_c_derive(const uint8_t *password, size_t password_length,
    const uint8_t *salt, size_t salt_length, size_t n, uint32_t r, uint32_t p,
    uint8_t *workspace, size_t workspace_length, uint8_t *output, size_t output_length);

#ifdef __cplusplus
}
#endif

#endif
