#ifndef ABC_X25519_C_H
#define ABC_X25519_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_X25519_C_BUILD_DLL)
#define ABC_X25519_C_API __declspec(dllexport)
#else
#define ABC_X25519_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum { ABC_X25519_C_OK, ABC_X25519_C_INVALID_LENGTH, ABC_X25519_C_INVALID_PEER,
       ABC_X25519_C_PROVIDER_FAILURE };
#define ABC_X25519_C_BYTES 32

/* Every buffer has exactly 32 bytes. Failure preserves the output. */
ABC_X25519_C_API int abc_x25519_c_public_key(const uint8_t *scalar, size_t scalar_length,
                                           uint8_t *public_key, size_t output_length);
ABC_X25519_C_API int abc_x25519_c_shared_secret(const uint8_t *scalar, size_t scalar_length,
    const uint8_t *peer, size_t peer_length, uint8_t *secret, size_t output_length);

#ifdef __cplusplus
}
#endif

#endif
