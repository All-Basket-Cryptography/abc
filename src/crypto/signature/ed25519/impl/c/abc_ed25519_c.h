#ifndef ABC_ED25519_C_H
#define ABC_ED25519_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_ED25519_C_BUILD_DLL)
#define ABC_ED25519_C_API __declspec(dllexport)
#else
#define ABC_ED25519_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum { ABC_ED25519_C_OK, ABC_ED25519_C_INVALID_ARGUMENT, ABC_ED25519_C_REJECTED,
       ABC_ED25519_C_PROVIDER_FAILURE };
#define ABC_ED25519_C_SEED_BYTES 32
#define ABC_ED25519_C_PUBLIC_BYTES 32
#define ABC_ED25519_C_SIGNATURE_BYTES 64

/* Seed, public key and signature buffers have exactly their named sizes.
 * An empty message may be NULL. A rejected operation preserves output. */
ABC_ED25519_C_API int abc_ed25519_c_public_key(const uint8_t seed[32], uint8_t public_key[32]);
ABC_ED25519_C_API int abc_ed25519_c_sign(const uint8_t seed[32], const uint8_t *message,
                                        size_t length, uint8_t signature[64]);
ABC_ED25519_C_API int abc_ed25519_c_verify_strict(const uint8_t public_key[32], const uint8_t *message,
                                                 size_t length, const uint8_t signature[64]);

#ifdef __cplusplus
}
#endif

#endif
