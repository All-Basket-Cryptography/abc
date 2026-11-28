#ifndef ABC_MLDSA65_C_H
#define ABC_MLDSA65_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_MLDSA65_C_SHARED)
#if defined(ABC_MLDSA65_C_BUILD)
#define ABC_MLDSA65_C_API __declspec(dllexport)
#else
#define ABC_MLDSA65_C_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_MLDSA65_C_API __attribute__((visibility("default")))
#else
#define ABC_MLDSA65_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_MLDSA65_C_SEED_BYTES 32
#define ABC_MLDSA65_C_PUBLIC_KEY_BYTES 1952
#define ABC_MLDSA65_C_SIGNATURE_BYTES 3309
#define ABC_MLDSA65_C_MAX_CONTEXT_BYTES 255

enum {
    ABC_MLDSA65_C_OK = 0,
    ABC_MLDSA65_C_INVALID_ARGUMENT = 1,
    ABC_MLDSA65_C_INVALID_LENGTH = 2,
    ABC_MLDSA65_C_VERIFICATION_FAILED = 3,
    ABC_MLDSA65_C_BACKEND_ERROR = 4
};

/* The caller supplies a 32-byte secret seed from its approved entropy source.
 * Output may overlap inputs. Failure leaves the output unchanged. */
ABC_MLDSA65_C_API int abc_mldsa65_c_public_key(
    const uint8_t *seed, size_t seed_len, uint8_t *public_key, size_t capacity);

/* Pure deterministic ML-DSA-65. NULL context and message are permitted at length zero. */
ABC_MLDSA65_C_API int abc_mldsa65_c_sign(
    const uint8_t *seed, size_t seed_len, const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len, uint8_t *signature, size_t capacity);

ABC_MLDSA65_C_API int abc_mldsa65_c_verify(
    const uint8_t *public_key, size_t public_key_len, const uint8_t *message, size_t message_len,
    const uint8_t *context, size_t context_len, const uint8_t *signature, size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif
