#ifndef ABC_ARGON2ID_C_H
#define ABC_ARGON2ID_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_ARGON2ID_C_BUILD_DLL)
#define ABC_ARGON2ID_C_API __declspec(dllexport)
#else
#define ABC_ARGON2ID_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct { const uint8_t *data; size_t size; } abc_argon2id_c_bytes;
typedef struct { uint32_t memory_kib; uint32_t passes; uint32_t lanes; } abc_argon2id_c_parameters;

enum {
    ABC_ARGON2ID_C_OK, ABC_ARGON2ID_C_INVALID_PARAMETERS, ABC_ARGON2ID_C_INVALID_BUFFER,
    ABC_ARGON2ID_C_MEMORY_BUDGET, ABC_ARGON2ID_C_PROVIDER_FAILURE
};

/* The budget is for the requested memory matrix. Failure preserves the tag. */
ABC_ARGON2ID_C_API int abc_argon2id_c_derive(abc_argon2id_c_parameters parameters,
    abc_argon2id_c_bytes password, abc_argon2id_c_bytes salt, abc_argon2id_c_bytes secret,
    abc_argon2id_c_bytes associated_data, size_t matrix_budget, uint8_t *tag, size_t tag_length);

#ifdef __cplusplus
}
#endif

#endif
