#ifndef ABC_KECCAK_P1600_C_H
#define ABC_KECCAK_P1600_C_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(ABC_KECCAK_C_SHARED)
#if defined(ABC_KECCAK_C_BUILD)
#define ABC_KECCAK_C_API __declspec(dllexport)
#else
#define ABC_KECCAK_C_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define ABC_KECCAK_C_API __attribute__((visibility("default")))
#else
#define ABC_KECCAK_C_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_KECCAK_C_RATE 136
#define ABC_KECCAK_C_LANES 25

enum {
    ABC_KECCAK_C_OK = 0,
    ABC_KECCAK_C_INVALID_ARGUMENT = 1,
    ABC_KECCAK_C_DESTINATION_TOO_SHORT = 2
};

typedef enum {
    ABC_KECCAK_C_SHA3 = 0x06,
    ABC_KECCAK_C_SHAKE = 0x1f
} abc_keccak_c_domain;

/* State fields are internal. Initialize the sponge before using it. */
typedef struct {
    uint64_t lanes[ABC_KECCAK_C_LANES];
    size_t offset;
} abc_keccak_c_sponge;

typedef struct {
    uint64_t lanes[ABC_KECCAK_C_LANES];
    size_t offset;
} abc_keccak_c_reader;

/* The state points to 25 writable lanes ordered by x + 5*y. */
ABC_KECCAK_C_API void abc_keccak_p1600_c_permute(uint64_t state[ABC_KECCAK_C_LANES]);

ABC_KECCAK_C_API int abc_keccak_c_init(abc_keccak_c_sponge *sponge);
ABC_KECCAK_C_API int abc_keccak_c_absorb(abc_keccak_c_sponge *sponge, const uint8_t *input, size_t length);
ABC_KECCAK_C_API int abc_keccak_c_finish(
    const abc_keccak_c_sponge *sponge, abc_keccak_c_domain domain, abc_keccak_c_reader *reader);
ABC_KECCAK_C_API int abc_keccak_c_read(abc_keccak_c_reader *reader, uint8_t *output, size_t length);

#ifdef __cplusplus
}
#endif

#endif
