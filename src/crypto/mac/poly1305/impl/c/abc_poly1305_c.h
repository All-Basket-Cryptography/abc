#ifndef ABC_POLY1305_C_H
#define ABC_POLY1305_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ABC_POLY1305_C_KEY_BYTES 32u
#define ABC_POLY1305_C_TAG_BYTES 16u

enum {
    ABC_POLY1305_C_OK = 0,
    ABC_POLY1305_C_INVALID_ARGUMENT = 1,
    ABC_POLY1305_C_OUTPUT_TOO_SHORT = 2,
    ABC_POLY1305_C_STATE = 5
};

/* Caller-owned storage. Access through these functions and keep input and
   output storage separate from the context. Use one fresh key per message. */
typedef struct abc_poly1305_c_mac {
    uint64_t residue[5], multiplier[5], folded[5];
    uint32_t pad[4];
    uint8_t pending[16], tag[16];
    size_t used;
    unsigned state;
} abc_poly1305_c_mac;

int abc_poly1305_c_init(abc_poly1305_c_mac *mac, const uint8_t key[32]);
int abc_poly1305_c_update(abc_poly1305_c_mac *mac, const uint8_t *input, size_t length);
int abc_poly1305_c_finish(abc_poly1305_c_mac *mac, uint8_t *output, size_t capacity);
void abc_poly1305_c_clear(abc_poly1305_c_mac *mac);

/* The tag destination may overlap the input or key. Errors preserve it. */
int abc_poly1305_c_authenticate(const uint8_t key[32], const uint8_t *input, size_t length,
                                uint8_t *output, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
