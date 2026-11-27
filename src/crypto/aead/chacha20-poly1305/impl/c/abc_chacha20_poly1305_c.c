#include "abc_chacha20_poly1305_c.h"

#include "abc_chacha20_c.h"
#include "abc_poly1305_c.h"

_Static_assert(SIZE_MAX <= UINT64_MAX, "ChaCha20-Poly1305 lengths fit the RFC fields");
_Static_assert((int)ABC_CHACHA20_POLY1305_C_COUNTER_RANGE == (int)ABC_CHACHA20_C_COUNTER_RANGE,
               "ChaCha20 and ChaCha20-Poly1305 counter errors share the status value");

static int validate(
    const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_length,
    const uint8_t *input, size_t length, uint8_t *output, size_t capacity)
{
    if (key == NULL || nonce == NULL || (aad_length != 0 && aad == NULL) ||
        (length != 0 && (input == NULL || output == NULL))) {
        return ABC_CHACHA20_POLY1305_C_INVALID_ARGUMENT;
    }
    if (capacity < length) {
        return ABC_CHACHA20_POLY1305_C_OUTPUT_TOO_SHORT;
    }
    if (!abc_chacha20_c_fits_counter(length, 1)) {
        return ABC_CHACHA20_POLY1305_C_COUNTER_RANGE;
    }
    return ABC_CHACHA20_POLY1305_C_OK;
}

static int overlaps_tag(const uint8_t *output, size_t length, const uint8_t *tag)
{
    if (length == 0) {
        return 0;
    }
    uintptr_t first = (uintptr_t)output;
    uintptr_t second = (uintptr_t)tag;
    return first <= second ? second - first < length :
                             first - second < ABC_CHACHA20_POLY1305_C_TAG_BYTES;
}

static void update_padded(abc_poly1305_c_mac *mac, const uint8_t *text, size_t length)
{
    static const uint8_t zeros[16] = {0};
    size_t padding = (16 - length % 16) % 16;
    (void)abc_poly1305_c_update(mac, text, length);
    (void)abc_poly1305_c_update(mac, zeros, padding);
}

static void start_mac(
    abc_poly1305_c_mac *mac, const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_length)
{
    uint8_t stream[ABC_CHACHA20_C_BLOCK_BYTES];
    (void)abc_chacha20_c_block(key, nonce, 0, stream, sizeof(stream));
    (void)abc_poly1305_c_init(mac, stream);
    volatile uint8_t *derived = stream;
    for (size_t i = 0; i < sizeof(stream); ++i) {
        derived[i] = 0;
    }
    update_padded(mac, aad, aad_length);
}

static void finish_mac(
    abc_poly1305_c_mac *mac, const uint8_t *ciphertext, size_t length, size_t aad_length,
    uint8_t tag[16])
{
    update_padded(mac, ciphertext, length);
    uint8_t lengths[16];
    for (size_t byte = 0; byte < 8; ++byte) {
        lengths[byte] = (uint8_t)((uint64_t)aad_length >> (8 * byte));
        lengths[8 + byte] = (uint8_t)((uint64_t)length >> (8 * byte));
    }
    (void)abc_poly1305_c_update(mac, lengths, sizeof(lengths));
    (void)abc_poly1305_c_finish(mac, tag, ABC_CHACHA20_POLY1305_C_TAG_BYTES);
    abc_poly1305_c_clear(mac);
}

int abc_chacha20_poly1305_c_seal(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_length, const uint8_t *input, size_t length,
    uint8_t *output, size_t capacity, uint8_t *tag, size_t tag_capacity)
{
    if (tag == NULL) {
        return ABC_CHACHA20_POLY1305_C_INVALID_ARGUMENT;
    }
    if (tag_capacity < ABC_CHACHA20_POLY1305_C_TAG_BYTES) {
        return ABC_CHACHA20_POLY1305_C_OUTPUT_TOO_SHORT;
    }
    int status = validate(key, nonce, aad, aad_length, input, length, output, capacity);
    if (status != ABC_CHACHA20_POLY1305_C_OK) {
        return status;
    }
    if (overlaps_tag(output, length, tag)) {
        return ABC_CHACHA20_POLY1305_C_INVALID_ARGUMENT;
    }
    abc_poly1305_c_mac mac;
    start_mac(&mac, key, nonce, aad, aad_length);
    (void)abc_chacha20_c_xor(key, nonce, 1, input, length, output, capacity);
    finish_mac(&mac, output, length, aad_length, tag);
    return ABC_CHACHA20_POLY1305_C_OK;
}

int abc_chacha20_poly1305_c_open(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_length, const uint8_t *input, size_t length,
    uint8_t *output, size_t capacity, const uint8_t *tag, size_t tag_length)
{
    if (tag == NULL || tag_length != ABC_CHACHA20_POLY1305_C_TAG_BYTES) {
        return ABC_CHACHA20_POLY1305_C_INVALID_ARGUMENT;
    }
    int status = validate(key, nonce, aad, aad_length, input, length, output, capacity);
    if (status != ABC_CHACHA20_POLY1305_C_OK) {
        return status;
    }
    abc_poly1305_c_mac mac;
    uint8_t expected[ABC_CHACHA20_POLY1305_C_TAG_BYTES];
    start_mac(&mac, key, nonce, aad, aad_length);
    finish_mac(&mac, input, length, aad_length, expected);
    volatile unsigned mismatch = 0;
    for (size_t i = 0; i < sizeof(expected); ++i) {
        mismatch = mismatch | (unsigned)(expected[i] ^ tag[i]);
    }
    if (mismatch != 0) {
        return ABC_CHACHA20_POLY1305_C_AUTHENTICATION_FAILED;
    }
    return abc_chacha20_c_xor(key, nonce, 1, input, length, output, capacity);
}
