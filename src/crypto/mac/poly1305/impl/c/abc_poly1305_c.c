#include "abc_poly1305_c.h"

#include <string.h>

#define LIMB_BITS 26u
#define LIMB_MASK ((UINT64_C(1) << LIMB_BITS) - 1)
#define FULL_BIT (UINT64_C(1) << 24)

enum { ACTIVE = 1, FINISHED = 2 };

static void clear_bytes(void *data, size_t length)
{
    volatile unsigned char *bytes = data;
    for (size_t i = 0; i < length; ++i) {
        bytes[i] = 0;
    }
}

static uint32_t load_word(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

static void unpack(uint64_t limbs[5], const uint8_t block[16])
{
    uint64_t a = load_word(block), b = load_word(block + 4);
    uint64_t c = load_word(block + 8), d = load_word(block + 12);
    limbs[0] = a & LIMB_MASK;
    limbs[1] = (a >> 26 | b << 6) & LIMB_MASK;
    limbs[2] = (b >> 20 | c << 12) & LIMB_MASK;
    limbs[3] = (c >> 14 | d << 18) & LIMB_MASK;
    limbs[4] = d >> 8;
}

static void carry(uint64_t limbs[5])
{
    for (size_t i = 0; i < 4; ++i) {
        limbs[i + 1] += limbs[i] >> LIMB_BITS;
        limbs[i] &= LIMB_MASK;
    }
    limbs[0] += 5 * (limbs[4] >> LIMB_BITS);
    limbs[4] &= LIMB_MASK;
    limbs[1] += limbs[0] >> LIMB_BITS;
    limbs[0] &= LIMB_MASK;
}

static void absorb(abc_poly1305_c_mac *mac, const uint8_t block[16], uint64_t high_bit)
{
    uint64_t h[5];
    unpack(h, block);
    for (size_t i = 0; i < 5; ++i) {
        h[i] += mac->residue[i];
    }
    h[4] += high_bit;
    const uint64_t *r = mac->multiplier;
    const uint64_t *f = mac->folded;
    uint64_t *d = mac->residue;
    d[0] = h[0] * r[0] + h[1] * f[4] + h[2] * f[3] + h[3] * f[2] + h[4] * f[1];
    d[1] = h[0] * r[1] + h[1] * r[0] + h[2] * f[4] + h[3] * f[3] + h[4] * f[2];
    d[2] = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * f[4] + h[4] * f[3];
    d[3] = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * f[4];
    d[4] = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];
    carry(d);
}

void abc_poly1305_c_clear(abc_poly1305_c_mac *mac)
{
    if (mac != NULL) {
        clear_bytes(mac, sizeof(*mac));
    }
}

int abc_poly1305_c_init(abc_poly1305_c_mac *mac, const uint8_t key[32])
{
    if (mac == NULL || key == NULL) {
        return ABC_POLY1305_C_INVALID_ARGUMENT;
    }
    uint8_t staged[32];
    memcpy(staged, key, sizeof(staged));
    memset(mac, 0, sizeof(*mac));
    for (size_t i = 0; i < 4; ++i) {
        mac->pad[i] = load_word(staged + 16 + 4 * i);
        staged[4 * i + 3] &= 15;
    }
    for (size_t i = 4; i < 16; i += 4) {
        staged[i] &= 252;
    }
    unpack(mac->multiplier, staged);
    for (size_t i = 1; i < 5; ++i) {
        mac->folded[i] = 5 * mac->multiplier[i];
    }
    clear_bytes(staged, sizeof(staged));
    mac->state = ACTIVE;
    return ABC_POLY1305_C_OK;
}

int abc_poly1305_c_update(abc_poly1305_c_mac *mac, const uint8_t *input, size_t length)
{
    if (mac == NULL || (input == NULL && length != 0)) {
        return ABC_POLY1305_C_INVALID_ARGUMENT;
    }
    if (mac->state != ACTIVE) {
        return ABC_POLY1305_C_STATE;
    }
    if (length == 0) {
        return ABC_POLY1305_C_OK;
    }
    if (mac->used != 0) {
        size_t room = sizeof(mac->pending) - mac->used;
        size_t taken = length < room ? length : room;
        memcpy(mac->pending + mac->used, input, taken);
        mac->used += taken;
        if (mac->used < sizeof(mac->pending)) {
            return ABC_POLY1305_C_OK;
        }
        absorb(mac, mac->pending, FULL_BIT);
        input += taken;
        length -= taken;
        mac->used = 0;
    }
    while (length >= sizeof(mac->pending)) {
        absorb(mac, input, FULL_BIT);
        input += sizeof(mac->pending);
        length -= sizeof(mac->pending);
    }
    if (length != 0) {
        memcpy(mac->pending, input, length);
        mac->used = length;
    }
    return ABC_POLY1305_C_OK;
}

static void final_tag(abc_poly1305_c_mac *mac, uint8_t tag[16])
{
    if (mac->used != 0) {
        memset(mac->pending + mac->used, 0, sizeof(mac->pending) - mac->used);
        mac->pending[mac->used] = 1;
        absorb(mac, mac->pending, 0);
    }
    uint64_t *h = mac->residue;
    carry(h);
    uint64_t reduced[5];
    memcpy(reduced, h, sizeof(reduced));
    reduced[0] += 5;
    for (size_t i = 0; i < 4; ++i) {
        reduced[i + 1] += reduced[i] >> LIMB_BITS;
        reduced[i] &= LIMB_MASK;
    }
    uint64_t choose = UINT64_C(0) - (reduced[4] >> LIMB_BITS);
    reduced[4] &= LIMB_MASK;
    for (size_t i = 0; i < 5; ++i) {
        h[i] = (h[i] & ~choose) | (reduced[i] & choose);
    }
    const uint32_t words[4] = {
        (uint32_t)(h[0] | h[1] << 26), (uint32_t)(h[1] >> 6 | h[2] << 20),
        (uint32_t)(h[2] >> 12 | h[3] << 14), (uint32_t)(h[3] >> 18 | h[4] << 8)
    };
    uint64_t sum = 0;
    for (size_t i = 0; i < 4; ++i) {
        sum = (sum >> 32) + (uint64_t)words[i] + mac->pad[i];
        for (size_t j = 0; j < 4; ++j) {
            tag[4 * i + j] = (uint8_t)(sum >> (8 * j));
        }
    }
}

int abc_poly1305_c_finish(abc_poly1305_c_mac *mac, uint8_t *output, size_t capacity)
{
    if (mac == NULL || output == NULL) {
        return ABC_POLY1305_C_INVALID_ARGUMENT;
    }
    if (capacity < ABC_POLY1305_C_TAG_BYTES) {
        return ABC_POLY1305_C_OUTPUT_TOO_SHORT;
    }
    if (mac->state != ACTIVE && mac->state != FINISHED) {
        return ABC_POLY1305_C_STATE;
    }
    if (mac->state == ACTIVE) {
        uint8_t tag[16];
        final_tag(mac, tag);
        abc_poly1305_c_clear(mac);
        memcpy(mac->tag, tag, sizeof(tag));
        mac->state = FINISHED;
    }
    memcpy(output, mac->tag, sizeof(mac->tag));
    return ABC_POLY1305_C_OK;
}

int abc_poly1305_c_authenticate(const uint8_t key[32], const uint8_t *input, size_t length,
                                uint8_t *output, size_t capacity)
{
    if (key == NULL || output == NULL || (input == NULL && length != 0)) {
        return ABC_POLY1305_C_INVALID_ARGUMENT;
    }
    if (capacity < ABC_POLY1305_C_TAG_BYTES) {
        return ABC_POLY1305_C_OUTPUT_TOO_SHORT;
    }
    abc_poly1305_c_mac mac;
    (void)abc_poly1305_c_init(&mac, key);
    (void)abc_poly1305_c_update(&mac, input, length);
    int status = abc_poly1305_c_finish(&mac, output, capacity);
    abc_poly1305_c_clear(&mac);
    return status;
}
