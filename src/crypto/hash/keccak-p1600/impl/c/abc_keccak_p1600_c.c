#include "abc_keccak_p1600_c.h"

#include <string.h>

static const uint64_t round_constants[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082), UINT64_C(0x800000000000808a),
    UINT64_C(0x8000000080008000), UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009), UINT64_C(0x000000000000008a),
    UINT64_C(0x0000000000000088), UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b), UINT64_C(0x8000000000008089),
    UINT64_C(0x8000000000008003), UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a), UINT64_C(0x8000000080008081),
    UINT64_C(0x8000000000008080), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

static uint64_t rotl(uint64_t word, unsigned distance) {
    return (word << distance) | (word >> (64 - distance));
}

static inline void move_lane(uint64_t state[25], uint64_t *carried, unsigned lane, unsigned rotation) {
    uint64_t saved = state[lane];
    state[lane] = rotl(*carried, rotation);
    *carried = saved;
}

void abc_keccak_p1600_c_permute(uint64_t state[ABC_KECCAK_C_LANES]) {
    for (unsigned round = 0; round < 24; ++round) {
        uint64_t parity[5];
        for (unsigned x = 0; x < 5; ++x) {
            parity[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (unsigned x = 0; x < 5; ++x) {
            uint64_t delta = parity[(x + 4) % 5] ^ rotl(parity[(x + 1) % 5], 1);
            for (unsigned lane = x; lane < ABC_KECCAK_C_LANES; lane += 5) {
                state[lane] ^= delta;
            }
        }

        // FIPS 202 rho and pi visit each nonzero lane in one cycle.
        uint64_t carried = state[1];
        move_lane(state, &carried, 10, 1);
        move_lane(state, &carried, 7, 3);
        move_lane(state, &carried, 11, 6);
        move_lane(state, &carried, 17, 10);
        move_lane(state, &carried, 18, 15);
        move_lane(state, &carried, 3, 21);
        move_lane(state, &carried, 5, 28);
        move_lane(state, &carried, 16, 36);
        move_lane(state, &carried, 8, 45);
        move_lane(state, &carried, 21, 55);
        move_lane(state, &carried, 24, 2);
        move_lane(state, &carried, 4, 14);
        move_lane(state, &carried, 15, 27);
        move_lane(state, &carried, 23, 41);
        move_lane(state, &carried, 19, 56);
        move_lane(state, &carried, 13, 8);
        move_lane(state, &carried, 12, 25);
        move_lane(state, &carried, 2, 43);
        move_lane(state, &carried, 20, 62);
        move_lane(state, &carried, 14, 18);
        move_lane(state, &carried, 22, 39);
        move_lane(state, &carried, 9, 61);
        move_lane(state, &carried, 6, 20);
        move_lane(state, &carried, 1, 44);

        for (unsigned row = 0; row < ABC_KECCAK_C_LANES; row += 5) {
            uint64_t a = state[row], b = state[row + 1], c = state[row + 2];
            uint64_t d = state[row + 3], e = state[row + 4];
            state[row] = a ^ (~b & c);
            state[row + 1] = b ^ (~c & d);
            state[row + 2] = c ^ (~d & e);
            state[row + 3] = d ^ (~e & a);
            state[row + 4] = e ^ (~a & b);
        }
        state[0] ^= round_constants[round];
    }
}

static uint64_t load_lane(const uint8_t *bytes) {
    return (uint64_t)bytes[0]       | (uint64_t)bytes[1] << 8  |
           (uint64_t)bytes[2] << 16 | (uint64_t)bytes[3] << 24 |
           (uint64_t)bytes[4] << 32 | (uint64_t)bytes[5] << 40 |
           (uint64_t)bytes[6] << 48 | (uint64_t)bytes[7] << 56;
}

static void store_lane(uint8_t *bytes, uint64_t word) {
    for (unsigned i = 0; i < 8; ++i) {
        bytes[i] = (uint8_t)(word >> (8 * i));
    }
}

static void xor_byte(uint64_t *lanes, size_t offset, uint8_t byte) {
    lanes[offset / 8] ^= (uint64_t)byte << (8 * (offset % 8));
}

static uint8_t read_byte(const uint64_t *lanes, size_t offset) {
    return (uint8_t)(lanes[offset / 8] >> (8 * (offset % 8)));
}

int abc_keccak_c_init(abc_keccak_c_sponge *sponge) {
    if (sponge == NULL) {
        return ABC_KECCAK_C_INVALID_ARGUMENT;
    }
    memset(sponge, 0, sizeof(*sponge));
    return ABC_KECCAK_C_OK;
}

int abc_keccak_c_absorb(abc_keccak_c_sponge *sponge, const uint8_t *input, size_t length) {
    if (sponge == NULL || (input == NULL && length != 0)) {
        return ABC_KECCAK_C_INVALID_ARGUMENT;
    }
    if (length == 0) {
        return ABC_KECCAK_C_OK;
    }

    if (sponge->offset != 0) {
        size_t space = ABC_KECCAK_C_RATE - sponge->offset;
        size_t count = length < space ? length : space;
        for (size_t i = 0; i < count; ++i) {
            xor_byte(sponge->lanes, sponge->offset + i, input[i]);
        }
        sponge->offset += count;
        if (sponge->offset < ABC_KECCAK_C_RATE) {
            return ABC_KECCAK_C_OK;
        }
        abc_keccak_p1600_c_permute(sponge->lanes);
        input += count;
        length -= count;
    }
    while (length >= ABC_KECCAK_C_RATE) {
        for (unsigned lane = 0; lane < ABC_KECCAK_C_RATE / 8; ++lane) {
            sponge->lanes[lane] ^= load_lane(input + 8 * lane);
        }
        abc_keccak_p1600_c_permute(sponge->lanes);
        input += ABC_KECCAK_C_RATE;
        length -= ABC_KECCAK_C_RATE;
    }
    for (size_t i = 0; i < length; ++i) {
        xor_byte(sponge->lanes, i, input[i]);
    }
    sponge->offset = length;
    return ABC_KECCAK_C_OK;
}

int abc_keccak_c_finish(const abc_keccak_c_sponge *sponge, abc_keccak_c_domain domain,
                        abc_keccak_c_reader *reader) {
    if (sponge == NULL || reader == NULL || (domain != ABC_KECCAK_C_SHA3 && domain != ABC_KECCAK_C_SHAKE)) {
        return ABC_KECCAK_C_INVALID_ARGUMENT;
    }
    abc_keccak_c_reader snapshot = {0};
    memcpy(snapshot.lanes, sponge->lanes, sizeof(snapshot.lanes));
    xor_byte(snapshot.lanes, sponge->offset, (uint8_t)domain);
    xor_byte(snapshot.lanes, ABC_KECCAK_C_RATE - 1, 0x80);
    abc_keccak_p1600_c_permute(snapshot.lanes);
    *reader = snapshot;
    return ABC_KECCAK_C_OK;
}

int abc_keccak_c_read(abc_keccak_c_reader *reader, uint8_t *output, size_t length) {
    if (reader == NULL || (output == NULL && length != 0)) {
        return ABC_KECCAK_C_INVALID_ARGUMENT;
    }
    while (length != 0) {
        if (reader->offset == ABC_KECCAK_C_RATE) {
            abc_keccak_p1600_c_permute(reader->lanes);
            reader->offset = 0;
        }
        size_t space = ABC_KECCAK_C_RATE - reader->offset;
        size_t count = length < space ? length : space;
        size_t i = 0;
        while (i < count && (reader->offset + i) % 8 != 0) {
            output[i] = read_byte(reader->lanes, reader->offset + i);
            ++i;
        }
        for (; count - i >= 8; i += 8) {
            store_lane(output + i, reader->lanes[(reader->offset + i) / 8]);
        }
        for (; i < count; ++i) {
            output[i] = read_byte(reader->lanes, reader->offset + i);
        }
        reader->offset += count;
        output += count;
        length -= count;
    }
    return ABC_KECCAK_C_OK;
}
