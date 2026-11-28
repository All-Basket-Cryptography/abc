#include "abc_scrypt_c.h"
#include "abc_pbkdf2_sha256_c.h"

#include <stdbool.h>
#include <string.h>

_Static_assert(sizeof(size_t) <= sizeof(uint64_t), "scrypt requires size_t of at most 64 bits");

typedef struct {
    size_t lane;
    size_t lanes;
    size_t table;
    size_t total;
} layout;

static int plan(size_t n, uint32_t r, uint32_t p, layout *result) {
    if (n <= 1 || (n & (n - 1)) != 0 || r == 0 || p == 0
        || (uint64_t)r * p >= (UINT64_C(1) << 30)
        || (r < 4 && (uint64_t)n >= (UINT64_C(1) << (16 * r)))) {
        return ABC_SCRYPT_C_BAD_PARAMETERS;
    }
    const uint64_t lane = UINT64_C(128) * r;
    const size_t limit = (size_t)(PTRDIFF_MAX / lane);
    if (p >= limit || n >= limit - p) {
        return ABC_SCRYPT_C_LENGTH_LIMIT;
    }
    result->lane = (size_t)lane;
    result->lanes = result->lane * p;
    result->table = result->lane * n;
    result->total = result->lanes + result->table + result->lane;
    return ABC_SCRYPT_C_OK;
}

int abc_scrypt_c_workspace_bytes(size_t n, uint32_t r, uint32_t p, size_t *bytes) {
    if (bytes == NULL) {
        return ABC_SCRYPT_C_INVALID_BUFFER;
    }
    layout work;
    const int status = plan(n, r, p, &work);
    if (status == ABC_SCRYPT_C_OK) {
        *bytes = work.total;
    }
    return status;
}

static uint32_t load_word(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8)
        | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void store_word(uint8_t *bytes, uint32_t word) {
    for (unsigned i = 0; i < 4; ++i) {
        bytes[i] = (uint8_t)(word >> (8 * i));
    }
}

static inline uint32_t rotate(uint32_t word, unsigned bits) {
    return (word << bits) | (word >> (32 - bits));
}

static inline void quarter(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *b ^= rotate(*a + *d, 7);
    *c ^= rotate(*b + *a, 9);
    *d ^= rotate(*c + *b, 13);
    *a ^= rotate(*d + *c, 18);
}

static void salsa8(uint32_t block[16]) {
    uint32_t x[16];
    memcpy(x, block, sizeof x);
    for (unsigned round = 0; round < 4; ++round) {
        quarter(x + 0,  x + 4,  x + 8,  x + 12);
        quarter(x + 5,  x + 9,  x + 13, x + 1);
        quarter(x + 10, x + 14, x + 2,  x + 6);
        quarter(x + 15, x + 3,  x + 7,  x + 11);
        quarter(x + 0,  x + 1,  x + 2,  x + 3);
        quarter(x + 5,  x + 6,  x + 7,  x + 4);
        quarter(x + 10, x + 11, x + 8,  x + 9);
        quarter(x + 15, x + 12, x + 13, x + 14);
    }
    for (size_t i = 0; i < 16; ++i) {
        block[i] += x[i];
    }
}

static void block_mix(const uint8_t *lane, size_t size, uint8_t *temporary) {
    uint32_t chain[16];
    for (size_t i = 0; i < 16; ++i) {
        chain[i] = load_word(lane + size - 64 + 4 * i);
    }
    for (size_t block = 0; block < size / 64; ++block) {
        const uint8_t *input = lane + 64 * block;
        uint8_t *output = temporary + (block / 2) * 64 + (block % 2) * (size / 2);
        for (size_t i = 0; i < 16; ++i) {
            chain[i] ^= load_word(input + 4 * i);
        }
        salsa8(chain);
        for (size_t i = 0; i < 16; ++i) {
            store_word(output + 4 * i, chain[i]);
        }
    }
}

static void romix(uint8_t *lane, size_t size, uint8_t *table, uint8_t *temporary, size_t n) {
    for (size_t row = 0; row < n; ++row) {
        memcpy(table + row * size, lane, size);
        block_mix(lane, size, temporary);
        uint8_t *previous = lane;
        lane = temporary;
        temporary = previous;
    }
    for (size_t visit = 0; visit < n; ++visit) {
        const uint8_t *last = lane + size - 64;
        const uint64_t integer = load_word(last) | ((uint64_t)load_word(last + 4) << 32);
        const uint8_t *entry = table + (size_t)(integer & (n - 1)) * size;
        for (size_t i = 0; i < size; ++i) {
            lane[i] ^= entry[i];
        }
        block_mix(lane, size, temporary);
        uint8_t *previous = lane;
        lane = temporary;
        temporary = previous;
    }
    /* The two passes perform 2*N swaps, returning the result to the caller's lane. */
}

static bool overlaps(const uint8_t *left, size_t left_length, const uint8_t *right, size_t right_length) {
    const uintptr_t a = (uintptr_t)left, b = (uintptr_t)right;
    return left_length != 0 && right_length != 0
        && (a <= b ? b - a < left_length : a - b < right_length);
}

static void wipe(uint8_t *workspace, size_t length) {
    volatile uint8_t *bytes = workspace;
    for (size_t i = 0; i < length; ++i) {
        bytes[i] = 0;
    }
}

int abc_scrypt_c_derive(const uint8_t *password, size_t password_length,
    const uint8_t *salt, size_t salt_length, size_t n, uint32_t r, uint32_t p,
    uint8_t *workspace, size_t workspace_length, uint8_t *output, size_t output_length) {
    layout work;
    int status = plan(n, r, p, &work);
    if (status != ABC_SCRYPT_C_OK) {
        return status;
    }
    if (output_length == 0 || output_length > ABC_PBKDF2_SHA256_C_MAX_OUTPUT_BYTES
        || password_length > ABC_HMAC_SHA256_C_MAX_KEY_BYTES || salt_length > ABC_PBKDF2_SHA256_C_MAX_SALT_BYTES) {
        return ABC_SCRYPT_C_LENGTH_LIMIT;
    }
    if (workspace_length < work.total) {
        return ABC_SCRYPT_C_WORKSPACE_TOO_SMALL;
    }
    if (workspace == NULL || output == NULL || (password == NULL && password_length != 0)
        || (salt == NULL && salt_length != 0) || overlaps(workspace, work.total, password, password_length)
        || overlaps(workspace, work.total, salt, salt_length) || overlaps(workspace, work.total, output, output_length)) {
        return ABC_SCRYPT_C_INVALID_BUFFER;
    }

    status = abc_pbkdf2_sha256_c_derive(password, password_length, salt, salt_length, 1, workspace, work.lanes);
    if (status == ABC_PBKDF2_SHA256_C_OK) {
        uint8_t *table = workspace + work.lanes;
        uint8_t *temporary = table + work.table;
        for (size_t lane = 0; lane < p; ++lane) {
            romix(workspace + lane * work.lane, work.lane, table, temporary, n);
        }
        status = abc_pbkdf2_sha256_c_derive(password, password_length, workspace, work.lanes, 1, output, output_length);
    }
    wipe(workspace, work.total);
    return status == ABC_PBKDF2_SHA256_C_OK ? ABC_SCRYPT_C_OK : ABC_SCRYPT_C_BACKEND_ERROR;
}
