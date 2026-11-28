#include "abc_aes256_gcm_c.h"

#include <stdbool.h>
#include <string.h>

typedef struct { uint64_t high; uint64_t low; } field;

static uint64_t load_be(const uint8_t *input) {
    uint64_t word = 0;
    for (size_t i = 0; i < 8; ++i) {
        word = (word << 8) | input[i];
    }
    return word;
}

static void store_be(uint8_t *output, uint64_t word) {
    for (size_t i = 0; i < 8; ++i) {
        output[i] = (uint8_t)(word >> (56 - 8 * i));
    }
}

static void multiply_word(uint64_t x, field *v, field *z) {
    for (unsigned i = 0; i < 64; ++i) {
        const uint64_t selected = 0 - (x >> 63);
        const uint64_t reduce = 0 - (v->low & 1);
        z->high ^= v->high & selected;
        z->low ^= v->low & selected;
        v->low = (v->low >> 1) | (v->high << 63);
        v->high = (v->high >> 1) ^ (UINT64_C(0xe100000000000000) & reduce);
        x <<= 1;
    }
}

static void ghash_block(field *sum, field h, const uint8_t *block) {
    field product = {0, 0};
    multiply_word(sum->high ^ load_be(block), &h, &product);
    multiply_word(sum->low ^ load_be(block + 8), &h, &product);
    *sum = product;
}

static void ghash_bytes(field *sum, field h, const uint8_t *data, size_t length) {
    while (length >= 16) {
        ghash_block(sum, h, data);
        data += 16;
        length -= 16;
    }
    if (length != 0) {
        uint8_t last[16] = {0};
        memcpy(last, data, length);
        ghash_block(sum, h, last);
    }
}

static void form_counter(uint8_t block[16], const uint8_t nonce[12], uint32_t counter) {
    memcpy(block, nonce, 12);
    for (size_t i = 0; i < 4; ++i) {
        block[12 + i] = (uint8_t)(counter >> (24 - 8 * i));
    }
}

static void ctr(const abc_aes256_c_context *key, const uint8_t *nonce,
                const uint8_t *input, uint8_t *output, size_t length) {
    const uintptr_t src = (uintptr_t)input;
    const uintptr_t dst = (uintptr_t)output;
    const bool backwards = dst > src && dst - src < length;
    const size_t blocks = length / 16 + (length % 16 != 0);
    for (size_t step = 0; step < blocks; ++step) {
        const size_t index = backwards ? blocks - 1 - step : step;
        const size_t offset = 16 * index;
        const size_t count = length - offset < 16 ? length - offset : 16;
        uint8_t counter[16], source[16];
        form_counter(counter, nonce, (uint32_t)index + 2);
        (void)abc_aes256_c_encrypt(key, counter, counter);
        memcpy(source, input + offset, count);
        for (size_t i = 0; i < count; ++i) {
            output[offset + i] = source[i] ^ counter[i];
        }
    }
}

static void finish_tag(const abc_aes256_c_context *key, const uint8_t *nonce, field sum, field h,
                       size_t aad_size, size_t length, uint8_t *tag) {
    uint8_t block[16];
    store_be(block, (uint64_t)aad_size * 8);
    store_be(block + 8, (uint64_t)length * 8);
    ghash_block(&sum, h, block);
    form_counter(block, nonce, 1);
    (void)abc_aes256_c_encrypt(key, block, block);
    store_be(tag, sum.high ^ load_be(block));
    store_be(tag + 8, sum.low ^ load_be(block + 8));
}

static bool invalid(const abc_aes256_gcm_c_context *context, const uint8_t *nonce,
                    const uint8_t *aad, size_t aad_size, const uint8_t *input, size_t length,
                    const uint8_t *tag, const uint8_t *out, size_t output_length) {
    return context == NULL || nonce == NULL || tag == NULL || (aad_size != 0 && aad == NULL)
        || (length != 0 && (input == NULL || out == NULL)) || length != output_length
        || length > UINT64_C(0xfffffffe) * 16 || aad_size > UINT64_MAX / 8;
}

static bool overlap(const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size) {
    if (a_size == 0 || b_size == 0) {
        return false;
    }
    const uintptr_t left = (uintptr_t)a;
    const uintptr_t right = (uintptr_t)b;
    return left <= right ? right - left < a_size : left - right < b_size;
}

int abc_aes256_gcm_c_init(abc_aes256_gcm_c_context *context, const uint8_t *key, size_t key_size) {
    if (context == NULL) {
        return ABC_AES256_C_INVALID_ARGUMENT;
    }
    const int status = abc_aes256_c_init(&context->cipher, key, key_size);
    if (status != ABC_AES256_C_OK) {
        return status;
    }
    uint8_t h[16] = {0};
    (void)abc_aes256_c_encrypt(&context->cipher, h, h);
    context->hash_high = load_be(h);
    context->hash_low = load_be(h + 8);
    return ABC_AES256_C_OK;
}

void abc_aes256_gcm_c_clear(abc_aes256_gcm_c_context *context) {
    if (context != NULL) {
        volatile unsigned char *bytes = (volatile unsigned char *)context;
        for (size_t i = 0; i < sizeof *context; ++i) {
            bytes[i] = 0;
        }
    }
}

int abc_aes256_gcm_c_seal(const abc_aes256_gcm_c_context *context,
    const uint8_t *nonce, const uint8_t *aad, size_t aad_size, const uint8_t *plaintext,
    size_t length, uint8_t *ciphertext, size_t output_length, uint8_t *tag) {
    if (invalid(context, nonce, aad, aad_size, plaintext, length, tag, ciphertext, output_length)
        || overlap(ciphertext, length, tag, 16)) {
        return ABC_AES256_C_INVALID_ARGUMENT;
    }
    const field h = {context->hash_high, context->hash_low};
    field sum = {0, 0};
    uint8_t nonce_copy[12];
    memcpy(nonce_copy, nonce, sizeof nonce_copy);
    ghash_bytes(&sum, h, aad, aad_size);
    ctr(&context->cipher, nonce_copy, plaintext, ciphertext, length);
    ghash_bytes(&sum, h, ciphertext, length);
    finish_tag(&context->cipher, nonce_copy, sum, h, aad_size, length, tag);
    return ABC_AES256_C_OK;
}

int abc_aes256_gcm_c_open(const abc_aes256_gcm_c_context *context,
    const uint8_t *nonce, const uint8_t *aad, size_t aad_size, const uint8_t *ciphertext,
    size_t length, const uint8_t *tag, uint8_t *plaintext, size_t output_length) {
    if (invalid(context, nonce, aad, aad_size, ciphertext, length, tag, plaintext, output_length)) {
        return ABC_AES256_C_INVALID_ARGUMENT;
    }
    const field h = {context->hash_high, context->hash_low};
    field sum = {0, 0};
    uint8_t expected[16], nonce_copy[12];
    memcpy(nonce_copy, nonce, sizeof nonce_copy);
    ghash_bytes(&sum, h, aad, aad_size);
    ghash_bytes(&sum, h, ciphertext, length);
    finish_tag(&context->cipher, nonce_copy, sum, h, aad_size, length, expected);
    uint8_t differences = 0;
    for (size_t i = 0; i < sizeof expected; ++i) {
        differences |= expected[i] ^ tag[i];
    }
    if (differences != 0) {
        return ABC_AES256_GCM_C_AUTHENTICATION_FAILED;
    }
    ctr(&context->cipher, nonce_copy, ciphertext, plaintext, length);
    return ABC_AES256_C_OK;
}
