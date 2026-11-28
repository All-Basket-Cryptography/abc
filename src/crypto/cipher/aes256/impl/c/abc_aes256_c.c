#include "abc_aes256_c.h"

#if defined(__x86_64__) || defined(_M_X64)
#define ABC_X64 1
#include <string.h>
#include <wmmintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#if defined(__clang__) || defined(__GNUC__)
#define ABC_AES __attribute__((target("aes,sse2")))
#else
#define ABC_AES
#endif

static ABC_AES __m128i load(const uint8_t *source) {
    __m128i word;
    memcpy(&word, source, sizeof word);
    return word;
}

static ABC_AES void store(uint8_t *destination, __m128i word) {
    memcpy(destination, &word, sizeof word);
}

static ABC_AES __m128i prefix_xor(__m128i words) {
    __m128i shift = _mm_slli_si128(words, 4);
    words = _mm_xor_si128(words, shift);
    shift = _mm_slli_si128(shift, 4);
    words = _mm_xor_si128(words, shift);
    return _mm_xor_si128(words, _mm_slli_si128(shift, 4));
}

static ABC_AES __m128i expand_even(__m128i left, __m128i assist) {
    return _mm_xor_si128(prefix_xor(left), _mm_shuffle_epi32(assist, 0xff));
}

static ABC_AES __m128i expand_odd(__m128i right, __m128i left) {
    const __m128i assist = _mm_aeskeygenassist_si128(left, 0);
    return _mm_xor_si128(prefix_xor(right), _mm_shuffle_epi32(assist, 0xaa));
}

static ABC_AES void load_schedule(abc_aes256_c_context *context, const uint8_t *key) {
    __m128i left = load(key);
    __m128i right = load(key + 16);
    store(context->encrypt_keys[0], left);
    store(context->encrypt_keys[1], right);

    /* AESKEYGENASSIST requires the round constant as an immediate. */
#define EXPAND_PAIR(round, constant) \
    left = expand_even(left, _mm_aeskeygenassist_si128(right, constant)); \
    right = expand_odd(right, left); \
    store(context->encrypt_keys[round], left); \
    store(context->encrypt_keys[(round) + 1], right)

    EXPAND_PAIR(2, 0x01);
    EXPAND_PAIR(4, 0x02);
    EXPAND_PAIR(6, 0x04);
    EXPAND_PAIR(8, 0x08);
    EXPAND_PAIR(10, 0x10);
    EXPAND_PAIR(12, 0x20);
#undef EXPAND_PAIR
    store(context->encrypt_keys[14], expand_even(left, _mm_aeskeygenassist_si128(right, 0x40)));

    store(context->decrypt_keys[0], load(context->encrypt_keys[14]));
    for (size_t round = 1; round < 14; ++round) {
        store(context->decrypt_keys[round], _mm_aesimc_si128(load(context->encrypt_keys[14 - round])));
    }
    store(context->decrypt_keys[14], load(context->encrypt_keys[0]));
}

static ABC_AES void encrypt_block(const abc_aes256_c_context *context, const uint8_t *input, uint8_t *output) {
    __m128i value = _mm_xor_si128(load(input), load(context->encrypt_keys[0]));
    for (size_t round = 1; round < 14; ++round) {
        value = _mm_aesenc_si128(value, load(context->encrypt_keys[round]));
    }
    store(output, _mm_aesenclast_si128(value, load(context->encrypt_keys[14])));
}

static ABC_AES void decrypt_block(const abc_aes256_c_context *context, const uint8_t *input, uint8_t *output) {
    __m128i value = _mm_xor_si128(load(input), load(context->decrypt_keys[0]));
    for (size_t round = 1; round < 14; ++round) {
        value = _mm_aesdec_si128(value, load(context->decrypt_keys[round]));
    }
    store(output, _mm_aesdeclast_si128(value, load(context->decrypt_keys[14])));
}
#endif

int abc_aes256_c_available(void) {
#if defined(ABC_X64) && defined(_MSC_VER)
    int cpu[4];
    __cpuid(cpu, 1);
    return ((unsigned)cpu[2] & (1U << 25)) != 0;
#elif defined(ABC_X64)
    unsigned a, b, c, d;
    return __get_cpuid(1, &a, &b, &c, &d) && (c & bit_AES) != 0;
#else
    return 0;
#endif
}

int abc_aes256_c_init(abc_aes256_c_context *context, const uint8_t *key, size_t key_size) {
    if (context == NULL || key == NULL || key_size != ABC_AES256_C_KEY_BYTES) {
        return ABC_AES256_C_INVALID_ARGUMENT;
    }
#ifdef ABC_X64
    if (abc_aes256_c_available()) {
        load_schedule(context, key);
        return ABC_AES256_C_OK;
    }
#endif
    return ABC_AES256_C_UNSUPPORTED;
}

int abc_aes256_c_encrypt(const abc_aes256_c_context *context, const uint8_t *input, uint8_t *output) {
    if (context == NULL || input == NULL || output == NULL) {
        return ABC_AES256_C_INVALID_ARGUMENT;
    }
#ifdef ABC_X64
    encrypt_block(context, input, output);
    return ABC_AES256_C_OK;
#else
    return ABC_AES256_C_UNSUPPORTED;
#endif
}

int abc_aes256_c_decrypt(const abc_aes256_c_context *context, const uint8_t *input, uint8_t *output) {
    if (context == NULL || input == NULL || output == NULL) {
        return ABC_AES256_C_INVALID_ARGUMENT;
    }
#ifdef ABC_X64
    decrypt_block(context, input, output);
    return ABC_AES256_C_OK;
#else
    return ABC_AES256_C_UNSUPPORTED;
#endif
}

void abc_aes256_c_clear(abc_aes256_c_context *context) {
    if (context != NULL) {
        volatile unsigned char *bytes = (volatile unsigned char *)context;
        for (size_t i = 0; i < sizeof *context; ++i) {
            bytes[i] = 0;
        }
    }
}
