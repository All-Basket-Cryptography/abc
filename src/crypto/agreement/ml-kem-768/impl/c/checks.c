#include "ml_kem_768.h"
#ifdef ABC_ML_KEM_768_TESTING
#include "test_seeds.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

#ifdef ABC_ML_KEM_768_TESTING
static uint8_t nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return (uint8_t)(value - '0');
    }
    require(value >= 'a' && value <= 'f', "hex fixture character");
    return (uint8_t)(value - 'a' + 10);
}

static void decode(const char *hex, uint8_t *output, size_t length)
{
    require(hex != NULL && strlen(hex) == 2 * length, "hex fixture length");
    for (size_t i = 0; i < length; ++i) {
        output[i] = (uint8_t)(nibble(hex[2 * i]) * 16 + nibble(hex[2 * i + 1]));
    }
}
#endif

static void print_bytes(const uint8_t *bytes, size_t length)
{
    putchar(' ');
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", (unsigned)bytes[i]);
    }
}

static void unchanged(const void *data, size_t length)
{
    const uint8_t *bytes = data;
    for (size_t i = 0; i < length; ++i) {
        require(bytes[i] == 0xa5, "rejected operation changed output");
    }
}

#ifdef ABC_ML_KEM_768_TESTING
static void run_encap(const char *encoded_ek, const char *encoded_message)
{
    uint8_t ek[ABC_ML_KEM_768_EK_BYTES], message[ABC_ML_KEM_768_MESSAGE_BYTES];
    abc_ml_kem_768_encapsulation result;
    decode(encoded_ek, ek, sizeof(ek));
    decode(encoded_message, message, sizeof(message));
    memset(&result, 0xa5, sizeof(result));
    const abc_ml_kem_768_status status = abc_ml_kem_768_encapsulate_fixture(ek, sizeof(ek), message, &result);
    printf("%d", status);
    if (status == ABC_ML_KEM_768_OK) {
        print_bytes(result.ciphertext, sizeof(result.ciphertext));
        print_bytes(result.shared, sizeof(result.shared));
    } else {
        unchanged(&result, sizeof(result));
    }
}

static void run_decap(const char *encoded_dk, const char *encoded_ct)
{
    uint8_t dk[ABC_ML_KEM_768_DK_BYTES], ct[ABC_ML_KEM_768_CT_BYTES], shared[ABC_ML_KEM_768_SHARED_BYTES];
    decode(encoded_dk, dk, sizeof(dk));
    decode(encoded_ct, ct, sizeof(ct));
    memset(shared, 0xa5, sizeof(shared));
    const abc_ml_kem_768_status status = abc_ml_kem_768_decapsulate(dk, sizeof(dk), ct, sizeof(ct),
        shared, sizeof(shared));
    printf("%d", status);
    if (status == ABC_ML_KEM_768_OK) {
        print_bytes(shared, sizeof(shared));
    } else {
        unchanged(shared, sizeof(shared));
    }
}

static void run_keygen(const char *encoded_seed)
{
    uint8_t seed[ABC_ML_KEM_768_SEED_BYTES];
    abc_ml_kem_768_keypair result;
    decode(encoded_seed, seed, sizeof(seed));
    const abc_ml_kem_768_status status = abc_ml_kem_768_keygen_fixture(seed, &result);
    require(status == ABC_ML_KEM_768_OK, "deterministic key generation");
    printf("%d", status);
    print_bytes(result.ek, sizeof(result.ek));
    print_bytes(result.dk, sizeof(result.dk));
}
#endif

static void run_public_api(void)
{
    abc_ml_kem_768_keypair keypair;
    require(abc_ml_kem_768_keygen(&keypair) == ABC_ML_KEM_768_OK, "randomized key generation");
    require(abc_ml_kem_768_keygen(NULL) == ABC_ML_KEM_768_INVALID_ARGUMENT, "null destination");

    abc_ml_kem_768_encapsulation encapsulation;
    memset(&encapsulation, 0xa5, sizeof(encapsulation));
    require(abc_ml_kem_768_encapsulate(keypair.ek, sizeof(keypair.ek) - 1, &encapsulation) ==
        ABC_ML_KEM_768_INVALID_ARGUMENT, "short encapsulation key");
    unchanged(&encapsulation, sizeof(encapsulation));
    require(abc_ml_kem_768_encapsulate(keypair.ek, sizeof(keypair.ek), &encapsulation) ==
        ABC_ML_KEM_768_OK, "randomized encapsulation");

    uint8_t shared[ABC_ML_KEM_768_SHARED_BYTES];
    memset(shared, 0xa5, sizeof(shared));
    require(abc_ml_kem_768_decapsulate(keypair.dk, sizeof(keypair.dk), encapsulation.ciphertext,
        sizeof(encapsulation.ciphertext) - 1, shared, sizeof(shared)) ==
        ABC_ML_KEM_768_INVALID_ARGUMENT, "short ciphertext");
    unchanged(shared, sizeof(shared));
    require(abc_ml_kem_768_decapsulate(keypair.dk, sizeof(keypair.dk), encapsulation.ciphertext,
        sizeof(encapsulation.ciphertext), shared, sizeof(shared)) == ABC_ML_KEM_768_OK, "decapsulation");
    require(memcmp(shared, encapsulation.shared, sizeof(shared)) == 0, "decapsulation result");
    printf("0");
    print_bytes(keypair.dk, sizeof(keypair.dk));
    print_bytes(encapsulation.ciphertext, sizeof(encapsulation.ciphertext));
    print_bytes(shared, sizeof(shared));
}

int main(void)
{
    char line[8192];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *state = NULL;
        const char *verb = strtok_s(line, " \r\n", &state);
        require(verb != NULL, "missing fixture verb");
        if (strcmp(verb, "random") == 0) {
            run_public_api();
#ifdef ABC_ML_KEM_768_TESTING
        } else {
            const char *first = strtok_s(NULL, " \r\n", &state);
            const char *second = strtok_s(NULL, " \r\n", &state);
            if (strcmp(verb, "keygen") == 0) {
                run_keygen(first);
            } else if (strcmp(verb, "encap") == 0) {
                run_encap(first, second);
            } else if (strcmp(verb, "decap") == 0) {
                run_decap(first, second);
            } else {
                require(0, "unknown fixture verb");
            }
#endif
        }
        putchar('\n');
    }
    require(!ferror(stdin), "fixture input error");
    return 0;
}
