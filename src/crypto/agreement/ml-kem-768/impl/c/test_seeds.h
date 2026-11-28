#ifndef ABC_ML_KEM_768_TEST_SEEDS_H
#define ABC_ML_KEM_768_TEST_SEEDS_H

#include "ml_kem_768.h"

#define ABC_ML_KEM_768_SEED_BYTES 64
#define ABC_ML_KEM_768_MESSAGE_BYTES 32

abc_ml_kem_768_status abc_ml_kem_768_keygen_fixture(
    const uint8_t seed[ABC_ML_KEM_768_SEED_BYTES], abc_ml_kem_768_keypair *result);
abc_ml_kem_768_status abc_ml_kem_768_encapsulate_fixture(
    const uint8_t *ek, size_t ek_len, const uint8_t message[ABC_ML_KEM_768_MESSAGE_BYTES],
    abc_ml_kem_768_encapsulation *result);

#endif
