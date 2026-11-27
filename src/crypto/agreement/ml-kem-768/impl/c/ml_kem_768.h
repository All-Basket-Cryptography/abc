#ifndef ABC_ML_KEM_768_H
#define ABC_ML_KEM_768_H

#include <stddef.h>
#include <stdint.h>

#define ABC_ML_KEM_768_EK_BYTES 1184
#define ABC_ML_KEM_768_DK_BYTES 2400
#define ABC_ML_KEM_768_CT_BYTES 1088
#define ABC_ML_KEM_768_SHARED_BYTES 32

typedef enum {
    ABC_ML_KEM_768_OK = 0,
    ABC_ML_KEM_768_INVALID_ARGUMENT,
    ABC_ML_KEM_768_PROVIDER_ERROR
} abc_ml_kem_768_status;

typedef struct {
    uint8_t ek[ABC_ML_KEM_768_EK_BYTES];
    uint8_t dk[ABC_ML_KEM_768_DK_BYTES];
} abc_ml_kem_768_keypair;

typedef struct {
    uint8_t ciphertext[ABC_ML_KEM_768_CT_BYTES];
    uint8_t shared[ABC_ML_KEM_768_SHARED_BYTES];
} abc_ml_kem_768_encapsulation;

/* Inputs are readable and outputs writable at their declared sizes.
   Operation errors preserve the destination. */
abc_ml_kem_768_status abc_ml_kem_768_keygen(abc_ml_kem_768_keypair *result);
abc_ml_kem_768_status abc_ml_kem_768_encapsulate(
    const uint8_t *ek, size_t ek_len, abc_ml_kem_768_encapsulation *result);

/* A correctly sized rejected ciphertext yields the implicit-rejection
   secret. Wrong lengths and rejected keys produce operation errors. */
abc_ml_kem_768_status abc_ml_kem_768_decapsulate(
    const uint8_t *dk, size_t dk_len, const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *result, size_t result_len);

#endif
