#ifndef PQC_CRYPTO_H
#define PQC_CRYPTO_H

#include "config.h"
#include <stddef.h>

// PQC key structures
typedef struct {
    unsigned char* public_key;
    size_t public_key_len;
    unsigned char* secret_key;
    size_t secret_key_len;
} pqc_kem_keypair_t;

typedef struct {
    unsigned char* public_key;
    size_t public_key_len;
    unsigned char* secret_key;
    size_t secret_key_len;
} pqc_sig_keypair_t;

// PQC KEM function prototypes
int pqc_kem_keygen(pqc_kem_t algorithm, pqc_kem_keypair_t* keypair);
int pqc_kem_encapsulate(pqc_kem_t algorithm, 
                        const unsigned char* public_key,
                        size_t public_key_len,
                        unsigned char* shared_secret,
                        size_t* shared_secret_len,
                        unsigned char* ciphertext,
                        size_t* ciphertext_len);
int pqc_kem_decapsulate(pqc_kem_t algorithm,
                        const unsigned char* secret_key,
                        size_t secret_key_len,
                        const unsigned char* ciphertext,
                        size_t ciphertext_len,
                        unsigned char* shared_secret,
                        size_t* shared_secret_len);

// PQC signature function prototypes
int pqc_sig_keygen(pqc_sig_t algorithm, pqc_sig_keypair_t* keypair);
int pqc_sign(pqc_sig_t algorithm,
             const unsigned char* secret_key,
             size_t secret_key_len,
             const unsigned char* message,
             size_t message_len,
             unsigned char* signature,
             size_t* signature_len);
int pqc_verify(pqc_sig_t algorithm,
               const unsigned char* public_key,
               size_t public_key_len,
               const unsigned char* message,
               size_t message_len,
               const unsigned char* signature,
               size_t signature_len);

// Utility functions
void free_pqc_kem_keypair(pqc_kem_keypair_t* keypair);
void free_pqc_sig_keypair(pqc_sig_keypair_t* keypair);
const char* get_pqc_kem_name(pqc_kem_t algorithm);
const char* get_pqc_sig_name(pqc_sig_t algorithm);
int get_pqc_kem_sizes(pqc_kem_t algorithm, size_t* pk_len, size_t* sk_len, size_t* ct_len, size_t* ss_len);
int get_pqc_sig_sizes(pqc_sig_t algorithm, size_t* pk_len, size_t* sk_len, size_t* sig_len);

// LibOQS integration functions
int initialize_liboqs(void);
void cleanup_liboqs(void);
int is_kem_supported(pqc_kem_t algorithm);
int is_sig_supported(pqc_sig_t algorithm);

#endif // PQC_CRYPTO_H