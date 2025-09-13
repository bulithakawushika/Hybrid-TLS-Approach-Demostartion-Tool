#ifndef CLASSICAL_CRYPTO_H
#define CLASSICAL_CRYPTO_H

#include "config.h"
#include <openssl/evp.h>

// Classical key data structures
typedef struct {
    EVP_PKEY* keypair;
    unsigned char* public_key_bytes;
    size_t public_key_len;
    unsigned char* private_key_bytes;
    size_t private_key_len;
} classical_keypair_t;

// Function prototypes for classical cryptography
int classical_keygen(classical_kex_t type, classical_keypair_t* keypair);
int classical_sig_keygen(classical_sig_t type, classical_keypair_t* keypair);
int classical_key_agreement(classical_kex_t type, 
                           const classical_keypair_t* my_keypair,
                           const unsigned char* their_public_key, 
                           size_t their_public_key_len,
                           unsigned char* shared_secret, 
                           size_t* shared_secret_len);
int classical_sign(classical_sig_t type, 
                  const classical_keypair_t* keypair,
                  const unsigned char* message, 
                  size_t msg_len,
                  unsigned char* signature, 
                  size_t* sig_len);
int classical_verify(classical_sig_t type,
                    const unsigned char* public_key,
                    size_t public_key_len,
                    const unsigned char* message,
                    size_t msg_len,
                    const unsigned char* signature,
                    size_t sig_len);

// Utility functions
void free_classical_keypair(classical_keypair_t* keypair);
int export_public_key(const classical_keypair_t* keypair, 
                     unsigned char** public_key, 
                     size_t* public_key_len);
const char* get_classical_curve_name(classical_kex_t type);
int get_expected_shared_secret_len(classical_kex_t type);

#endif // CLASSICAL_CRYPTO_H