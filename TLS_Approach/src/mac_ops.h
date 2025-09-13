#ifndef MAC_OPS_H
#define MAC_OPS_H

#include <stddef.h>
#include <stdint.h>

// Poly1305 constants
#define POLY1305_KEY_SIZE 32
#define POLY1305_TAG_SIZE 16
#define POLY1305_NONCE_SIZE 12

// MAC operation result codes
#define MAC_SUCCESS 0
#define MAC_ERROR -1
#define MAC_VERIFY_FAILED -2

// Function prototypes for MAC operations
int poly1305_generate_mac(const unsigned char* key,
                         const unsigned char* nonce,
                         const unsigned char* message,
                         size_t message_len,
                         unsigned char* mac);

int poly1305_verify_mac(const unsigned char* key,
                       const unsigned char* nonce,
                       const unsigned char* message,
                       size_t message_len,
                       const unsigned char* expected_mac);

// HMAC-SHA256 fallback (used when Poly1305 not available)
int hmac_sha256_generate_mac(const unsigned char* key,
                            const unsigned char* nonce,
                            const unsigned char* message,
                            size_t message_len,
                            unsigned char* mac);

// Utility functions
void print_mac_hex(const unsigned char* mac);
int compare_macs(const unsigned char* mac1, const unsigned char* mac2);

// ChaCha20-Poly1305 AEAD (optional for future use)
int chacha20_poly1305_encrypt(const unsigned char* key,
                              const unsigned char* nonce,
                              const unsigned char* plaintext,
                              size_t plaintext_len,
                              const unsigned char* additional_data,
                              size_t ad_len,
                              unsigned char* ciphertext,
                              unsigned char* tag);

int chacha20_poly1305_decrypt(const unsigned char* key,
                              const unsigned char* nonce,
                              const unsigned char* ciphertext,
                              size_t ciphertext_len,
                              const unsigned char* additional_data,
                              size_t ad_len,
                              const unsigned char* tag,
                              unsigned char* plaintext);

#endif // MAC_OPS_H