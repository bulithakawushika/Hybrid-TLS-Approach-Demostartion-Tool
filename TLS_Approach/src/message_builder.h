#ifndef MESSAGE_BUILDER_H
#define MESSAGE_BUILDER_H

#include "config.h"
#include "classical_crypto.h"
#include "pqc_crypto.h"
#include <stddef.h>
#include <stdint.h>
#include <time.h>

// Protocol message types
typedef enum {
    MESSAGE_MA = 1,
    MESSAGE_MB = 2
} message_type_t;

// Message data structures
typedef struct {
    message_type_t type;
    unsigned char* data;
    size_t data_len;
    uint64_t timestamp;
} protocol_message_t;

// Alice's ma message components
typedef struct {
    unsigned char* classical_pka;     // Classical public key
    size_t classical_pka_len;
    unsigned char* pqc_pka;          // PQC public key 
    size_t pqc_pka_len;
    unsigned char* uuid;              // QKD UUID
    size_t uuid_len;
    uint64_t timestamp;               // Message timestamp
} ma_components_t;

// Bob's mb message components
typedef struct {
    unsigned char* classical_pkb;     // Bob's classical public key
    size_t classical_pkb_len;
    unsigned char* ciphertext;        // PQC encapsulation ciphertext
    size_t ciphertext_len;
    unsigned char* h_b;               // Hash of ma message
    size_t h_b_len;
} mb_components_t;

// Function prototypes for message construction
int build_ma_message(const ma_components_t* components, 
                     unsigned char** message, 
                     size_t* message_len);

int build_mb_message(const mb_components_t* components,
                     unsigned char** message,
                     size_t* message_len);

int parse_ma_message(const unsigned char* message,
                     size_t message_len,
                     ma_components_t* components);

int parse_mb_message(const unsigned char* message,
                     size_t message_len,
                     mb_components_t* components);

// Hash message using SHA-512
int hash_message_sha512(const unsigned char* message,
                       size_t message_len,
                       unsigned char* hash);

// Timestamp operations
uint64_t get_current_timestamp(void);
int validate_timestamp(uint64_t timestamp, uint64_t max_skew_seconds);

// Signature operations for protocol messages
int sign_message_classical(const unsigned char* message,
                          size_t message_len,
                          classical_sig_t sig_type,
                          const classical_keypair_t* keypair,
                          unsigned char* signature,
                          size_t* signature_len);

int sign_message_pqc(const unsigned char* message,
                    size_t message_len,
                    pqc_sig_t sig_type,
                    const pqc_sig_keypair_t* keypair,
                    unsigned char* signature,
                    size_t* signature_len);

int verify_message_classical(const unsigned char* message,
                            size_t message_len,
                            classical_sig_t sig_type,
                            const unsigned char* public_key,
                            size_t public_key_len,
                            const unsigned char* signature,
                            size_t signature_len);

int verify_message_pqc(const unsigned char* message,
                      size_t message_len,
                      pqc_sig_t sig_type,
                      const unsigned char* public_key,
                      size_t public_key_len,
                      const unsigned char* signature,
                      size_t signature_len);

// Protocol-specific key operations
int derive_string_v(const unsigned char* classical_pka,
                   size_t classical_pka_len,
                   const unsigned char* classical_pkb,
                   size_t classical_pkb_len,
                   const unsigned char* ciphertext,
                   size_t ciphertext_len,
                   const unsigned char* uuid,
                   size_t uuid_len,
                   unsigned char** string_v,
                   size_t* string_v_len);

int compute_final_key(const unsigned char* k_classical,
                     size_t k_classical_len,
                     const unsigned char* k_pqc,
                     size_t k_pqc_len,
                     const unsigned char* k_qkd,
                     size_t k_qkd_len,
                     const unsigned char* string_v,
                     size_t string_v_len,
                     unsigned char* k_final,
                     size_t* k_final_len);

// Utility functions
void free_message_components_ma(ma_components_t* components);
void free_message_components_mb(mb_components_t* components);
void free_protocol_message(protocol_message_t* message);
void print_message_hex(const unsigned char* message, size_t len, const char* label);

// Protocol constants
#define MAX_TIMESTAMP_SKEW 300  // 5 minutes in seconds
#define PROTOCOL_VERSION 1
#define SHA512_DIGEST_LENGTH 64

#endif // MESSAGE_BUILDER_H