#ifndef HYBRID_TLS_PROTOCOL_H
#define HYBRID_TLS_PROTOCOL_H

#include "config.h"
#include "classical_crypto.h"
#include "pqc_crypto.h"
#include "qkd_interface.h"
#include "mac_ops.h"
#include <stdint.h>
#include <time.h>

// Protocol constants (remove MAX_MESSAGE_SIZE to avoid conflict)
#define TIMESTAMP_SIZE 8
#define HASH_SIZE SHA256_DIGEST_LENGTH
#define HMAC_SIZE 32
#define FINAL_KEY_SIZE 32

// Protocol state
typedef enum {
    STATE_INIT = 0,
    STATE_ALICE_SENT_MA,
    STATE_BOB_RECEIVED_MA,
    STATE_BOB_SENT_MB,
    STATE_ALICE_RECEIVED_MB,
    STATE_KEYS_DERIVED,
    STATE_HANDSHAKE_COMPLETE,
    STATE_ERROR
} protocol_state_t;

// Message structures
typedef struct {
    unsigned char* classical_pka;
    size_t classical_pka_len;
    unsigned char* pqc_pka;
    size_t pqc_pka_len;
    unsigned char uuid[UUID_LENGTH];
    uint64_t timestamp;
    unsigned char hash[HASH_SIZE];
} ma_message_t;

typedef struct {
    unsigned char* classical_pkb;
    size_t classical_pkb_len;
    unsigned char* pqc_ciphertext;
    size_t pqc_ciphertext_len;
    unsigned char hash_b[HASH_SIZE];
} mb_message_t;

// Protocol session data
typedef struct {
    // Configuration
    test_config_t config;
    
    // State
    protocol_state_t state;
    
    // Keys and cryptographic materials
    classical_keypair_t alice_classical_keypair;
    classical_keypair_t bob_classical_keypair;
    classical_keypair_t alice_sig_keypair;
    classical_keypair_t bob_sig_keypair;
    
    pqc_kem_keypair_t alice_pqc_keypair;
    pqc_sig_keypair_t alice_pqc_sig_keypair;
    pqc_sig_keypair_t bob_pqc_sig_keypair;
    
    // QKD derived components
    unsigned char k_qkd[32];
    unsigned char k_auth[32];
    unsigned char na[12];
    unsigned char nb[12];
    
    // Protocol messages
    ma_message_t ma_msg;
    mb_message_t mb_msg;
    
    // Signatures and MACs
    unsigned char ma_classical_sig[MAX_SIGNATURE_SIZE];
    size_t ma_classical_sig_len;
    unsigned char ma_pqc_sig[MAX_SIGNATURE_SIZE * 4]; // PQC sigs can be large
    size_t ma_pqc_sig_len;
    unsigned char ma_mac[POLY1305_TAG_SIZE];
    
    unsigned char mb_classical_sig[MAX_SIGNATURE_SIZE];
    size_t mb_classical_sig_len;
    unsigned char mb_pqc_sig[MAX_SIGNATURE_SIZE * 4];
    size_t mb_pqc_sig_len;
    unsigned char mb_mac[POLY1305_TAG_SIZE];
    
    // Final derived keys
    unsigned char k_classical[64];
    size_t k_classical_len;
    unsigned char k_pqc[64];
    size_t k_pqc_len;
    unsigned char k_final[FINAL_KEY_SIZE];
    
    // Performance metrics
    double alice_setup_time;
    double bob_setup_time;
    double message_creation_time;
    double signature_time;
    double verification_time;
    double key_derivation_time;
    
} hybrid_tls_session_t;

// Function prototypes

// Session management
int initialize_hybrid_session(hybrid_tls_session_t* session, const test_config_t* config);
void cleanup_hybrid_session(hybrid_tls_session_t* session);

// Alice's operations
int alice_setup_keys(hybrid_tls_session_t* session);
int alice_create_ma_message(hybrid_tls_session_t* session);
int alice_sign_ma_message(hybrid_tls_session_t* session);
int alice_process_mb_message(hybrid_tls_session_t* session);
int alice_derive_final_key(hybrid_tls_session_t* session);

// Bob's operations  
int bob_setup_keys(hybrid_tls_session_t* session);
int bob_verify_ma_message(hybrid_tls_session_t* session);
int bob_create_mb_message(hybrid_tls_session_t* session);
int bob_sign_mb_message(hybrid_tls_session_t* session);
int bob_derive_final_key(hybrid_tls_session_t* session);

// Message operations
int serialize_ma_message(const ma_message_t* msg, unsigned char* buffer, size_t* buffer_len);
int deserialize_ma_message(const unsigned char* buffer, size_t buffer_len, ma_message_t* msg);
int serialize_mb_message(const mb_message_t* msg, unsigned char* buffer, size_t* buffer_len);
int deserialize_mb_message(const unsigned char* buffer, size_t buffer_len, mb_message_t* msg);

// Utility functions
uint64_t get_current_timestamp(void);
int verify_timestamp(uint64_t timestamp, uint64_t tolerance_seconds);
int compute_message_hash(const unsigned char* message, size_t msg_len, unsigned char* hash);
int create_v_string(const hybrid_tls_session_t* session, unsigned char* v_string, size_t* v_len);
double get_time_us_precise(void);

// Key derivation
int derive_hmac_values(const unsigned char* k_classical, size_t k_classical_len,
                      const unsigned char* k_pqc, size_t k_pqc_len,
                      const unsigned char* k_qkd, size_t k_qkd_len,
                      const unsigned char* v_string, size_t v_len,
                      unsigned char* hmac1, unsigned char* hmac2, unsigned char* hmac3);

int combine_final_key(const unsigned char* hmac1, const unsigned char* hmac2, 
                     const unsigned char* hmac3, unsigned char* k_final);

// Complete handshake protocol
int run_hybrid_handshake(const test_config_t* config, unsigned char* shared_key);

// Demo functions
int demo_tls_connection(const unsigned char* shared_key, size_t key_len);
void print_session_summary(const hybrid_tls_session_t* session);

#endif // HYBRID_TLS_PROTOCOL_H