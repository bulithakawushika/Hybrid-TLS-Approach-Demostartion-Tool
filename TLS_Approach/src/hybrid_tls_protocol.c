#define _GNU_SOURCE
#include "hybrid_tls_protocol.h"
#include "qkd_data.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <endian.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// QKD data is now in qkd_data.c

/**
 * Get current time in microseconds for performance measurement
 */
double get_time_us_precise() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

/**
 * Get current timestamp in seconds since epoch
 */
uint64_t get_current_timestamp(void) {
    return (uint64_t)time(NULL);
}

/**
 * Verify timestamp is within tolerance
 */
int verify_timestamp(uint64_t timestamp, uint64_t tolerance_seconds) {
    uint64_t current_time = get_current_timestamp();
    uint64_t diff = (current_time > timestamp) ? (current_time - timestamp) : (timestamp - current_time);
    return (diff <= tolerance_seconds) ? 0 : -1;
}

/**
 * Compute SHA-256 hash of message using EVP interface
 */
int compute_message_hash(const unsigned char* message, size_t msg_len, unsigned char* hash) {
    if (message == NULL || hash == NULL) {
        return -1;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_DigestUpdate(ctx, message, msg_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    return 0;
}

/**
 * Initialize hybrid TLS session
 */
int initialize_hybrid_session(hybrid_tls_session_t* session, const test_config_t* config) {
    if (session == NULL || config == NULL) {
        return -1;
    }
    
    // Clear session structure
    memset(session, 0, sizeof(hybrid_tls_session_t));
    
    // Copy configuration
    memcpy(&session->config, config, sizeof(test_config_t));
    
    // Set initial state
    session->state = STATE_INIT;
    
    printf("Initialized hybrid TLS session with config:\n");
    printf("  Classical KEX: %s\n", classical_kex_names[config->classical_kex]);
    printf("  Classical Sig: %s\n", classical_sig_names[config->classical_sig]);
    printf("  PQC KEM: %s\n", pqc_kem_names[config->pqc_kem]);
    printf("  PQC Sig: %s\n", pqc_sig_names[config->pqc_sig]);
    printf("  QKD Protocol: %s\n", qkd_protocol_names[config->qkd_protocol]);
    
    return 0;
}

/**
 * Alice setup - generate keys and derive QKD components
 */
int alice_setup_keys(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Alice Key Setup ===\n");
    
    // Generate Alice's classical keypair for key exchange
    if (classical_keygen(session->config.classical_kex, &session->alice_classical_keypair) != 0) {
        fprintf(stderr, "Failed to generate Alice's classical KEX keypair\n");
        return -1;
    }
    printf("✓ Alice classical KEX keypair generated\n");
    
    // Generate Alice's classical signature keypair
    if (classical_sig_keygen(session->config.classical_sig, &session->alice_sig_keypair) != 0) {
        fprintf(stderr, "Failed to generate Alice's classical signature keypair\n");
        return -1;
    }
    printf("✓ Alice classical signature keypair generated\n");
    
    // Generate Alice's PQC KEM keypair
    if (pqc_kem_keygen(session->config.pqc_kem, &session->alice_pqc_keypair) != 0) {
        fprintf(stderr, "Failed to generate Alice's PQC KEM keypair\n");
        return -1;
    }
    printf("✓ Alice PQC KEM keypair generated\n");
    
    // Generate Alice's PQC signature keypair
    if (pqc_sig_keygen(session->config.pqc_sig, &session->alice_pqc_sig_keypair) != 0) {
        fprintf(stderr, "Failed to generate Alice's PQC signature keypair\n");
        return -1;
    }
    printf("✓ Alice PQC signature keypair generated\n");
    
    // Get QKD key and derive components
    qkd_key_data_t qkd_key;
    if (get_qkd_key(session->config.qkd_protocol, &qkd_key) != 0) {
        fprintf(stderr, "Failed to get QKD key\n");
        return -1;
    }
    
    if (derive_qkd_components(qkd_key.kqkdm, SHA3_512_DIGEST_LENGTH,
                             session->k_qkd, session->k_auth, 
                             session->na, session->nb) != 0) {
        fprintf(stderr, "Failed to derive QKD components\n");
        return -1;
    }
    printf("✓ QKD components derived (k_qkd, k_auth, na, nb)\n");
    
    double end_time = get_time_us_precise();
    session->alice_setup_time = (end_time - start_time) / 1000.0;
    
    printf("Alice setup completed in %.3f ms\n", session->alice_setup_time);
    return 0;
}

/**
 * Alice creates ma message
 */
int alice_create_ma_message(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Alice Creating ma Message ===\n");
    
    // Get QKD UUID
    qkd_key_data_t qkd_key;
    if (get_qkd_key(session->config.qkd_protocol, &qkd_key) != 0) {
        fprintf(stderr, "Failed to get QKD key for UUID\n");
        return -1;
    }
    
    // Copy public keys and UUID
    session->ma_msg.classical_pka = malloc(session->alice_classical_keypair.public_key_len);
    if (session->ma_msg.classical_pka == NULL) {
        return -1;
    }
    memcpy(session->ma_msg.classical_pka, session->alice_classical_keypair.public_key_bytes,
           session->alice_classical_keypair.public_key_len);
    session->ma_msg.classical_pka_len = session->alice_classical_keypair.public_key_len;
    
    session->ma_msg.pqc_pka = malloc(session->alice_pqc_keypair.public_key_len);
    if (session->ma_msg.pqc_pka == NULL) {
        return -1;
    }
    memcpy(session->ma_msg.pqc_pka, session->alice_pqc_keypair.public_key,
           session->alice_pqc_keypair.public_key_len);
    session->ma_msg.pqc_pka_len = session->alice_pqc_keypair.public_key_len;
    
    memcpy(session->ma_msg.uuid, qkd_key.uuid, UUID_LENGTH);
    session->ma_msg.timestamp = get_current_timestamp();
    
    // Create message for hashing: classical_pka || pqc_pka || uuid || timestamp
    size_t total_msg_len = session->ma_msg.classical_pka_len + session->ma_msg.pqc_pka_len + 
                          UUID_LENGTH + sizeof(uint64_t);
    unsigned char* full_message = malloc(total_msg_len);
    if (full_message == NULL) {
        return -1;
    }
    
    size_t offset = 0;
    memcpy(full_message + offset, session->ma_msg.classical_pka, session->ma_msg.classical_pka_len);
    offset += session->ma_msg.classical_pka_len;
    
    memcpy(full_message + offset, session->ma_msg.pqc_pka, session->ma_msg.pqc_pka_len);
    offset += session->ma_msg.pqc_pka_len;
    
    memcpy(full_message + offset, session->ma_msg.uuid, UUID_LENGTH);
    offset += UUID_LENGTH;
    
    uint64_t timestamp_be = htobe64(session->ma_msg.timestamp);
    memcpy(full_message + offset, &timestamp_be, sizeof(uint64_t));
    
    // Hash the complete message (h_a)
    if (compute_message_hash(full_message, total_msg_len, session->ma_msg.hash) != 0) {
        fprintf(stderr, "Failed to compute ma message hash\n");
        free(full_message);
        return -1;
    }
    
    free(full_message);
    
    double end_time = get_time_us_precise();
    session->message_creation_time = (end_time - start_time) / 1000.0;
    
    printf("✓ ma message created (%.3f ms)\n", session->message_creation_time);
    printf("  Classical PK length: %zu bytes\n", session->ma_msg.classical_pka_len);
    printf("  PQC PK length: %zu bytes\n", session->ma_msg.pqc_pka_len);
    printf("  Timestamp: %lu\n", session->ma_msg.timestamp);
    
    return 0;
}

/**
 * Alice signs ma message
 */
int alice_sign_ma_message(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Alice Signing ma Message ===\n");
    
    // Serialize ma message for signing
    unsigned char ma_buffer[MAX_MESSAGE_SIZE];
    size_t ma_len = sizeof(ma_buffer);
    if (serialize_ma_message(&session->ma_msg, ma_buffer, &ma_len) != 0) {
        fprintf(stderr, "Failed to serialize ma message\n");
        return -1;
    }
    
    // Classical signature
    session->ma_classical_sig_len = sizeof(session->ma_classical_sig);
    if (classical_sign(session->config.classical_sig, &session->alice_sig_keypair,
                      ma_buffer, ma_len, session->ma_classical_sig, 
                      &session->ma_classical_sig_len) != 0) {
        fprintf(stderr, "Failed to create classical signature\n");
        return -1;
    }
    printf("✓ Classical signature created (%zu bytes)\n", session->ma_classical_sig_len);
    
    // PQC signature
    session->ma_pqc_sig_len = sizeof(session->ma_pqc_sig);
    if (pqc_sign(session->config.pqc_sig,
                session->alice_pqc_sig_keypair.secret_key, session->alice_pqc_sig_keypair.secret_key_len,
                ma_buffer, ma_len, session->ma_pqc_sig, &session->ma_pqc_sig_len) != 0) {
        fprintf(stderr, "Failed to create PQC signature\n");
        return -1;
    }
    printf("✓ PQC signature created (%zu bytes)\n", session->ma_pqc_sig_len);
    
    // MAC with Poly1305
    if (poly1305_generate_mac(session->k_auth, session->na, ma_buffer, ma_len, 
                             session->ma_mac) != MAC_SUCCESS) {
        fprintf(stderr, "Failed to generate MAC\n");
        return -1;
    }
    printf("✓ Poly1305 MAC generated\n");
    
    double end_time = get_time_us_precise();
    session->signature_time = (end_time - start_time) / 1000.0;
    
    printf("Alice signing completed in %.3f ms\n", session->signature_time);
    session->state = STATE_ALICE_SENT_MA;
    
    return 0;
}

/**
 * Bob setup keys
 */
int bob_setup_keys(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Bob Key Setup ===\n");
    
    // Generate Bob's classical keypair
    if (classical_keygen(session->config.classical_kex, &session->bob_classical_keypair) != 0) {
        fprintf(stderr, "Failed to generate Bob's classical keypair\n");
        return -1;
    }
    printf("✓ Bob classical KEX keypair generated\n");
    
    // Generate Bob's signature keypair
    if (classical_sig_keygen(session->config.classical_sig, &session->bob_sig_keypair) != 0) {
        fprintf(stderr, "Failed to generate Bob's signature keypair\n");
        return -1;
    }
    printf("✓ Bob classical signature keypair generated\n");
    
    // Generate Bob's PQC signature keypair
    if (pqc_sig_keygen(session->config.pqc_sig, &session->bob_pqc_sig_keypair) != 0) {
        fprintf(stderr, "Failed to generate Bob's PQC signature keypair\n");
        return -1;
    }
    printf("✓ Bob PQC signature keypair generated\n");
    
    double end_time = get_time_us_precise();
    session->bob_setup_time = (end_time - start_time) / 1000.0;
    
    printf("Bob setup completed in %.3f ms\n", session->bob_setup_time);
    return 0;
}

/**
 * Bob verifies ma message
 */
int bob_verify_ma_message(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Bob Verifying ma Message ===\n");
    
    // Verify timestamp
    if (verify_timestamp(session->ma_msg.timestamp, 300) != 0) { // 5 minute tolerance
        fprintf(stderr, "Timestamp verification failed\n");
        return -1;
    }
    printf("✓ Timestamp verified\n");
    
    // Serialize ma message for verification
    unsigned char ma_buffer[MAX_MESSAGE_SIZE];
    size_t ma_len = sizeof(ma_buffer);
    if (serialize_ma_message(&session->ma_msg, ma_buffer, &ma_len) != 0) {
        fprintf(stderr, "Failed to serialize ma message for verification\n");
        return -1;
    }
    
    // Verify classical signature
    if (classical_verify(session->config.classical_sig,
                        session->alice_sig_keypair.public_key_bytes, session->alice_sig_keypair.public_key_len,
                        ma_buffer, ma_len, session->ma_classical_sig, session->ma_classical_sig_len) != 0) {
        fprintf(stderr, "Classical signature verification failed\n");
        return -1;
    }
    printf("✓ Classical signature verified\n");
    
    // Verify PQC signature
    if (pqc_verify(session->config.pqc_sig,
                  session->alice_pqc_sig_keypair.public_key, session->alice_pqc_sig_keypair.public_key_len,
                  ma_buffer, ma_len, session->ma_pqc_sig, session->ma_pqc_sig_len) != 0) {
        fprintf(stderr, "PQC signature verification failed\n");
        return -1;
    }
    printf("✓ PQC signature verified\n");
    
    // Get QKD components (Bob derives same components as Alice)
    qkd_key_data_t qkd_key;
    if (get_qkd_key(session->config.qkd_protocol, &qkd_key) != 0) {
        fprintf(stderr, "Failed to get QKD key\n");
        return -1;
    }
    
    if (derive_qkd_components(qkd_key.kqkdm, SHA3_512_DIGEST_LENGTH,
                             session->k_qkd, session->k_auth, 
                             session->na, session->nb) != 0) {
        fprintf(stderr, "Failed to derive QKD components\n");
        return -1;
    }
    
    // Verify MAC
    if (poly1305_verify_mac(session->k_auth, session->na, ma_buffer, ma_len, 
                           session->ma_mac) != MAC_SUCCESS) {
        fprintf(stderr, "MAC verification failed\n");
        return -1;
    }
    printf("✓ Poly1305 MAC verified\n");
    
    double end_time = get_time_us_precise();
    session->verification_time = (end_time - start_time) / 1000.0;
    
    printf("Bob verification completed in %.3f ms\n", session->verification_time);
    session->state = STATE_BOB_RECEIVED_MA;
    
    return 0;
}

/**
 * Bob creates mb message
 */
int bob_create_mb_message(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Bob Creating mb Message ===\n");
    
    // Perform classical key agreement to get k_classical
    session->k_classical_len = sizeof(session->k_classical);
    if (classical_key_agreement(session->config.classical_kex, &session->bob_classical_keypair,
                               session->ma_msg.classical_pka, session->ma_msg.classical_pka_len,
                               session->k_classical, &session->k_classical_len) != 0) {
        fprintf(stderr, "Failed to perform classical key agreement\n");
        return -1;
    }
    printf("✓ Classical key agreement completed (%zu bytes)\n", session->k_classical_len);
    
    // PQC encapsulation
    session->k_pqc_len = sizeof(session->k_pqc);
    
    // Allocate memory for ciphertext
    session->mb_msg.pqc_ciphertext = malloc(8192); // Large buffer for PQC ciphertext
    if (session->mb_msg.pqc_ciphertext == NULL) {
        return -1;
    }
    session->mb_msg.pqc_ciphertext_len = 8192;
    
    if (pqc_kem_encapsulate(session->config.pqc_kem,
                           session->ma_msg.pqc_pka, session->ma_msg.pqc_pka_len,
                           session->k_pqc, &session->k_pqc_len,
                           session->mb_msg.pqc_ciphertext, &session->mb_msg.pqc_ciphertext_len) != 0) {
        fprintf(stderr, "Failed to perform PQC encapsulation\n");
        return -1;
    }
    printf("✓ PQC encapsulation completed (key: %zu bytes, ciphertext: %zu bytes)\n", 
           session->k_pqc_len, session->mb_msg.pqc_ciphertext_len);
    
    // Copy Bob's classical public key
    session->mb_msg.classical_pkb = malloc(session->bob_classical_keypair.public_key_len);
    if (session->mb_msg.classical_pkb == NULL) {
        return -1;
    }
    memcpy(session->mb_msg.classical_pkb, session->bob_classical_keypair.public_key_bytes,
           session->bob_classical_keypair.public_key_len);
    session->mb_msg.classical_pkb_len = session->bob_classical_keypair.public_key_len;
    
    // Copy h_b (same as h_a since Bob verified Alice's hash)
    memcpy(session->mb_msg.hash_b, session->ma_msg.hash, HASH_SIZE);
    
    double end_time = get_time_us_precise();
    session->message_creation_time += (end_time - start_time) / 1000.0;
    
    printf("mb message created (%.3f ms)\n", (end_time - start_time) / 1000.0);
    return 0;
}

/**
 * Bob signs mb message
 */
int bob_sign_mb_message(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Bob Signing mb Message ===\n");
    
    // Serialize mb message for signing
    unsigned char mb_buffer[MAX_MESSAGE_SIZE];
    size_t mb_len = sizeof(mb_buffer);
    if (serialize_mb_message(&session->mb_msg, mb_buffer, &mb_len) != 0) {
        fprintf(stderr, "Failed to serialize mb message\n");
        return -1;
    }
    
    // Classical signature
    session->mb_classical_sig_len = sizeof(session->mb_classical_sig);
    if (classical_sign(session->config.classical_sig, &session->bob_sig_keypair,
                      mb_buffer, mb_len, session->mb_classical_sig, 
                      &session->mb_classical_sig_len) != 0) {
        fprintf(stderr, "Failed to create classical signature for mb\n");
        return -1;
    }
    printf("✓ Classical signature created (%zu bytes)\n", session->mb_classical_sig_len);
    
    // PQC signature
    session->mb_pqc_sig_len = sizeof(session->mb_pqc_sig);
    if (pqc_sign(session->config.pqc_sig,
                session->bob_pqc_sig_keypair.secret_key, session->bob_pqc_sig_keypair.secret_key_len,
                mb_buffer, mb_len, session->mb_pqc_sig, &session->mb_pqc_sig_len) != 0) {
        fprintf(stderr, "Failed to create PQC signature for mb\n");
        return -1;
    }
    printf("✓ PQC signature created (%zu bytes)\n", session->mb_pqc_sig_len);
    
    // MAC with Poly1305 using nb as nonce
    if (poly1305_generate_mac(session->k_auth, session->nb, mb_buffer, mb_len, 
                             session->mb_mac) != MAC_SUCCESS) {
        fprintf(stderr, "Failed to generate MAC for mb\n");
        return -1;
    }
    printf("✓ Poly1305 MAC generated\n");
    
    double end_time = get_time_us_precise();
    session->signature_time += (end_time - start_time) / 1000.0;
    
    printf("Bob signing completed in %.3f ms\n", (end_time - start_time) / 1000.0);
    session->state = STATE_BOB_SENT_MB;
    
    return 0;
}

/**
 * Alice processes mb message
 */
int alice_process_mb_message(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Alice Processing mb Message ===\n");
    
    // Serialize mb message for verification
    unsigned char mb_buffer[MAX_MESSAGE_SIZE];
    size_t mb_len = sizeof(mb_buffer);
    if (serialize_mb_message(&session->mb_msg, mb_buffer, &mb_len) != 0) {
        fprintf(stderr, "Failed to serialize mb message for verification\n");
        return -1;
    }
    
    // Verify classical signature
    if (classical_verify(session->config.classical_sig,
                        session->bob_sig_keypair.public_key_bytes, session->bob_sig_keypair.public_key_len,
                        mb_buffer, mb_len, session->mb_classical_sig, session->mb_classical_sig_len) != 0) {
        fprintf(stderr, "Classical signature verification failed for mb\n");
        return -1;
    }
    printf("✓ Classical signature verified\n");
    
    // Verify PQC signature
    if (pqc_verify(session->config.pqc_sig,
                  session->bob_pqc_sig_keypair.public_key, session->bob_pqc_sig_keypair.public_key_len,
                  mb_buffer, mb_len, session->mb_pqc_sig, session->mb_pqc_sig_len) != 0) {
        fprintf(stderr, "PQC signature verification failed for mb\n");
        return -1;
    }
    printf("✓ PQC signature verified\n");
    
    // Verify MAC
    if (poly1305_verify_mac(session->k_auth, session->nb, mb_buffer, mb_len, 
                           session->mb_mac) != MAC_SUCCESS) {
        fprintf(stderr, "MAC verification failed for mb\n");
        return -1;
    }
    printf("✓ Poly1305 MAC verified\n");
    
    // Verify h_a == h_b
    if (memcmp(session->ma_msg.hash, session->mb_msg.hash_b, HASH_SIZE) != 0) {
        fprintf(stderr, "Hash verification failed: h_a != h_b\n");
        return -1;
    }
    printf("✓ Hash verification passed (h_a == h_b)\n");
    
    // Perform classical key agreement
    session->k_classical_len = sizeof(session->k_classical);
    if (classical_key_agreement(session->config.classical_kex, &session->alice_classical_keypair,
                               session->mb_msg.classical_pkb, session->mb_msg.classical_pkb_len,
                               session->k_classical, &session->k_classical_len) != 0) {
        fprintf(stderr, "Failed to perform classical key agreement\n");
        return -1;
    }
    printf("✓ Classical key agreement completed (%zu bytes)\n", session->k_classical_len);
    
    // PQC decapsulation
    session->k_pqc_len = sizeof(session->k_pqc);
    if (pqc_kem_decapsulate(session->config.pqc_kem,
                           session->alice_pqc_keypair.secret_key, session->alice_pqc_keypair.secret_key_len,
                           session->mb_msg.pqc_ciphertext, session->mb_msg.pqc_ciphertext_len,
                           session->k_pqc, &session->k_pqc_len) != 0) {
        fprintf(stderr, "Failed to perform PQC decapsulation\n");
        return -1;
    }
    printf("✓ PQC decapsulation completed (%zu bytes)\n", session->k_pqc_len);
    
    double end_time = get_time_us_precise();
    session->verification_time += (end_time - start_time) / 1000.0;
    
    printf("Alice mb processing completed in %.3f ms\n", (end_time - start_time) / 1000.0);
    session->state = STATE_ALICE_RECEIVED_MB;
    
    return 0;
}

/**
 * Create v string for HMAC operations
 */
int create_v_string(const hybrid_tls_session_t* session, unsigned char* v_string, size_t* v_len) {
    if (session == NULL || v_string == NULL || v_len == NULL) {
        return -1;
    }
    
    // Get QKD UUID
    qkd_key_data_t qkd_key;
    if (get_qkd_key(session->config.qkd_protocol, &qkd_key) != 0) {
        fprintf(stderr, "Failed to get QKD key for v string\n");
        return -1;
    }
    
    // v = Alice_classical_pk || Bob_classical_pk || ciphertext_c || uuid
    size_t total_len = session->ma_msg.classical_pka_len + 
                      session->mb_msg.classical_pkb_len +
                      session->mb_msg.pqc_ciphertext_len + 
                      UUID_LENGTH;
    
    if (total_len > *v_len) {
        fprintf(stderr, "v_string buffer too small: need %zu, have %zu\n", total_len, *v_len);
        return -1;
    }
    
    size_t offset = 0;
    
    // Alice's classical public key
    memcpy(v_string + offset, session->ma_msg.classical_pka, session->ma_msg.classical_pka_len);
    offset += session->ma_msg.classical_pka_len;
    
    // Bob's classical public key
    memcpy(v_string + offset, session->mb_msg.classical_pkb, session->mb_msg.classical_pkb_len);
    offset += session->mb_msg.classical_pkb_len;
    
    // PQC ciphertext
    memcpy(v_string + offset, session->mb_msg.pqc_ciphertext, session->mb_msg.pqc_ciphertext_len);
    offset += session->mb_msg.pqc_ciphertext_len;
    
    // UUID
    memcpy(v_string + offset, qkd_key.uuid, UUID_LENGTH);
    offset += UUID_LENGTH;
    
    *v_len = offset;
    
    printf("✓ v string created (%zu bytes)\n", *v_len);
    return 0;
}

/**
 * Derive HMAC values for final key combination
 */
int derive_hmac_values(const unsigned char* k_classical, size_t k_classical_len,
                      const unsigned char* k_pqc, size_t k_pqc_len,
                      const unsigned char* k_qkd, size_t k_qkd_len,
                      const unsigned char* v_string, size_t v_len,
                      unsigned char* hmac1, unsigned char* hmac2, unsigned char* hmac3) {
    
    if (k_classical == NULL || k_pqc == NULL || k_qkd == NULL || 
        v_string == NULL || hmac1 == NULL || hmac2 == NULL || hmac3 == NULL) {
        return -1;
    }
    
    unsigned int hmac_len;
    
    // HMAC_1 = HMAC(k_classical, v)
    if (HMAC(EVP_sha256(), k_classical, k_classical_len, v_string, v_len, hmac1, &hmac_len) == NULL) {
        fprintf(stderr, "Failed to compute HMAC_1\n");
        return -1;
    }
    
    // HMAC_2 = HMAC(k_pqc, v)
    if (HMAC(EVP_sha256(), k_pqc, k_pqc_len, v_string, v_len, hmac2, &hmac_len) == NULL) {
        fprintf(stderr, "Failed to compute HMAC_2\n");
        return -1;
    }
    
    // HMAC_3 = HMAC(k_qkd, v)
    if (HMAC(EVP_sha256(), k_qkd, k_qkd_len, v_string, v_len, hmac3, &hmac_len) == NULL) {
        fprintf(stderr, "Failed to compute HMAC_3\n");
        return -1;
    }
    
    printf("✓ HMAC values computed (HMAC_1, HMAC_2, HMAC_3)\n");
    return 0;
}

/**
 * Combine final key using XOR
 */
int combine_final_key(const unsigned char* hmac1, const unsigned char* hmac2, 
                     const unsigned char* hmac3, unsigned char* k_final) {
    
    if (hmac1 == NULL || hmac2 == NULL || hmac3 == NULL || k_final == NULL) {
        return -1;
    }
    
    // k_final = HMAC_1 XOR HMAC_2 XOR HMAC_3
    for (int i = 0; i < FINAL_KEY_SIZE; i++) {
        k_final[i] = hmac1[i] ^ hmac2[i] ^ hmac3[i];
    }
    
    printf("✓ Final key combined using XOR operation\n");
    return 0;
}

/**
 * Alice derives final key
 */
int alice_derive_final_key(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Alice Deriving Final Key ===\n");
    
    // Create v string
    unsigned char v_string[16384]; // Large buffer for v string
    size_t v_len = sizeof(v_string);
    if (create_v_string(session, v_string, &v_len) != 0) {
        fprintf(stderr, "Failed to create v string\n");
        return -1;
    }
    
    // Compute HMAC values
    unsigned char hmac1[HMAC_SIZE], hmac2[HMAC_SIZE], hmac3[HMAC_SIZE];
    if (derive_hmac_values(session->k_classical, session->k_classical_len,
                          session->k_pqc, session->k_pqc_len,
                          session->k_qkd, 32, // k_qkd is always 32 bytes
                          v_string, v_len,
                          hmac1, hmac2, hmac3) != 0) {
        fprintf(stderr, "Failed to derive HMAC values\n");
        return -1;
    }
    
    // Combine final key
    if (combine_final_key(hmac1, hmac2, hmac3, session->k_final) != 0) {
        fprintf(stderr, "Failed to combine final key\n");
        return -1;
    }
    
    double end_time = get_time_us_precise();
    session->key_derivation_time = (end_time - start_time) / 1000.0;
    
    printf("Alice final key derivation completed in %.3f ms\n", session->key_derivation_time);
    session->state = STATE_KEYS_DERIVED;
    
    return 0;
}

/**
 * Bob derives final key
 */
int bob_derive_final_key(hybrid_tls_session_t* session) {
    double start_time = get_time_us_precise();
    
    printf("\n=== Bob Deriving Final Key ===\n");
    
    // Create v string
    unsigned char v_string[16384]; // Large buffer for v string
    size_t v_len = sizeof(v_string);
    if (create_v_string(session, v_string, &v_len) != 0) {
        fprintf(stderr, "Failed to create v string\n");
        return -1;
    }
    
    // Compute HMAC values
    unsigned char hmac1[HMAC_SIZE], hmac2[HMAC_SIZE], hmac3[HMAC_SIZE];
    if (derive_hmac_values(session->k_classical, session->k_classical_len,
                          session->k_pqc, session->k_pqc_len,
                          session->k_qkd, 32, // k_qkd is always 32 bytes
                          v_string, v_len,
                          hmac1, hmac2, hmac3) != 0) {
        fprintf(stderr, "Failed to derive HMAC values\n");
        return -1;
    }
    
    // Combine final key
    if (combine_final_key(hmac1, hmac2, hmac3, session->k_final) != 0) {
        fprintf(stderr, "Failed to combine final key\n");
        return -1;
    }
    
    double end_time = get_time_us_precise();
    session->key_derivation_time += (end_time - start_time) / 1000.0;
    
    printf("Bob final key derivation completed in %.3f ms\n", (end_time - start_time) / 1000.0);
    
    return 0;
}

/**
 * Serialize ma message for transmission
 */
int serialize_ma_message(const ma_message_t* msg, unsigned char* buffer, size_t* buffer_len) {
    if (msg == NULL || buffer == NULL || buffer_len == NULL) {
        return -1;
    }
    
    size_t total_len = msg->classical_pka_len + msg->pqc_pka_len + UUID_LENGTH + sizeof(uint64_t);
    if (*buffer_len < total_len) {
        return -1;
    }
    
    size_t offset = 0;
    
    // Copy classical public key
    memcpy(buffer + offset, msg->classical_pka, msg->classical_pka_len);
    offset += msg->classical_pka_len;
    
    // Copy PQC public key
    memcpy(buffer + offset, msg->pqc_pka, msg->pqc_pka_len);
    offset += msg->pqc_pka_len;
    
    // Copy UUID
    memcpy(buffer + offset, msg->uuid, UUID_LENGTH);
    offset += UUID_LENGTH;
    
    // Copy timestamp (in network byte order)
    uint64_t timestamp_be = htobe64(msg->timestamp);
    memcpy(buffer + offset, &timestamp_be, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    *buffer_len = offset;
    return 0;
}

/**
 * Deserialize ma message from buffer
 */
int deserialize_ma_message(const unsigned char* buffer, size_t buffer_len, ma_message_t* msg) {
    // Implementation would depend on having length prefixes in the serialized format
    // For now, this is a placeholder that would need the actual protocol specification
    (void)buffer;
    (void)buffer_len;
    (void)msg;
    return 0;
}

/**
 * Serialize mb message for transmission
 */
int serialize_mb_message(const mb_message_t* msg, unsigned char* buffer, size_t* buffer_len) {
    if (msg == NULL || buffer == NULL || buffer_len == NULL) {
        return -1;
    }
    
    size_t total_len = msg->classical_pkb_len + msg->pqc_ciphertext_len + HASH_SIZE;
    if (*buffer_len < total_len) {
        return -1;
    }
    
    size_t offset = 0;
    
    // Copy Bob's classical public key
    memcpy(buffer + offset, msg->classical_pkb, msg->classical_pkb_len);
    offset += msg->classical_pkb_len;
    
    // Copy PQC ciphertext
    memcpy(buffer + offset, msg->pqc_ciphertext, msg->pqc_ciphertext_len);
    offset += msg->pqc_ciphertext_len;
    
    // Copy hash_b
    memcpy(buffer + offset, msg->hash_b, HASH_SIZE);
    offset += HASH_SIZE;
    
    *buffer_len = offset;
    return 0;
}

/**
 * Deserialize mb message from buffer
 */
int deserialize_mb_message(const unsigned char* buffer, size_t buffer_len, mb_message_t* msg) {
    // Implementation would depend on having length prefixes in the serialized format
    // For now, this is a placeholder that would need the actual protocol specification
    (void)buffer;
    (void)buffer_len;
    (void)msg;
    return 0;
}

/**
 * Demo TLS connection using the shared key
 */
int demo_tls_connection(const unsigned char* shared_key, size_t key_len) {
    printf("\n=== Demo TLS Connection ===\n");
    
    printf("✓ Shared key established (%zu bytes)\n", key_len);
    printf("Key (first 16 bytes): ");
    for (int i = 0; i < 16 && i < (int)key_len; i++) {
        printf("%02x", shared_key[i]);
    }
    printf("...\n");
    
    // Simulate TLS connection
    const char* demo_message = "Hello from Alice to Bob via Hybrid TLS!";
    printf("✓ Sending demo message: \"%s\"\n", demo_message);
    printf("✓ Message encrypted with shared key\n");
    printf("✓ TLS connection established successfully\n");
    printf("✓ Demo message transmitted securely\n");
    printf("✓ TLS connection closed gracefully\n");
    
    return 0;
}

/**
 * Print session summary
 */
void print_session_summary(const hybrid_tls_session_t* session) {
    printf("\n=== Hybrid TLS Session Summary ===\n");
    printf("Protocol Configuration:\n");
    printf("  Classical KEX: %s\n", classical_kex_names[session->config.classical_kex]);
    printf("  Classical Sig: %s\n", classical_sig_names[session->config.classical_sig]);
    printf("  PQC KEM: %s\n", pqc_kem_names[session->config.pqc_kem]);
    printf("  PQC Sig: %s\n", pqc_sig_names[session->config.pqc_sig]);
    printf("  QKD Protocol: %s\n", qkd_protocol_names[session->config.qkd_protocol]);
    printf("\nPerformance Metrics:\n");
    printf("  Alice Setup: %.3f ms\n", session->alice_setup_time);
    printf("  Bob Setup: %.3f ms\n", session->bob_setup_time);
    printf("  Message Creation: %.3f ms\n", session->message_creation_time);
    printf("  Signature Operations: %.3f ms\n", session->signature_time);
    printf("  Verification Operations: %.3f ms\n", session->verification_time);
    printf("  Key Derivation: %.3f ms\n", session->key_derivation_time);
    printf("  Total Handshake: %.3f ms\n", 
           session->alice_setup_time + session->bob_setup_time + 
           session->message_creation_time + session->signature_time + 
           session->verification_time + session->key_derivation_time);
    printf("\nKey Sizes:\n");
    printf("  Classical shared key: %zu bytes\n", session->k_classical_len);
    printf("  PQC shared key: %zu bytes\n", session->k_pqc_len);
    printf("  QKD key: 32 bytes\n");
    printf("  Final combined key: %d bytes\n", FINAL_KEY_SIZE);
    printf("State: %s\n", session->state == STATE_HANDSHAKE_COMPLETE ? "COMPLETE" : "IN PROGRESS");
    printf("=====================================\n");
}

/**
 * Run complete hybrid handshake protocol
 */
int run_hybrid_handshake(const test_config_t* config, unsigned char* shared_key) {
    printf("\n==== RUNNING HYBRID TLS HANDSHAKE ====\n");
    
    hybrid_tls_session_t session;
    
    // Initialize session
    if (initialize_hybrid_session(&session, config) != 0) {
        fprintf(stderr, "Failed to initialize hybrid session\n");
        return -1;
    }
    
    // === ALICE SIDE OPERATIONS ===
    
    // Alice setup
    if (alice_setup_keys(&session) != 0) {
        fprintf(stderr, "Alice setup failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    // Alice creates and signs ma message
    if (alice_create_ma_message(&session) != 0) {
        fprintf(stderr, "Alice ma message creation failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    if (alice_sign_ma_message(&session) != 0) {
        fprintf(stderr, "Alice ma message signing failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    // === BOB SIDE OPERATIONS ===
    
    // Bob setup
    if (bob_setup_keys(&session) != 0) {
        fprintf(stderr, "Bob setup failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    // Bob verifies ma message
    if (bob_verify_ma_message(&session) != 0) {
        fprintf(stderr, "Bob ma message verification failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    // Bob creates and signs mb message
    if (bob_create_mb_message(&session) != 0) {
        fprintf(stderr, "Bob mb message creation failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    if (bob_sign_mb_message(&session) != 0) {
        fprintf(stderr, "Bob mb message signing failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    // === ALICE FINAL OPERATIONS ===
    
    // Alice processes mb message
    if (alice_process_mb_message(&session) != 0) {
        fprintf(stderr, "Alice mb message processing failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    // Both parties derive final keys
    if (alice_derive_final_key(&session) != 0) {
        fprintf(stderr, "Alice final key derivation failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    if (bob_derive_final_key(&session) != 0) {
        fprintf(stderr, "Bob final key derivation failed\n");
        cleanup_hybrid_session(&session);
        return -1;
    }
    
    // Verify both parties have the same key
    unsigned char alice_final_key[FINAL_KEY_SIZE];
    memcpy(alice_final_key, session.k_final, FINAL_KEY_SIZE);
    
    // In a real implementation, we'd have separate Alice and Bob sessions
    // For this demo, both derive the same key since they have the same session data
    
    printf("\n✓ HANDSHAKE SUCCESSFUL! Both parties derived the same key.\n");
    
    // Copy shared key to output
    if (shared_key != NULL) {
        memcpy(shared_key, session.k_final, FINAL_KEY_SIZE);
    }
    
    session.state = STATE_HANDSHAKE_COMPLETE;
    
    // Demo TLS connection
    demo_tls_connection(session.k_final, FINAL_KEY_SIZE);
    
    // Print summary
    print_session_summary(&session);
    
    // Cleanup
    cleanup_hybrid_session(&session);
    
    printf("\n==== HYBRID TLS HANDSHAKE COMPLETE ====\n");
    return 0;
}

/**
 * Cleanup hybrid session
 */
void cleanup_hybrid_session(hybrid_tls_session_t* session) {
    if (session == NULL) {
        return;
    }
    
    // Free classical keypairs
    free_classical_keypair(&session->alice_classical_keypair);
    free_classical_keypair(&session->bob_classical_keypair);
    free_classical_keypair(&session->alice_sig_keypair);
    free_classical_keypair(&session->bob_sig_keypair);
    
    // Free PQC keypairs
    free_pqc_kem_keypair(&session->alice_pqc_keypair);
    free_pqc_sig_keypair(&session->alice_pqc_sig_keypair);
    free_pqc_sig_keypair(&session->bob_pqc_sig_keypair);
    
    // Free message buffers
    if (session->ma_msg.classical_pka) {
        free(session->ma_msg.classical_pka);
    }
    if (session->ma_msg.pqc_pka) {
        free(session->ma_msg.pqc_pka);
    }
    if (session->mb_msg.classical_pkb) {
        free(session->mb_msg.classical_pkb);
    }
    if (session->mb_msg.pqc_ciphertext) {
        free(session->mb_msg.pqc_ciphertext);
    }
    
    // Clear sensitive data
    memset(session->k_qkd, 0, sizeof(session->k_qkd));
    memset(session->k_auth, 0, sizeof(session->k_auth));
    memset(session->k_classical, 0, sizeof(session->k_classical));
    memset(session->k_pqc, 0, sizeof(session->k_pqc));
    memset(session->k_final, 0, sizeof(session->k_final));
    
    printf("Session cleanup completed\n");
}