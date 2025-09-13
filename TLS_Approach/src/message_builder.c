#include "message_builder.h"
#include "classical_crypto.h"
#include "pqc_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/**
 * Build ma message: classical_pka || pqc_pka || uuid || timestamp
 */
int build_ma_message(const ma_components_t* components, 
                     unsigned char** message, 
                     size_t* message_len) {
    
    if (components == NULL || message == NULL || message_len == NULL) {
        return -1;
    }
    
    // Calculate total message length
    size_t total_len = components->classical_pka_len + 
                      components->pqc_pka_len +
                      components->uuid_len +
                      sizeof(uint64_t); // timestamp
    
    // Allocate message buffer
    *message = malloc(total_len);
    if (*message == NULL) {
        return -1;
    }
    
    size_t offset = 0;
    
    // Copy classical public key
    memcpy(*message + offset, components->classical_pka, components->classical_pka_len);
    offset += components->classical_pka_len;
    
    // Copy PQC public key  
    memcpy(*message + offset, components->pqc_pka, components->pqc_pka_len);
    offset += components->pqc_pka_len;
    
    // Copy UUID
    memcpy(*message + offset, components->uuid, components->uuid_len);
    offset += components->uuid_len;
    
    // Copy timestamp (network byte order)
    uint64_t timestamp_be = htobe64(components->timestamp);
    memcpy(*message + offset, &timestamp_be, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    
    *message_len = total_len;
    return 0;
}

/**
 * Build mb message: classical_pkb || ciphertext || h_b
 */
int build_mb_message(const mb_components_t* components,
                     unsigned char** message,
                     size_t* message_len) {
    
    if (components == NULL || message == NULL || message_len == NULL) {
        return -1;
    }
    
    // Calculate total message length
    size_t total_len = components->classical_pkb_len +
                      components->ciphertext_len +
                      components->h_b_len;
    
    // Allocate message buffer
    *message = malloc(total_len);
    if (*message == NULL) {
        return -1;
    }
    
    size_t offset = 0;
    
    // Copy Bob's classical public key
    memcpy(*message + offset, components->classical_pkb, components->classical_pkb_len);
    offset += components->classical_pkb_len;
    
    // Copy PQC ciphertext
    memcpy(*message + offset, components->ciphertext, components->ciphertext_len);
    offset += components->ciphertext_len;
    
    // Copy hash h_b
    memcpy(*message + offset, components->h_b, components->h_b_len);
    offset += components->h_b_len;
    
    *message_len = total_len;
    return 0;
}

/**
 * Parse ma message (simplified - assumes known component sizes)
 * In practice, you'd need length prefixes or delimiters
 */
int parse_ma_message(const unsigned char* message,
                     size_t message_len,
                     ma_components_t* components) {
    
    if (message == NULL || components == NULL) {
        return -1;
    }
    
    // This is a simplified parser - real implementation needs
    // to handle variable-length components properly
    memset(components, 0, sizeof(ma_components_t));
    
    // For now, just extract timestamp from the end
    if (message_len < sizeof(uint64_t)) {
        return -1;
    }
    
    uint64_t timestamp_be;
    memcpy(&timestamp_be, message + message_len - sizeof(uint64_t), sizeof(uint64_t));
    components->timestamp = be64toh(timestamp_be);
    
    return 0;
}

/**
 * Parse mb message (simplified)
 */
int parse_mb_message(const unsigned char* message,
                     size_t message_len,
                     mb_components_t* components) {
    
    if (message == NULL || components == NULL) {
        return -1;
    }
    
    // Simplified parser - real implementation needs proper parsing
    memset(components, 0, sizeof(mb_components_t));
    
    // For now, just validate message exists
    if (message_len == 0) {
        return -1;
    }
    
    return 0;
}

/**
 * Hash message using SHA-512
 */
int hash_message_sha512(const unsigned char* message,
                       size_t message_len,
                       unsigned char* hash) {
    
    if (message == NULL || hash == NULL) {
        return -1;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_DigestUpdate(ctx, message, message_len) != 1) {
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
 * Get current timestamp in seconds since epoch
 */
uint64_t get_current_timestamp(void) {
    return (uint64_t)time(NULL);
}

/**
 * Validate timestamp against current time with allowed skew
 */
int validate_timestamp(uint64_t timestamp, uint64_t max_skew_seconds) {
    uint64_t current_time = get_current_timestamp();
    uint64_t time_diff = (current_time > timestamp) ? 
                        (current_time - timestamp) : (timestamp - current_time);
    
    return (time_diff <= max_skew_seconds) ? 0 : -1;
}

/**
 * Sign message using classical signature algorithm
 */
int sign_message_classical(const unsigned char* message,
                          size_t message_len,
                          classical_sig_t sig_type,
                          const classical_keypair_t* keypair,
                          unsigned char* signature,
                          size_t* signature_len) {
    
    return classical_sign(sig_type, keypair, message, message_len, signature, signature_len);
}

/**
 * Sign message using PQC signature algorithm
 */
int sign_message_pqc(const unsigned char* message,
                    size_t message_len,
                    pqc_sig_t sig_type,
                    const pqc_sig_keypair_t* keypair,
                    unsigned char* signature,
                    size_t* signature_len) {
    
    return pqc_sign(sig_type, keypair->secret_key, keypair->secret_key_len,
                   message, message_len, signature, signature_len);
}

/**
 * Verify classical signature
 */
int verify_message_classical(const unsigned char* message,
                            size_t message_len,
                            classical_sig_t sig_type,
                            const unsigned char* public_key,
                            size_t public_key_len,
                            const unsigned char* signature,
                            size_t signature_len) {
    
    return classical_verify(sig_type, public_key, public_key_len,
                           message, message_len, signature, signature_len);
}

/**
 * Verify PQC signature
 */
int verify_message_pqc(const unsigned char* message,
                      size_t message_len,
                      pqc_sig_t sig_type,
                      const unsigned char* public_key,
                      size_t public_key_len,
                      const unsigned char* signature,
                      size_t signature_len) {
    
    return pqc_verify(sig_type, public_key, public_key_len,
                     message, message_len, signature, signature_len);
}

/**
 * Derive string v: classical_pka || classical_pkb || ciphertext || uuid
 */
int derive_string_v(const unsigned char* classical_pka,
                   size_t classical_pka_len,
                   const unsigned char* classical_pkb,
                   size_t classical_pkb_len,
                   const unsigned char* ciphertext,
                   size_t ciphertext_len,
                   const unsigned char* uuid,
                   size_t uuid_len,
                   unsigned char** string_v,
                   size_t* string_v_len) {
    
    if (classical_pka == NULL || classical_pkb == NULL || 
        ciphertext == NULL || uuid == NULL || 
        string_v == NULL || string_v_len == NULL) {
        return -1;
    }
    
    // Calculate total length
    *string_v_len = classical_pka_len + classical_pkb_len + ciphertext_len + uuid_len;
    
    // Allocate buffer
    *string_v = malloc(*string_v_len);
    if (*string_v == NULL) {
        return -1;
    }
    
    size_t offset = 0;
    
    // Concatenate all components
    memcpy(*string_v + offset, classical_pka, classical_pka_len);
    offset += classical_pka_len;
    
    memcpy(*string_v + offset, classical_pkb, classical_pkb_len);
    offset += classical_pkb_len;
    
    memcpy(*string_v + offset, ciphertext, ciphertext_len);
    offset += ciphertext_len;
    
    memcpy(*string_v + offset, uuid, uuid_len);
    offset += uuid_len;
    
    return 0;
}

/**
 * Compute final key: HMAC(k_classical, v) ⊕ HMAC(k_pqc, v) ⊕ HMAC(k_qkd, v)
 */
int compute_final_key(const unsigned char* k_classical,
                     size_t k_classical_len,
                     const unsigned char* k_pqc,
                     size_t k_pqc_len,
                     const unsigned char* k_qkd,
                     size_t k_qkd_len,
                     const unsigned char* string_v,
                     size_t string_v_len,
                     unsigned char* k_final,
                     size_t* k_final_len) {
    
    if (k_classical == NULL || k_pqc == NULL || k_qkd == NULL ||
        string_v == NULL || k_final == NULL || k_final_len == NULL) {
        return -1;
    }
    
    unsigned char hmac1[32], hmac2[32], hmac3[32];
    unsigned int hmac_len;
    
    // Compute HMAC(k_classical, v)
    if (HMAC(EVP_sha256(), k_classical, k_classical_len,
             string_v, string_v_len, hmac1, &hmac_len) == NULL) {
        return -1;
    }
    
    // Compute HMAC(k_pqc, v)
    if (HMAC(EVP_sha256(), k_pqc, k_pqc_len,
             string_v, string_v_len, hmac2, &hmac_len) == NULL) {
        return -1;
    }
    
    // Compute HMAC(k_qkd, v)
    if (HMAC(EVP_sha256(), k_qkd, k_qkd_len,
             string_v, string_v_len, hmac3, &hmac_len) == NULL) {
        return -1;
    }
    
    // XOR all three HMACs: HMAC1 ⊕ HMAC2 ⊕ HMAC3
    for (int i = 0; i < 32; i++) {
        k_final[i] = hmac1[i] ^ hmac2[i] ^ hmac3[i];
    }
    
    *k_final_len = 32; // SHA256 output size
    
    // Clear intermediate HMAC values
    memset(hmac1, 0, sizeof(hmac1));
    memset(hmac2, 0, sizeof(hmac2));
    memset(hmac3, 0, sizeof(hmac3));
    
    return 0;
}

/**
 * Free ma message components
 */
void free_message_components_ma(ma_components_t* components) {
    if (components == NULL) return;
    
    if (components->classical_pka) {
        free(components->classical_pka);
        components->classical_pka = NULL;
    }
    if (components->pqc_pka) {
        free(components->pqc_pka);
        components->pqc_pka = NULL;
    }
    if (components->uuid) {
        free(components->uuid);
        components->uuid = NULL;
    }
    
    memset(components, 0, sizeof(ma_components_t));
}

/**
 * Free mb message components
 */
void free_message_components_mb(mb_components_t* components) {
    if (components == NULL) return;
    
    if (components->classical_pkb) {
        free(components->classical_pkb);
        components->classical_pkb = NULL;
    }
    if (components->ciphertext) {
        free(components->ciphertext);
        components->ciphertext = NULL;
    }
    if (components->h_b) {
        free(components->h_b);
        components->h_b = NULL;
    }
    
    memset(components, 0, sizeof(mb_components_t));
}

/**
 * Free protocol message
 */
void free_protocol_message(protocol_message_t* message) {
    if (message == NULL) return;
    
    if (message->data) {
        free(message->data);
        message->data = NULL;
    }
    
    memset(message, 0, sizeof(protocol_message_t));
}

/**
 * Print message in hexadecimal for debugging
 */
void print_message_hex(const unsigned char* message, size_t len, const char* label) {
    if (message == NULL || label == NULL) return;
    
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 64; i++) { // Limit output to first 64 bytes
        printf("%02x", message[i]);
    }
    if (len > 64) {
        printf("...");
    }
    printf("\n");
}