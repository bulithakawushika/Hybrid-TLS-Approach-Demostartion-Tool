#include "qkd_interface.h"
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// External references to QKD keys from stage.c
extern qkd_key_data_t bb84_data;
extern qkd_key_data_t e91_data;
extern qkd_key_data_t mdi_data;

/**
 * Simple HKDF implementation using HMAC-SHA256
 * This is more compatible with older OpenSSL versions
 */
int simple_hkdf(const unsigned char* ikm, size_t ikm_len,
                const unsigned char* salt, size_t salt_len,
                const unsigned char* info, size_t info_len,
                unsigned char* okm, size_t okm_len) {
    
    unsigned char prk[32]; // SHA256 output size
    unsigned int prk_len = 32;
    
    // Step 1: Extract (HMAC with salt)
    if (HMAC(EVP_sha256(), salt, salt_len, ikm, ikm_len, prk, &prk_len) == NULL) {
        fprintf(stderr, "HKDF Extract failed\n");
        return -1;
    }
    
    // Step 2: Expand
    unsigned char okm_temp[256]; // Temporary buffer
    unsigned char counter = 1;
    size_t n = (okm_len + 31) / 32; // Number of iterations needed
    size_t generated = 0;
    
    for (size_t i = 0; i < n && generated < okm_len; i++) {
        // Create T(i) = HMAC-Hash(PRK, T(i-1) | info | counter)
        unsigned char hmac_input[512];
        size_t hmac_input_len = 0;
        
        // Add T(i-1) for i > 1 (skip for first iteration)
        if (i > 0) {
            memcpy(hmac_input + hmac_input_len, okm_temp + (i-1) * 32, 32);
            hmac_input_len += 32;
        }
        
        // Add info
        if (info && info_len > 0) {
            memcpy(hmac_input + hmac_input_len, info, info_len);
            hmac_input_len += info_len;
        }
        
        // Add counter
        hmac_input[hmac_input_len] = counter;
        hmac_input_len++;
        
        // Compute HMAC
        unsigned int hmac_len = 32;
        if (HMAC(EVP_sha256(), prk, prk_len, hmac_input, hmac_input_len, 
                 okm_temp + i * 32, &hmac_len) == NULL) {
            fprintf(stderr, "HKDF Expand failed at iteration %zu\n", i);
            return -1;
        }
        
        counter++;
        generated += 32;
    }
    
    // Copy the required amount to output
    memcpy(okm, okm_temp, okm_len);
    
    // Clear sensitive data
    memset(prk, 0, sizeof(prk));
    memset(okm_temp, 0, sizeof(okm_temp));
    
    return 0;
}

/**
 * Get QKD key data for specified protocol
 */
int get_qkd_key(qkd_protocol_t protocol, qkd_key_data_t* key_out) {
    if (key_out == NULL) {
        return -1;
    }
    
    switch(protocol) {
        case QKD_BB84:
            if (!bb84_data.valid) {
                fprintf(stderr, "BB84 key data not valid\n");
                return -1;
            }
            memcpy(key_out, &bb84_data, sizeof(qkd_key_data_t));
            break;
        case QKD_E91:
            if (!e91_data.valid) {
                fprintf(stderr, "E91 key data not valid\n");
                return -1;
            }
            memcpy(key_out, &e91_data, sizeof(qkd_key_data_t));
            break;
        case QKD_MDI:
            if (!mdi_data.valid) {
                fprintf(stderr, "MDI key data not valid\n");
                return -1;
            }
            memcpy(key_out, &mdi_data, sizeof(qkd_key_data_t));
            break;
        default:
            fprintf(stderr, "Unknown QKD protocol: %d\n", protocol);
            return -1;
    }
    return 0;
}

/**
 * Derive k_qkd, k_auth, na, nb from kqkdm using simple HKDF
 */
int derive_qkd_components(const unsigned char* kqkdm, size_t kqkdm_len,
                         unsigned char* k_qkd, unsigned char* k_auth,
                         unsigned char* na, unsigned char* nb) {
    
    const char* salt = "QKD-TLS-HYBRID";
    
    // Derive k_qkd (32 bytes)
    const char* info_k_qkd = "k_qkd";
    if (simple_hkdf(kqkdm, kqkdm_len, 
                    (unsigned char*)salt, strlen(salt),
                    (unsigned char*)info_k_qkd, strlen(info_k_qkd),
                    k_qkd, 32) != 0) {
        fprintf(stderr, "Failed to derive k_qkd\n");
        return -1;
    }
    
    // Derive k_auth (32 bytes)
    const char* info_k_auth = "k_auth";
    if (simple_hkdf(kqkdm, kqkdm_len,
                    (unsigned char*)salt, strlen(salt),
                    (unsigned char*)info_k_auth, strlen(info_k_auth),
                    k_auth, 32) != 0) {
        fprintf(stderr, "Failed to derive k_auth\n");
        return -1;
    }
    
    // Derive na (12 bytes for Poly1305)
    const char* info_na = "nonce_a";
    if (simple_hkdf(kqkdm, kqkdm_len,
                    (unsigned char*)salt, strlen(salt),
                    (unsigned char*)info_na, strlen(info_na),
                    na, 12) != 0) {
        fprintf(stderr, "Failed to derive na\n");
        return -1;
    }
    
    // Derive nb (12 bytes for Poly1305)  
    const char* info_nb = "nonce_b";
    if (simple_hkdf(kqkdm, kqkdm_len,
                    (unsigned char*)salt, strlen(salt),
                    (unsigned char*)info_nb, strlen(info_nb),
                    nb, 12) != 0) {
        fprintf(stderr, "Failed to derive nb\n");
        return -1;
    }
    
    return 0;
}

/**
 * Check if QKD keys are available for all protocols
 */
int check_qkd_availability(void) {
    printf("Checking QKD key availability:\n");
    printf("  BB84: %s\n", bb84_data.valid ? "Available" : "Not Available");
    printf("  E91:  %s\n", e91_data.valid ? "Available" : "Not Available");
    printf("  MDI:  %s\n", mdi_data.valid ? "Available" : "Not Available");
    
    return (bb84_data.valid && e91_data.valid && mdi_data.valid) ? 0 : -1;
}

/**
 * Print QKD key information for debugging
 */
void print_qkd_key_info(qkd_protocol_t protocol) {
    qkd_key_data_t key_data;
    
    if (get_qkd_key(protocol, &key_data) != 0) {
        printf("Failed to get %s key data\n", qkd_protocol_names[protocol]);
        return;
    }
    
    printf("QKD Key Info for %s:\n", qkd_protocol_names[protocol]);
    printf("  kqkdm: ");
    for (int i = 0; i < SHA3_512_DIGEST_LENGTH; i++) {
        printf("%02x", key_data.kqkdm[i]);
    }
    printf("\n  uuid:  ");
    for (int i = 0; i < UUID_LENGTH; i++) {
        printf("%02x", key_data.uuid[i]);
    }
    printf("\n");
}