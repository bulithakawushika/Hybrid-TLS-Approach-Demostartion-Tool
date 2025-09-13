#include "mac_ops.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

/**
 * Generate Poly1305 MAC using OpenSSL EVP interface
 */
int poly1305_generate_mac(const unsigned char* key,
                         const unsigned char* nonce,
                         const unsigned char* message,
                         size_t message_len,
                         unsigned char* mac) {
    
    if (key == NULL || nonce == NULL || message == NULL || mac == NULL) {
        fprintf(stderr, "Invalid parameters for Poly1305 MAC generation\n");
        return MAC_ERROR;
    }
    
    // Create combined key (32 bytes: key || nonce padded)
    unsigned char poly_key[POLY1305_KEY_SIZE];
    
    // Use first 20 bytes of key material and 12 bytes of nonce
    memcpy(poly_key, key, 20);
    memcpy(poly_key + 20, nonce, POLY1305_NONCE_SIZE);
    
    // Try to use EVP interface for Poly1305
    EVP_MAC* mac_ctx_type = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if (mac_ctx_type == NULL) {
        // Fallback to HMAC-SHA256 if Poly1305 not available
        fprintf(stderr, "Poly1305 not available, using HMAC-SHA256 fallback\n");
        return hmac_sha256_generate_mac(key, nonce, message, message_len, mac);
    }
    
    EVP_MAC_CTX* mac_ctx = EVP_MAC_CTX_new(mac_ctx_type);
    if (mac_ctx == NULL) {
        fprintf(stderr, "Failed to create Poly1305 MAC context\n");
        EVP_MAC_free(mac_ctx_type);
        return MAC_ERROR;
    }
    
    // Set the key
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string("key", poly_key, POLY1305_KEY_SIZE),
        OSSL_PARAM_END
    };
    
    if (EVP_MAC_init(mac_ctx, NULL, 0, params) != 1) {
        fprintf(stderr, "Failed to initialize Poly1305 MAC\n");
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac_ctx_type);
        return MAC_ERROR;
    }
    
    // Update with message
    if (EVP_MAC_update(mac_ctx, message, message_len) != 1) {
        fprintf(stderr, "Failed to update Poly1305 MAC\n");
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac_ctx_type);
        return MAC_ERROR;
    }
    
    // Finalize MAC
    size_t mac_len = POLY1305_TAG_SIZE;
    if (EVP_MAC_final(mac_ctx, mac, &mac_len, POLY1305_TAG_SIZE) != 1) {
        fprintf(stderr, "Failed to finalize Poly1305 MAC\n");
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac_ctx_type);
        return MAC_ERROR;
    }
    
    // Cleanup
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac_ctx_type);
    
    // Clear sensitive key material
    memset(poly_key, 0, sizeof(poly_key));
    
    return MAC_SUCCESS;
}

/**
 * HMAC-SHA256 fallback implementation
 */
int hmac_sha256_generate_mac(const unsigned char* key,
                           const unsigned char* nonce,
                           const unsigned char* message,
                           size_t message_len,
                           unsigned char* mac) {
    
    // Create combined key material
    unsigned char hmac_key[POLY1305_KEY_SIZE];
    memcpy(hmac_key, key, 20);
    memcpy(hmac_key + 20, nonce, POLY1305_NONCE_SIZE);
    
    EVP_MAC* mac_ctx_type = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac_ctx_type == NULL) {
        fprintf(stderr, "Failed to fetch HMAC\n");
        return MAC_ERROR;
    }
    
    EVP_MAC_CTX* mac_ctx = EVP_MAC_CTX_new(mac_ctx_type);
    if (mac_ctx == NULL) {
        fprintf(stderr, "Failed to create HMAC context\n");
        EVP_MAC_free(mac_ctx_type);
        return MAC_ERROR;
    }
    
    // Set HMAC parameters
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_octet_string("key", hmac_key, POLY1305_KEY_SIZE),
        OSSL_PARAM_END
    };
    
    if (EVP_MAC_init(mac_ctx, NULL, 0, params) != 1) {
        fprintf(stderr, "Failed to initialize HMAC\n");
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac_ctx_type);
        return MAC_ERROR;
    }
    
    // Update with message
    if (EVP_MAC_update(mac_ctx, message, message_len) != 1) {
        fprintf(stderr, "Failed to update HMAC\n");
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac_ctx_type);
        return MAC_ERROR;
    }
    
    // Finalize HMAC
    unsigned char full_mac[32]; // SHA256 output size
    size_t full_mac_len = 32;
    if (EVP_MAC_final(mac_ctx, full_mac, &full_mac_len, 32) != 1) {
        fprintf(stderr, "Failed to finalize HMAC\n");
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac_ctx_type);
        return MAC_ERROR;
    }
    
    // Use first 16 bytes as MAC (same size as Poly1305)
    memcpy(mac, full_mac, POLY1305_TAG_SIZE);
    
    // Cleanup
    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac_ctx_type);
    memset(hmac_key, 0, sizeof(hmac_key));
    memset(full_mac, 0, sizeof(full_mac));
    
    return MAC_SUCCESS;
}

/**
 * Verify Poly1305 MAC
 */
int poly1305_verify_mac(const unsigned char* key,
                       const unsigned char* nonce,
                       const unsigned char* message,
                       size_t message_len,
                       const unsigned char* expected_mac) {
    
    if (key == NULL || nonce == NULL || message == NULL || expected_mac == NULL) {
        fprintf(stderr, "Invalid parameters for MAC verification\n");
        return MAC_ERROR;
    }
    
    unsigned char computed_mac[POLY1305_TAG_SIZE];
    
    // Generate MAC for verification
    int result = poly1305_generate_mac(key, nonce, message, message_len, computed_mac);
    if (result != MAC_SUCCESS) {
        return result;
    }
    
    // Compare MACs using constant-time comparison
    if (CRYPTO_memcmp(computed_mac, expected_mac, POLY1305_TAG_SIZE) == 0) {
        return MAC_SUCCESS;
    } else {
        return MAC_VERIFY_FAILED;
    }
}

/**
 * Print MAC in hexadecimal format
 */
void print_mac_hex(const unsigned char* mac) {
    if (mac == NULL) {
        printf("(null MAC)");
        return;
    }
    
    for (int i = 0; i < POLY1305_TAG_SIZE; i++) {
        printf("%02x", mac[i]);
    }
}

/**
 * Compare two MACs securely
 */
int compare_macs(const unsigned char* mac1, const unsigned char* mac2) {
    if (mac1 == NULL || mac2 == NULL) {
        return -1;
    }
    
    return CRYPTO_memcmp(mac1, mac2, POLY1305_TAG_SIZE);
}

/**
 * ChaCha20-Poly1305 AEAD encryption (for future use)
 */
int chacha20_poly1305_encrypt(const unsigned char* key,
                              const unsigned char* nonce,
                              const unsigned char* plaintext,
                              size_t plaintext_len,
                              const unsigned char* additional_data,
                              size_t ad_len,
                              unsigned char* ciphertext,
                              unsigned char* tag) {
    
    if (key == NULL || nonce == NULL || plaintext == NULL || 
        ciphertext == NULL || tag == NULL) {
        return MAC_ERROR;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return MAC_ERROR;
    }
    
    // Initialize ChaCha20-Poly1305
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return MAC_ERROR;
    }
    
    int len;
    int ciphertext_len = 0;
    
    // Add additional authenticated data if provided
    if (additional_data != NULL && ad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, additional_data, ad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return MAC_ERROR;
        }
    }
    
    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return MAC_ERROR;
    }
    ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return MAC_ERROR;
    }
    ciphertext_len += len;
    
    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return MAC_ERROR;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

/**
 * ChaCha20-Poly1305 AEAD decryption (for future use)
 */
int chacha20_poly1305_decrypt(const unsigned char* key,
                              const unsigned char* nonce,
                              const unsigned char* ciphertext,
                              size_t ciphertext_len,
                              const unsigned char* additional_data,
                              size_t ad_len,
                              const unsigned char* tag,
                              unsigned char* plaintext) {
    
    if (key == NULL || nonce == NULL || ciphertext == NULL || 
        tag == NULL || plaintext == NULL) {
        return MAC_ERROR;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return MAC_ERROR;
    }
    
    // Initialize ChaCha20-Poly1305
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return MAC_ERROR;
    }
    
    int len;
    int plaintext_len = 0;
    
    // Add additional authenticated data if provided
    if (additional_data != NULL && ad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, additional_data, ad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return MAC_ERROR;
        }
    }
    
    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return MAC_ERROR;
    }
    plaintext_len = len;
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return MAC_ERROR;
    }
    
    // Finalize decryption and verify tag
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return MAC_VERIFY_FAILED;
    }
}