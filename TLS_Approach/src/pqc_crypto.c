#include "pqc_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

// LibOQS algorithm mappings
static const char* kem_algorithm_names[PQC_KEM_MAX] = {
    "ML-KEM-768",    // PQC_ML_KEM_768
    "HQC-192",       // PQC_HQC_192  
    "BIKE-L3"        // PQC_BIKE_L3
};

static const char* sig_algorithm_names[PQC_SIG_MAX] = {
    "ML-DSA-65",                    // PQC_ML_DSA_65
    "Falcon-512",                   // PQC_FALCON_512
    "SPHINCS+-SHA2-192f-simple",    // PQC_SPHINCS_SHA2_192F
    "SPHINCS+-SHAKE-192f-simple"    // PQC_SPHINCS_SHAKE_192F
};

/**
 * Initialize LibOQS library
 */
int initialize_liboqs(void) {
    // LibOQS doesn't require explicit initialization in recent versions
    // Just verify that the library is working
    printf("LibOQS Version: %s\n", OQS_version());
    return 0;
}

/**
 * Cleanup LibOQS resources
 */
void cleanup_liboqs(void) {
    // LibOQS handles cleanup automatically
    // No explicit cleanup needed in recent versions
}

/**
 * Check if KEM algorithm is supported
 */
int is_kem_supported(pqc_kem_t algorithm) {
    if (algorithm >= PQC_KEM_MAX) {
        return 0;
    }
    
    return OQS_KEM_alg_is_enabled(kem_algorithm_names[algorithm]);
}

/**
 * Check if signature algorithm is supported
 */
int is_sig_supported(pqc_sig_t algorithm) {
    if (algorithm >= PQC_SIG_MAX) {
        return 0;
    }
    
    return OQS_SIG_alg_is_enabled(sig_algorithm_names[algorithm]);
}

/**
 * Generate PQC KEM keypair
 */
int pqc_kem_keygen(pqc_kem_t algorithm, pqc_kem_keypair_t* keypair) {
    if (algorithm >= PQC_KEM_MAX || keypair == NULL) {
        return -1;
    }
    
    memset(keypair, 0, sizeof(pqc_kem_keypair_t));
    
    if (!is_kem_supported(algorithm)) {
        fprintf(stderr, "KEM algorithm %s not supported\n", kem_algorithm_names[algorithm]);
        return -1;
    }
    
    OQS_KEM* kem = OQS_KEM_new(kem_algorithm_names[algorithm]);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create KEM instance for %s\n", kem_algorithm_names[algorithm]);
        return -1;
    }
    
    // Allocate key buffers
    keypair->public_key = malloc(kem->length_public_key);
    keypair->secret_key = malloc(kem->length_secret_key);
    
    if (keypair->public_key == NULL || keypair->secret_key == NULL) {
        fprintf(stderr, "Failed to allocate memory for KEM keys\n");
        free_pqc_kem_keypair(keypair);
        OQS_KEM_free(kem);
        return -1;
    }
    
    keypair->public_key_len = kem->length_public_key;
    keypair->secret_key_len = kem->length_secret_key;
    
    // Generate keypair
    OQS_STATUS status = OQS_KEM_keypair(kem, keypair->public_key, keypair->secret_key);
    
    OQS_KEM_free(kem);
    
    if (status != OQS_SUCCESS) {
        fprintf(stderr, "KEM key generation failed\n");
        free_pqc_kem_keypair(keypair);
        return -1;
    }
    
    return 0;
}

/**
 * PQC KEM encapsulation
 */
int pqc_kem_encapsulate(pqc_kem_t algorithm, 
                        const unsigned char* public_key,
                        size_t public_key_len,
                        unsigned char* shared_secret,
                        size_t* shared_secret_len,
                        unsigned char* ciphertext,
                        size_t* ciphertext_len) {
    
    if (algorithm >= PQC_KEM_MAX || public_key == NULL || 
        shared_secret == NULL || ciphertext == NULL) {
        return -1;
    }
    
    if (!is_kem_supported(algorithm)) {
        fprintf(stderr, "KEM algorithm %s not supported\n", kem_algorithm_names[algorithm]);
        return -1;
    }
    
    OQS_KEM* kem = OQS_KEM_new(kem_algorithm_names[algorithm]);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create KEM instance for %s\n", kem_algorithm_names[algorithm]);
        return -1;
    }
    
    // Verify key length
    if (public_key_len != kem->length_public_key) {
        fprintf(stderr, "Invalid public key length: %zu != %zu\n", 
                public_key_len, kem->length_public_key);
        OQS_KEM_free(kem);
        return -1;
    }
    
    // Check buffer sizes
    if (*shared_secret_len < kem->length_shared_secret ||
        *ciphertext_len < kem->length_ciphertext) {
        fprintf(stderr, "Output buffers too small\n");
        OQS_KEM_free(kem);
        return -1;
    }
    
    // Perform encapsulation
    OQS_STATUS status = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    
    if (status == OQS_SUCCESS) {
        *shared_secret_len = kem->length_shared_secret;
        *ciphertext_len = kem->length_ciphertext;
    }
    
    OQS_KEM_free(kem);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}

/**
 * PQC KEM decapsulation
 */
int pqc_kem_decapsulate(pqc_kem_t algorithm,
                        const unsigned char* secret_key,
                        size_t secret_key_len,
                        const unsigned char* ciphertext,
                        size_t ciphertext_len,
                        unsigned char* shared_secret,
                        size_t* shared_secret_len) {
    
    if (algorithm >= PQC_KEM_MAX || secret_key == NULL || 
        ciphertext == NULL || shared_secret == NULL) {
        return -1;
    }
    
    if (!is_kem_supported(algorithm)) {
        fprintf(stderr, "KEM algorithm %s not supported\n", kem_algorithm_names[algorithm]);
        return -1;
    }
    
    OQS_KEM* kem = OQS_KEM_new(kem_algorithm_names[algorithm]);
    if (kem == NULL) {
        fprintf(stderr, "Failed to create KEM instance for %s\n", kem_algorithm_names[algorithm]);
        return -1;
    }
    
    // Verify lengths
    if (secret_key_len != kem->length_secret_key || 
        ciphertext_len != kem->length_ciphertext) {
        fprintf(stderr, "Invalid key/ciphertext lengths\n");
        OQS_KEM_free(kem);
        return -1;
    }
    
    if (*shared_secret_len < kem->length_shared_secret) {
        fprintf(stderr, "Shared secret buffer too small\n");
        OQS_KEM_free(kem);
        return -1;
    }
    
    // Perform decapsulation
    OQS_STATUS status = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    
    if (status == OQS_SUCCESS) {
        *shared_secret_len = kem->length_shared_secret;
    }
    
    OQS_KEM_free(kem);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}

/**
 * Generate PQC signature keypair
 */
int pqc_sig_keygen(pqc_sig_t algorithm, pqc_sig_keypair_t* keypair) {
    if (algorithm >= PQC_SIG_MAX || keypair == NULL) {
        return -1;
    }
    
    memset(keypair, 0, sizeof(pqc_sig_keypair_t));
    
    if (!is_sig_supported(algorithm)) {
        fprintf(stderr, "Signature algorithm %s not supported\n", sig_algorithm_names[algorithm]);
        return -1;
    }
    
    OQS_SIG* sig = OQS_SIG_new(sig_algorithm_names[algorithm]);
    if (sig == NULL) {
        fprintf(stderr, "Failed to create signature instance for %s\n", sig_algorithm_names[algorithm]);
        return -1;
    }
    
    // Allocate key buffers
    keypair->public_key = malloc(sig->length_public_key);
    keypair->secret_key = malloc(sig->length_secret_key);
    
    if (keypair->public_key == NULL || keypair->secret_key == NULL) {
        fprintf(stderr, "Failed to allocate memory for signature keys\n");
        free_pqc_sig_keypair(keypair);
        OQS_SIG_free(sig);
        return -1;
    }
    
    keypair->public_key_len = sig->length_public_key;
    keypair->secret_key_len = sig->length_secret_key;
    
    // Generate keypair
    OQS_STATUS status = OQS_SIG_keypair(sig, keypair->public_key, keypair->secret_key);
    
    OQS_SIG_free(sig);
    
    if (status != OQS_SUCCESS) {
        fprintf(stderr, "Signature key generation failed\n");
        free_pqc_sig_keypair(keypair);
        return -1;
    }
    
    return 0;
}

/**
 * PQC digital signature
 */
int pqc_sign(pqc_sig_t algorithm,
             const unsigned char* secret_key,
             size_t secret_key_len,
             const unsigned char* message,
             size_t message_len,
             unsigned char* signature,
             size_t* signature_len) {
    
    if (algorithm >= PQC_SIG_MAX || secret_key == NULL || 
        message == NULL || signature == NULL || signature_len == NULL) {
        return -1;
    }
    
    if (!is_sig_supported(algorithm)) {
        fprintf(stderr, "Signature algorithm %s not supported\n", sig_algorithm_names[algorithm]);
        return -1;
    }
    
    OQS_SIG* sig = OQS_SIG_new(sig_algorithm_names[algorithm]);
    if (sig == NULL) {
        fprintf(stderr, "Failed to create signature instance for %s\n", sig_algorithm_names[algorithm]);
        return -1;
    }
    
    // Verify secret key length
    if (secret_key_len != sig->length_secret_key) {
        fprintf(stderr, "Invalid secret key length\n");
        OQS_SIG_free(sig);
        return -1;
    }
    
    // Perform signing
    OQS_STATUS status = OQS_SIG_sign(sig, signature, signature_len, 
                                     message, message_len, secret_key);
    
    OQS_SIG_free(sig);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}

/**
 * PQC signature verification
 */
int pqc_verify(pqc_sig_t algorithm,
               const unsigned char* public_key,
               size_t public_key_len,
               const unsigned char* message,
               size_t message_len,
               const unsigned char* signature,
               size_t signature_len) {
    
    if (algorithm >= PQC_SIG_MAX || public_key == NULL || 
        message == NULL || signature == NULL) {
        return -1;
    }
    
    if (!is_sig_supported(algorithm)) {
        fprintf(stderr, "Signature algorithm %s not supported\n", sig_algorithm_names[algorithm]);
        return -1;
    }
    
    OQS_SIG* sig = OQS_SIG_new(sig_algorithm_names[algorithm]);
    if (sig == NULL) {
        fprintf(stderr, "Failed to create signature instance for %s\n", sig_algorithm_names[algorithm]);
        return -1;
    }
    
    // Verify public key length
    if (public_key_len != sig->length_public_key) {
        fprintf(stderr, "Invalid public key length\n");
        OQS_SIG_free(sig);
        return -1;
    }
    
    // Perform verification
    OQS_STATUS status = OQS_SIG_verify(sig, message, message_len, 
                                       signature, signature_len, public_key);
    
    OQS_SIG_free(sig);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}

/**
 * Free PQC KEM keypair
 */
void free_pqc_kem_keypair(pqc_kem_keypair_t* keypair) {
    if (keypair == NULL) {
        return;
    }
    
    if (keypair->public_key) {
        OQS_MEM_secure_free(keypair->public_key, keypair->public_key_len);
        keypair->public_key = NULL;
    }
    
    if (keypair->secret_key) {
        OQS_MEM_secure_free(keypair->secret_key, keypair->secret_key_len);
        keypair->secret_key = NULL;
    }
    
    keypair->public_key_len = 0;
    keypair->secret_key_len = 0;
}

/**
 * Free PQC signature keypair
 */
void free_pqc_sig_keypair(pqc_sig_keypair_t* keypair) {
    if (keypair == NULL) {
        return;
    }
    
    if (keypair->public_key) {
        OQS_MEM_secure_free(keypair->public_key, keypair->public_key_len);
        keypair->public_key = NULL;
    }
    
    if (keypair->secret_key) {
        OQS_MEM_secure_free(keypair->secret_key, keypair->secret_key_len);
        keypair->secret_key = NULL;
    }
    
    keypair->public_key_len = 0;
    keypair->secret_key_len = 0;
}

/**
 * Get PQC KEM algorithm name
 */
const char* get_pqc_kem_name(pqc_kem_t algorithm) {
    if (algorithm >= PQC_KEM_MAX) {
        return "unknown";
    }
    return kem_algorithm_names[algorithm];
}

/**
 * Get PQC signature algorithm name
 */
const char* get_pqc_sig_name(pqc_sig_t algorithm) {
    if (algorithm >= PQC_SIG_MAX) {
        return "unknown";
    }
    return sig_algorithm_names[algorithm];
}

/**
 * Get PQC KEM sizes
 */
int get_pqc_kem_sizes(pqc_kem_t algorithm, size_t* pk_len, size_t* sk_len, 
                      size_t* ct_len, size_t* ss_len) {
    if (algorithm >= PQC_KEM_MAX) {
        return -1;
    }
    
    if (!is_kem_supported(algorithm)) {
        return -1;
    }
    
    OQS_KEM* kem = OQS_KEM_new(kem_algorithm_names[algorithm]);
    if (kem == NULL) {
        return -1;
    }
    
    if (pk_len) *pk_len = kem->length_public_key;
    if (sk_len) *sk_len = kem->length_secret_key;
    if (ct_len) *ct_len = kem->length_ciphertext;
    if (ss_len) *ss_len = kem->length_shared_secret;
    
    OQS_KEM_free(kem);
    return 0;
}

/**
 * Get PQC signature sizes
 */
int get_pqc_sig_sizes(pqc_sig_t algorithm, size_t* pk_len, size_t* sk_len, size_t* sig_len) {
    if (algorithm >= PQC_SIG_MAX) {
        return -1;
    }
    
    if (!is_sig_supported(algorithm)) {
        return -1;
    }
    
    OQS_SIG* sig = OQS_SIG_new(sig_algorithm_names[algorithm]);
    if (sig == NULL) {
        return -1;
    }
    
    if (pk_len) *pk_len = sig->length_public_key;
    if (sk_len) *sk_len = sig->length_secret_key;
    if (sig_len) *sig_len = sig->length_signature;
    
    OQS_SIG_free(sig);
    return 0;
}