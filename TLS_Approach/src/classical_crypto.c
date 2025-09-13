#include "classical_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

/**
 * Generate classical keypair based on algorithm type
 */
int classical_keygen(classical_kex_t type, classical_keypair_t* keypair) {
    if (keypair == NULL) {
        return -1;
    }
    
    memset(keypair, 0, sizeof(classical_keypair_t));
    
    EVP_PKEY_CTX* ctx = NULL;
    int ret = -1;
    
    switch (type) {
        case CLASSICAL_ECDHE_P256:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (ctx == NULL) goto cleanup;
            
            if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) goto cleanup;
            if (EVP_PKEY_keygen(ctx, &keypair->keypair) <= 0) goto cleanup;
            break;
            
        case CLASSICAL_ECDHE_P384:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (ctx == NULL) goto cleanup;
            
            if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) <= 0) goto cleanup;
            if (EVP_PKEY_keygen(ctx, &keypair->keypair) <= 0) goto cleanup;
            break;
            
        case CLASSICAL_X25519:
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
            if (ctx == NULL) goto cleanup;
            
            if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
            if (EVP_PKEY_keygen(ctx, &keypair->keypair) <= 0) goto cleanup;
            break;
            
        default:
            fprintf(stderr, "Unsupported classical key exchange type: %d\n", type);
            goto cleanup;
    }
    
    // Export public key
    if (export_public_key(keypair, &keypair->public_key_bytes, &keypair->public_key_len) != 0) {
        goto cleanup;
    }
    
    ret = 0;
    
cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    
    if (ret != 0 && keypair) {
        free_classical_keypair(keypair);
    }
    
    return ret;
}

/**
 * Perform classical key agreement
 */
int classical_key_agreement(classical_kex_t type, 
                           const classical_keypair_t* my_keypair,
                           const unsigned char* their_public_key, 
                           size_t their_public_key_len,
                           unsigned char* shared_secret, 
                           size_t* shared_secret_len) {
    
    if (my_keypair == NULL || their_public_key == NULL || shared_secret == NULL || shared_secret_len == NULL) {
        return -1;
    }
    
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* peer_key = NULL;
    int ret = -1;
    
    // Import peer's public key
    const unsigned char* p = their_public_key;
    peer_key = d2i_PUBKEY(NULL, &p, their_public_key_len);
    if (peer_key == NULL) {
        fprintf(stderr, "Failed to import peer's public key\n");
        goto cleanup;
    }
    
    // Create key agreement context
    ctx = EVP_PKEY_CTX_new(my_keypair->keypair, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create key agreement context\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key derivation\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        fprintf(stderr, "Failed to set peer key\n");
        goto cleanup;
    }
    
    // Derive shared secret
    if (EVP_PKEY_derive(ctx, shared_secret, shared_secret_len) <= 0) {
        fprintf(stderr, "Failed to derive shared secret\n");
        goto cleanup;
    }
    
    ret = 0;
    
cleanup:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (peer_key) {
        EVP_PKEY_free(peer_key);
    }
    
    return ret;
}

/**
 * Classical digital signature
 */
int classical_sign(classical_sig_t type, 
                  const classical_keypair_t* keypair,
                  const unsigned char* message, 
                  size_t msg_len,
                  unsigned char* signature, 
                  size_t* sig_len) {
    
    if (keypair == NULL || message == NULL || signature == NULL || sig_len == NULL) {
        return -1;
    }
    
    EVP_MD_CTX* ctx = NULL;
    const EVP_MD* md = NULL;
    int ret = -1;
    
    // Select hash function based on signature type
    switch (type) {
        case SIG_ECDSA_P256:
            md = EVP_sha256();
            break;
        case SIG_ECDSA_P384:
            md = EVP_sha384();
            break;
        case SIG_ED25519:
            md = NULL; // Ed25519 uses its own hash internally
            break;
        default:
            fprintf(stderr, "Unsupported signature type: %d\n", type);
            return -1;
    }
    
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create signature context\n");
        goto cleanup;
    }
    
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, keypair->keypair) <= 0) {
        fprintf(stderr, "Failed to initialize signature\n");
        goto cleanup;
    }
    
    if (EVP_DigestSign(ctx, signature, sig_len, message, msg_len) <= 0) {
        fprintf(stderr, "Failed to sign message\n");
        goto cleanup;
    }
    
    ret = 0;
    
cleanup:
    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }
    
    return ret;
}

/**
 * Classical signature verification
 */
int classical_verify(classical_sig_t type,
                    const unsigned char* public_key,
                    size_t public_key_len,
                    const unsigned char* message,
                    size_t msg_len,
                    const unsigned char* signature,
                    size_t sig_len) {
    
    if (public_key == NULL || message == NULL || signature == NULL) {
        return -1;
    }
    
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;
    const EVP_MD* md = NULL;
    int ret = -1;
    
    // Import public key
    const unsigned char* p = public_key;
    pkey = d2i_PUBKEY(NULL, &p, public_key_len);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to import public key for verification\n");
        goto cleanup;
    }
    
    // Select hash function
    switch (type) {
        case SIG_ECDSA_P256:
            md = EVP_sha256();
            break;
        case SIG_ECDSA_P384:
            md = EVP_sha384();
            break;
        case SIG_ED25519:
            md = NULL;
            break;
        default:
            fprintf(stderr, "Unsupported signature type: %d\n", type);
            goto cleanup;
    }
    
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create verification context\n");
        goto cleanup;
    }
    
    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) <= 0) {
        fprintf(stderr, "Failed to initialize verification\n");
        goto cleanup;
    }
    
    int verify_result = EVP_DigestVerify(ctx, signature, sig_len, message, msg_len);
    if (verify_result == 1) {
        ret = 0; // Verification successful
    } else if (verify_result == 0) {
        fprintf(stderr, "Signature verification failed\n");
        ret = -2; // Verification failed
    } else {
        fprintf(stderr, "Signature verification error\n");
        ret = -1; // Error during verification
    }
    
cleanup:
    if (ctx) {
        EVP_MD_CTX_free(ctx);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    
    return ret;
}

/**
 * Free classical keypair resources
 */
void free_classical_keypair(classical_keypair_t* keypair) {
    if (keypair == NULL) {
        return;
    }
    
    if (keypair->keypair) {
        EVP_PKEY_free(keypair->keypair);
        keypair->keypair = NULL;
    }
    
    if (keypair->public_key_bytes) {
        OPENSSL_free(keypair->public_key_bytes);
        keypair->public_key_bytes = NULL;
    }
    
    if (keypair->private_key_bytes) {
        OPENSSL_free(keypair->private_key_bytes);
        keypair->private_key_bytes = NULL;
    }
    
    keypair->public_key_len = 0;
    keypair->private_key_len = 0;
}

/**
 * Export public key in DER format
 */
int export_public_key(const classical_keypair_t* keypair, 
                     unsigned char** public_key, 
                     size_t* public_key_len) {
    
    if (keypair == NULL || keypair->keypair == NULL || public_key == NULL || public_key_len == NULL) {
        return -1;
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return -1;
    }
    
    if (i2d_PUBKEY_bio(bio, keypair->keypair) != 1) {
        BIO_free(bio);
        return -1;
    }
    
    long len = BIO_get_mem_data(bio, public_key);
    if (len <= 0) {
        BIO_free(bio);
        return -1;
    }
    
    // Allocate and copy the key data
    *public_key = OPENSSL_malloc(len);
    if (*public_key == NULL) {
        BIO_free(bio);
        return -1;
    }
    
    BIO_read(bio, *public_key, len);
    *public_key_len = len;
    
    BIO_free(bio);
    return 0;
}

/**
 * Get curve name for display purposes
 */
const char* get_classical_curve_name(classical_kex_t type) {
    switch (type) {
        case CLASSICAL_ECDHE_P256:
            return "prime256v1";
        case CLASSICAL_ECDHE_P384:
            return "secp384r1";
        case CLASSICAL_X25519:
            return "X25519";
        default:
            return "unknown";
    }
}

/**
 * Get expected shared secret length
 */
int get_expected_shared_secret_len(classical_kex_t type) {
    switch (type) {
        case CLASSICAL_ECDHE_P256:
            return 32; // 256 bits
        case CLASSICAL_ECDHE_P384:
            return 48; // 384 bits
        case CLASSICAL_X25519:
            return 32; // 256 bits
        default:
            return -1;
    }
}