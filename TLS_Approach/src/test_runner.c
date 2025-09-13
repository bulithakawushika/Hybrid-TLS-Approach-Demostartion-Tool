#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "qkd_interface.h"
#include "classical_crypto.h"
#include "pqc_crypto.h"
#include "mac_ops.h"

// External QKD key data from stage.c
qkd_key_data_t bb84_data = {0};
qkd_key_data_t e91_data = {0};
qkd_key_data_t mdi_data = {0};

/**
 * Get current time in microseconds
 */
double get_time_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000.0 + tv.tv_usec;
}

/**
 * Initialize mock QKD data for testing
 */
void initialize_mock_qkd_data() {
    // Mock BB84 data
    memset(&bb84_data.kqkdm, 0xAA, SHA3_512_DIGEST_LENGTH);
    memset(&bb84_data.uuid, 0xBB, UUID_LENGTH);
    bb84_data.valid = 1;
    
    // Mock E91 data
    memset(&e91_data.kqkdm, 0xCC, SHA3_512_DIGEST_LENGTH);
    memset(&e91_data.uuid, 0xDD, UUID_LENGTH);
    e91_data.valid = 1;
    
    // Mock MDI data
    memset(&mdi_data.kqkdm, 0xEE, SHA3_512_DIGEST_LENGTH);
    memset(&mdi_data.uuid, 0xFF, UUID_LENGTH);
    mdi_data.valid = 1;
    
    printf("Mock QKD data initialized successfully\n");
}

/**
 * Test classical cryptography operations
 */
int test_classical_operations(const test_config_t* config, performance_metrics_t* metrics) {
    printf("  Testing classical operations...\n");
    
    classical_keypair_t alice_keypair = {0};
    classical_keypair_t bob_keypair = {0};
    classical_keypair_t sig_keypair = {0};
    unsigned char shared_secret_alice[64] = {0};
    unsigned char shared_secret_bob[64] = {0};
    size_t shared_secret_len_alice = sizeof(shared_secret_alice);
    size_t shared_secret_len_bob = sizeof(shared_secret_bob);
    
    double start_time, end_time;
    
    // Test classical key generation for key exchange
    printf("    Generating %s keypairs...\n", classical_kex_names[config->classical_kex]);
    
    start_time = get_time_us();
    if (classical_keygen(config->classical_kex, &alice_keypair) != 0) {
        fprintf(stderr, "    Failed to generate Alice's classical keypair\n");
        return -1;
    }
    
    if (classical_keygen(config->classical_kex, &bob_keypair) != 0) {
        fprintf(stderr, "    Failed to generate Bob's classical keypair\n");
        free_classical_keypair(&alice_keypair);
        return -1;
    }
    end_time = get_time_us();
    metrics->classical_keygen_time = (end_time - start_time) / 1000.0;
    
    printf("    Classical key generation: %.3f ms\n", metrics->classical_keygen_time);
    
    // Test key agreement
    printf("    Testing %s key agreement...\n", classical_kex_names[config->classical_kex]);
    
    if (classical_key_agreement(config->classical_kex, &alice_keypair, 
                               bob_keypair.public_key_bytes, bob_keypair.public_key_len,
                               shared_secret_alice, &shared_secret_len_alice) != 0) {
        fprintf(stderr, "    Alice's key agreement failed\n");
        free_classical_keypair(&alice_keypair);
        free_classical_keypair(&bob_keypair);
        return -1;
    }
    
    if (classical_key_agreement(config->classical_kex, &bob_keypair,
                               alice_keypair.public_key_bytes, alice_keypair.public_key_len,
                               shared_secret_bob, &shared_secret_len_bob) != 0) {
        fprintf(stderr, "    Bob's key agreement failed\n");
        free_classical_keypair(&alice_keypair);
        free_classical_keypair(&bob_keypair);
        return -1;
    }
    
    // Verify shared secrets match
    if (shared_secret_len_alice != shared_secret_len_bob ||
        memcmp(shared_secret_alice, shared_secret_bob, shared_secret_len_alice) != 0) {
        fprintf(stderr, "    Shared secrets don't match!\n");
        free_classical_keypair(&alice_keypair);
        free_classical_keypair(&bob_keypair);
        return -1;
    }
    
    printf("    Key agreement successful! Shared secret length: %zu bytes\n", shared_secret_len_alice);
    
    // Test digital signatures - generate separate signature keypair
    printf("    Testing %s signatures...\n", classical_sig_names[config->classical_sig]);
    
    if (classical_sig_keygen(config->classical_sig, &sig_keypair) != 0) {
        fprintf(stderr, "    Failed to generate signature keypair\n");
        free_classical_keypair(&alice_keypair);
        free_classical_keypair(&bob_keypair);
        return -1;
    }
    
    const unsigned char test_message[] = "This is a test message for hybrid TLS";
    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t signature_len = sizeof(signature);
    
    start_time = get_time_us();
    if (classical_sign(config->classical_sig, &sig_keypair, 
                      test_message, sizeof(test_message) - 1,
                      signature, &signature_len) != 0) {
        fprintf(stderr, "    Classical signature generation failed\n");
        free_classical_keypair(&alice_keypair);
        free_classical_keypair(&bob_keypair);
        free_classical_keypair(&sig_keypair);
        return -1;
    }
    end_time = get_time_us();
    metrics->classical_sign_time = (end_time - start_time) / 1000.0;
    
    start_time = get_time_us();
    int verify_result = classical_verify(config->classical_sig,
                                        sig_keypair.public_key_bytes, sig_keypair.public_key_len,
                                        test_message, sizeof(test_message) - 1,
                                        signature, signature_len);
    end_time = get_time_us();
    metrics->classical_verify_time = (end_time - start_time) / 1000.0;
    
    if (verify_result != 0) {
        fprintf(stderr, "    Classical signature verification failed (code: %d)\n", verify_result);
        free_classical_keypair(&alice_keypair);
        free_classical_keypair(&bob_keypair);
        free_classical_keypair(&sig_keypair);
        return -1;
    }
    
    printf("    Classical signature: %.3f ms, verification: %.3f ms\n", 
           metrics->classical_sign_time, metrics->classical_verify_time);
    
    // Cleanup
    free_classical_keypair(&alice_keypair);
    free_classical_keypair(&bob_keypair);
    free_classical_keypair(&sig_keypair);
    
    printf("    Classical operations completed successfully\n");
    return 0;
}

/**
 * Test Post-Quantum Cryptography operations
 */
int test_pqc_operations(const test_config_t* config, performance_metrics_t* metrics) {
    printf("  Testing PQC operations...\n");
    
    // Test PQC KEM operations
    printf("    Testing %s KEM...\n", pqc_kem_names[config->pqc_kem]);
    
    if (!is_kem_supported(config->pqc_kem)) {
        fprintf(stderr, "    KEM algorithm %s not supported in this LibOQS build\n", 
                pqc_kem_names[config->pqc_kem]);
        return -1;
    }
    
    pqc_kem_keypair_t kem_keypair = {0};
    double start_time, end_time;
    
    // Generate KEM keypair
    start_time = get_time_us();
    if (pqc_kem_keygen(config->pqc_kem, &kem_keypair) != 0) {
        fprintf(stderr, "    Failed to generate PQC KEM keypair\n");
        return -1;
    }
    end_time = get_time_us();
    metrics->pqc_keygen_time = (end_time - start_time) / 1000.0;
    
    printf("    PQC KEM key generation: %.3f ms\n", metrics->pqc_keygen_time);
    printf("    Public key size: %zu bytes, Secret key size: %zu bytes\n",
           kem_keypair.public_key_len, kem_keypair.secret_key_len);
    
    // Allocate buffers based on actual algorithm requirements
    size_t max_shared_secret_len, max_ciphertext_len;
    if (get_pqc_kem_sizes(config->pqc_kem, NULL, NULL, &max_ciphertext_len, &max_shared_secret_len) != 0) {
        fprintf(stderr, "    Failed to get KEM algorithm sizes\n");
        free_pqc_kem_keypair(&kem_keypair);
        return -1;
    }
    
    // Allocate buffers with proper sizes
    unsigned char* shared_secret_encap = malloc(max_shared_secret_len);
    unsigned char* ciphertext = malloc(max_ciphertext_len);
    unsigned char* shared_secret_decap = malloc(max_shared_secret_len);
    
    if (shared_secret_encap == NULL || ciphertext == NULL || shared_secret_decap == NULL) {
        fprintf(stderr, "    Failed to allocate KEM buffers\n");
        free(shared_secret_encap);
        free(ciphertext);
        free(shared_secret_decap);
        free_pqc_kem_keypair(&kem_keypair);
        return -1;
    }
    
    size_t shared_secret_len = max_shared_secret_len;
    size_t ciphertext_len = max_ciphertext_len;
    
    // Test encapsulation
    start_time = get_time_us();
    if (pqc_kem_encapsulate(config->pqc_kem, 
                           kem_keypair.public_key, kem_keypair.public_key_len,
                           shared_secret_encap, &shared_secret_len,
                           ciphertext, &ciphertext_len) != 0) {
        fprintf(stderr, "    PQC KEM encapsulation failed\n");
        free(shared_secret_encap);
        free(ciphertext);
        free(shared_secret_decap);
        free_pqc_kem_keypair(&kem_keypair);
        return -1;
    }
    end_time = get_time_us();
    metrics->pqc_encap_time = (end_time - start_time) / 1000.0;
    
    // Test decapsulation
    size_t shared_secret_decap_len = max_shared_secret_len;
    
    start_time = get_time_us();
    if (pqc_kem_decapsulate(config->pqc_kem,
                           kem_keypair.secret_key, kem_keypair.secret_key_len,
                           ciphertext, ciphertext_len,
                           shared_secret_decap, &shared_secret_decap_len) != 0) {
        fprintf(stderr, "    PQC KEM decapsulation failed\n");
        free(shared_secret_encap);
        free(ciphertext);
        free(shared_secret_decap);
        free_pqc_kem_keypair(&kem_keypair);
        return -1;
    }
    end_time = get_time_us();
    metrics->pqc_decap_time = (end_time - start_time) / 1000.0;
    
    // Verify shared secrets match
    if (shared_secret_len != shared_secret_decap_len ||
        memcmp(shared_secret_encap, shared_secret_decap, shared_secret_len) != 0) {
        fprintf(stderr, "    PQC KEM shared secrets don't match!\n");
        free(shared_secret_encap);
        free(ciphertext);
        free(shared_secret_decap);
        free_pqc_kem_keypair(&kem_keypair);
        return -1;
    }
    
    printf("    PQC KEM encap: %.3f ms, decap: %.3f ms\n", 
           metrics->pqc_encap_time, metrics->pqc_decap_time);
    printf("    Shared secret length: %zu bytes, Ciphertext length: %zu bytes\n",
           shared_secret_len, ciphertext_len);
    
    // Cleanup KEM buffers
    free(shared_secret_encap);
    free(ciphertext);
    free(shared_secret_decap);
    
    // Test PQC signatures
    printf("    Testing %s signatures...\n", pqc_sig_names[config->pqc_sig]);
    
    if (!is_sig_supported(config->pqc_sig)) {
        fprintf(stderr, "    Signature algorithm %s not supported in this LibOQS build\n", 
                pqc_sig_names[config->pqc_sig]);
        free_pqc_kem_keypair(&kem_keypair);
        return -1;
    }
    
    pqc_sig_keypair_t sig_keypair = {0};
    
    // Generate signature keypair
    if (pqc_sig_keygen(config->pqc_sig, &sig_keypair) != 0) {
        fprintf(stderr, "    Failed to generate PQC signature keypair\n");
        free_pqc_kem_keypair(&kem_keypair);
        return -1;
    }
    
    // Get signature size for buffer allocation
    size_t max_sig_len;
    if (get_pqc_sig_sizes(config->pqc_sig, NULL, NULL, &max_sig_len) != 0) {
        fprintf(stderr, "    Failed to get signature algorithm sizes\n");
        free_pqc_kem_keypair(&kem_keypair);
        free_pqc_sig_keypair(&sig_keypair);
        return -1;
    }
    
    // Allocate signature buffer on heap to handle large signatures
    unsigned char* pqc_signature = malloc(max_sig_len);
    if (pqc_signature == NULL) {
        fprintf(stderr, "    Failed to allocate signature buffer (%zu bytes)\n", max_sig_len);
        free_pqc_kem_keypair(&kem_keypair);
        free_pqc_sig_keypair(&sig_keypair);
        return -1;
    }
    
    const unsigned char test_message[] = "This is a test message for PQC signatures";
    size_t pqc_signature_len = max_sig_len;
    
    // Test signing
    start_time = get_time_us();
    if (pqc_sign(config->pqc_sig,
                sig_keypair.secret_key, sig_keypair.secret_key_len,
                test_message, sizeof(test_message) - 1,
                pqc_signature, &pqc_signature_len) != 0) {
        fprintf(stderr, "    PQC signature generation failed\n");
        free(pqc_signature);
        free_pqc_kem_keypair(&kem_keypair);
        free_pqc_sig_keypair(&sig_keypair);
        return -1;
    }
    end_time = get_time_us();
    metrics->pqc_sign_time = (end_time - start_time) / 1000.0;
    
    // Test verification
    start_time = get_time_us();
    if (pqc_verify(config->pqc_sig,
                  sig_keypair.public_key, sig_keypair.public_key_len,
                  test_message, sizeof(test_message) - 1,
                  pqc_signature, pqc_signature_len) != 0) {
        fprintf(stderr, "    PQC signature verification failed\n");
        free(pqc_signature);
        free_pqc_kem_keypair(&kem_keypair);
        free_pqc_sig_keypair(&sig_keypair);
        return -1;
    }
    end_time = get_time_us();
    metrics->pqc_verify_time = (end_time - start_time) / 1000.0;
    
    printf("    PQC signature: %.3f ms, verification: %.3f ms\n", 
           metrics->pqc_sign_time, metrics->pqc_verify_time);
    printf("    Signature size: %zu bytes\n", pqc_signature_len);
    
    // Cleanup
    free(pqc_signature);
    free_pqc_kem_keypair(&kem_keypair);
    free_pqc_sig_keypair(&sig_keypair);
    
    printf("    PQC operations completed successfully\n");
    return 0;
}

/**
 * Test QKD key derivation and MAC operations
 */
int test_qkd_and_mac_operations(const test_config_t* config, performance_metrics_t* metrics) {
    printf("  Testing QKD and MAC operations...\n");
    
    qkd_key_data_t qkd_key;
    unsigned char k_qkd[32], k_auth[32], na[12], nb[12];
    double start_time, end_time;
    
    // Get QKD key
    if (get_qkd_key(config->qkd_protocol, &qkd_key) != 0) {
        fprintf(stderr, "    Failed to get %s key\n", qkd_protocol_names[config->qkd_protocol]);
        return -1;
    }
    
    printf("    Using %s protocol\n", qkd_protocol_names[config->qkd_protocol]);
    
    // Test key derivation
    start_time = get_time_us();
    if (derive_qkd_components(qkd_key.kqkdm, SHA3_512_DIGEST_LENGTH,
                             k_qkd, k_auth, na, nb) != 0) {
        fprintf(stderr, "    QKD key derivation failed\n");
        return -1;
    }
    end_time = get_time_us();
    metrics->qkd_derive_time = (end_time - start_time) / 1000.0;
    
    printf("    QKD key derivation: %.3f ms\n", metrics->qkd_derive_time);
    
    // Test MAC operations with derived keys
    const unsigned char test_message[] = "Test message for MAC operations";
    unsigned char mac[POLY1305_TAG_SIZE];
    
    start_time = get_time_us();
    if (poly1305_generate_mac(k_auth, na, test_message, sizeof(test_message) - 1, mac) != MAC_SUCCESS) {
        fprintf(stderr, "    MAC generation failed\n");
        return -1;
    }
    end_time = get_time_us();
    metrics->mac_compute_time = (end_time - start_time) / 1000.0;
    
    start_time = get_time_us();
    if (poly1305_verify_mac(k_auth, na, test_message, sizeof(test_message) - 1, mac) != MAC_SUCCESS) {
        fprintf(stderr, "    MAC verification failed\n");
        return -1;
    }
    end_time = get_time_us();
    metrics->mac_verify_time = (end_time - start_time) / 1000.0;
    
    printf("    MAC generation: %.3f ms, verification: %.3f ms\n", 
           metrics->mac_compute_time, metrics->mac_verify_time);
    printf("    Derived k_qkd: ");
    for (int i = 0; i < 8; i++) printf("%02x", k_qkd[i]);
    printf("...\n");
    printf("    MAC: ");
    print_mac_hex(mac);
    printf("\n");
    
    printf("    QKD and MAC operations completed successfully\n");
    return 0;
}

/**
 * Run a single test case
 */
int run_single_test(const test_config_t* config) {
    performance_metrics_t metrics = {0};
    double total_start_time, total_end_time;
    
    printf("\n=== Running %s ===\n", get_test_description(config));
    
    total_start_time = get_time_us();
    
    // Test classical operations
    if (test_classical_operations(config, &metrics) != 0) {
        printf("❌ Test %d FAILED: Classical operations\n", config->test_id);
        return -1;
    }
    
    // Test PQC operations
    if (test_pqc_operations(config, &metrics) != 0) {
        printf("❌ Test %d FAILED: PQC operations\n", config->test_id);
        return -1;
    }
    
    // Test QKD and MAC operations
    if (test_qkd_and_mac_operations(config, &metrics) != 0) {
        printf("❌ Test %d FAILED: QKD/MAC operations\n", config->test_id);
        return -1;
    }
    
    total_end_time = get_time_us();
    metrics.total_handshake_time = (total_end_time - total_start_time) / 1000.0;
    
    printf("✅ Test %d PASSED (%.3f ms total)\n", config->test_id, metrics.total_handshake_time);
    
    return 0;
}

/**
 * Run subset of tests for initial validation
 */
int run_basic_test_suite() {
    printf("=== Running Basic Test Suite ===\n");
    
    // Test one configuration from each category
    test_config_t basic_tests[] = {
        {0, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_BB84},
        {1, CLASSICAL_ECDHE_P384, SIG_ECDSA_P384, PQC_HQC_192, PQC_FALCON_512, QKD_E91},
        {2, CLASSICAL_X25519, SIG_ED25519, PQC_BIKE_L3, PQC_SPHINCS_SHA2_192F, QKD_MDI}
    };
    
    int passed = 0;
    int total = sizeof(basic_tests) / sizeof(basic_tests[0]);
    
    for (int i = 0; i < total; i++) {
        if (run_single_test(&basic_tests[i]) == 0) {
            passed++;
        }
    }
    
    printf("\n=== Basic Test Results ===\n");
    printf("Passed: %d/%d tests\n", passed, total);
    
    return (passed == total) ? 0 : -1;
}

/**
 * Main function
 */
int main(int argc, char* argv[]) {
    // Suppress unused parameter warnings
    (void)argc;
    (void)argv;
    
    printf("=== Hybrid TLS Test Framework ===\n");
    printf("Testing combinations of Classical + PQC + QKD cryptography\n\n");
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Initialize LibOQS
    if (initialize_liboqs() != 0) {
        fprintf(stderr, "Failed to initialize LibOQS\n");
        return 1;
    }
    
    // Initialize mock QKD data
    initialize_mock_qkd_data();
    
    // Check QKD availability
    if (check_qkd_availability() != 0) {
        fprintf(stderr, "Warning: Not all QKD keys are available\n");
    }
    
    // Parse command line arguments
    if (argc > 1 && strcmp(argv[1], "--full") == 0) {
        // Run full test matrix (all 108 combinations)
        test_config_t* all_tests = malloc(calculate_total_combinations() * sizeof(test_config_t));
        if (all_tests == NULL) {
            fprintf(stderr, "Failed to allocate memory for test matrix\n");
            cleanup_liboqs();
            return 1;
        }
        
        int total_tests;
        generate_test_matrix(all_tests, &total_tests);
        
        printf("Generated %d test combinations\n", total_tests);
        printf("Warning: Full test suite will take significant time!\n");
        
        int passed = 0;
        for (int i = 0; i < total_tests; i++) {
            if (run_single_test(&all_tests[i]) == 0) {
                passed++;
            }
        }
        
        printf("\n=== Full Test Results ===\n");
        printf("Passed: %d/%d tests\n", passed, total_tests);
        
        free(all_tests);
        cleanup_liboqs();
        return (passed == total_tests) ? 0 : 1;
    } else {
        // Run basic test suite
        int result = run_basic_test_suite();
        cleanup_liboqs();
        return result == 0 ? 0 : 1;
    }
}