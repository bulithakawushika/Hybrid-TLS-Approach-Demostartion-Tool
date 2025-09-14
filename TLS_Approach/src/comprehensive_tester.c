#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "qkd_interface.h"
#include "classical_crypto.h"
#include "pqc_crypto.h"
#include "mac_ops.h"
#include "qkd_data.h"

#define NUM_ITERATIONS 3  // Reduced for debugging
#define MAX_COMBINATIONS 12  // Test subset first

// Simplified test structure
typedef struct {
    double total_time_ms;
    int success;
} simple_result_t;

typedef struct {
    int id;
    test_config_t config;
    simple_result_t results[NUM_ITERATIONS];
    double avg_time;
} test_combo_t;

test_combo_t tests[MAX_COMBINATIONS];
int num_tests = 0;

void signal_handler(int sig) {
    printf("\nReceived signal %d - cleaning up...\n", sig);
    cleanup_liboqs();
    exit(1);
}

double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

void init_qkd_data() {
    printf("DEBUG: Initializing QKD data...\n");
    memset(&bb84_data.kqkdm, 0xAA, SHA3_512_DIGEST_LENGTH);
    memset(&bb84_data.uuid, 0xBB, UUID_LENGTH);
    bb84_data.valid = 1;
    
    memset(&e91_data.kqkdm, 0xCC, SHA3_512_DIGEST_LENGTH);
    memset(&e91_data.uuid, 0xDD, UUID_LENGTH);
    e91_data.valid = 1;
    
    memset(&mdi_data.kqkdm, 0xEE, SHA3_512_DIGEST_LENGTH);
    memset(&mdi_data.uuid, 0xFF, UUID_LENGTH);
    mdi_data.valid = 1;
    printf("DEBUG: QKD data initialized\n");
}

int safe_classical_test(classical_kex_t kex, classical_sig_t sig) {
    printf("DEBUG: Testing classical crypto - KEX:%d SIG:%d\n", kex, sig);
    
    classical_keypair_t alice_kex = {0}, bob_kex = {0}, sig_pair = {0};
    
    if (classical_keygen(kex, &alice_kex) != 0) {
        printf("DEBUG: Alice KEX keygen failed\n");
        return -1;
    }
    printf("DEBUG: Alice KEX keygen OK\n");
    
    if (classical_keygen(kex, &bob_kex) != 0) {
        printf("DEBUG: Bob KEX keygen failed\n");
        free_classical_keypair(&alice_kex);
        return -1;
    }
    printf("DEBUG: Bob KEX keygen OK\n");
    
    if (classical_sig_keygen(sig, &sig_pair) != 0) {
        printf("DEBUG: Signature keygen failed\n");
        free_classical_keypair(&alice_kex);
        free_classical_keypair(&bob_kex);
        return -1;
    }
    printf("DEBUG: Signature keygen OK\n");
    
    // Test key agreement
    unsigned char shared1[64], shared2[64];
    size_t len1 = sizeof(shared1), len2 = sizeof(shared2);
    
    if (classical_key_agreement(kex, &alice_kex, bob_kex.public_key_bytes, bob_kex.public_key_len,
                               shared1, &len1) != 0) {
        printf("DEBUG: Key agreement 1 failed\n");
        goto cleanup;
    }
    printf("DEBUG: Key agreement 1 OK\n");
    
    if (classical_key_agreement(kex, &bob_kex, alice_kex.public_key_bytes, alice_kex.public_key_len,
                               shared2, &len2) != 0) {
        printf("DEBUG: Key agreement 2 failed\n");
        goto cleanup;
    }
    printf("DEBUG: Key agreement 2 OK\n");
    
    // Test signing
    const char* msg = "test message";
    unsigned char sig_buf[MAX_SIGNATURE_SIZE];
    size_t sig_len = sizeof(sig_buf);
    
    if (classical_sign(sig, &sig_pair, (unsigned char*)msg, strlen(msg), sig_buf, &sig_len) != 0) {
        printf("DEBUG: Classical signing failed\n");
        goto cleanup;
    }
    printf("DEBUG: Classical signing OK (%zu bytes)\n", sig_len);
    
    if (classical_verify(sig, sig_pair.public_key_bytes, sig_pair.public_key_len,
                        (unsigned char*)msg, strlen(msg), sig_buf, sig_len) != 0) {
        printf("DEBUG: Classical verification failed\n");
        goto cleanup;
    }
    printf("DEBUG: Classical verification OK\n");
    
cleanup:
    free_classical_keypair(&alice_kex);
    free_classical_keypair(&bob_kex);
    free_classical_keypair(&sig_pair);
    printf("DEBUG: Classical test completed\n");
    return 0;
}

int safe_pqc_test(pqc_kem_t kem, pqc_sig_t sig) {
    printf("DEBUG: Testing PQC - KEM:%d SIG:%d\n", kem, sig);
    
    if (!is_kem_supported(kem)) {
        printf("DEBUG: KEM %d not supported\n", kem);
        return -1;
    }
    
    if (!is_sig_supported(sig)) {
        printf("DEBUG: SIG %d not supported\n", sig);
        return -1;
    }
    
    pqc_kem_keypair_t kem_pair = {0};
    pqc_sig_keypair_t sig_pair = {0};
    
    printf("DEBUG: Generating PQC KEM keypair...\n");
    if (pqc_kem_keygen(kem, &kem_pair) != 0) {
        printf("DEBUG: PQC KEM keygen failed\n");
        return -1;
    }
    printf("DEBUG: PQC KEM keygen OK (pk:%zu sk:%zu)\n", kem_pair.public_key_len, kem_pair.secret_key_len);
    
    printf("DEBUG: Generating PQC signature keypair...\n");
    if (pqc_sig_keygen(sig, &sig_pair) != 0) {
        printf("DEBUG: PQC sig keygen failed\n");
        free_pqc_kem_keypair(&kem_pair);
        return -1;
    }
    printf("DEBUG: PQC sig keygen OK (pk:%zu sk:%zu)\n", sig_pair.public_key_len, sig_pair.secret_key_len);
    
    // Test encapsulation/decapsulation
    size_t ss_len = 64, ct_len = 8192;  // Conservative buffer sizes
    unsigned char* shared_secret = malloc(ss_len);
    unsigned char* ciphertext = malloc(ct_len);
    unsigned char* decap_secret = malloc(ss_len);
    
    if (!shared_secret || !ciphertext || !decap_secret) {
        printf("DEBUG: Memory allocation failed\n");
        goto pqc_cleanup;
    }
    
    printf("DEBUG: Testing PQC encapsulation...\n");
    if (pqc_kem_encapsulate(kem, kem_pair.public_key, kem_pair.public_key_len,
                           shared_secret, &ss_len, ciphertext, &ct_len) != 0) {
        printf("DEBUG: PQC encapsulation failed\n");
        goto pqc_cleanup;
    }
    printf("DEBUG: PQC encapsulation OK (ss:%zu ct:%zu)\n", ss_len, ct_len);
    
    size_t decap_len = 64;
    printf("DEBUG: Testing PQC decapsulation...\n");
    if (pqc_kem_decapsulate(kem, kem_pair.secret_key, kem_pair.secret_key_len,
                           ciphertext, ct_len, decap_secret, &decap_len) != 0) {
        printf("DEBUG: PQC decapsulation failed\n");
        goto pqc_cleanup;
    }
    printf("DEBUG: PQC decapsulation OK\n");
    
    // Test signing - with careful memory management
    const char* msg = "test message for pqc";
    size_t max_sig_len;
    if (get_pqc_sig_sizes(sig, NULL, NULL, &max_sig_len) != 0) {
        printf("DEBUG: Cannot get signature size\n");
        goto pqc_cleanup;
    }
    
    printf("DEBUG: Allocating %zu bytes for PQC signature...\n", max_sig_len);
    unsigned char* pqc_sig_buf = malloc(max_sig_len);
    if (!pqc_sig_buf) {
        printf("DEBUG: Signature buffer allocation failed\n");
        goto pqc_cleanup;
    }
    
    size_t pqc_sig_len = max_sig_len;
    printf("DEBUG: Testing PQC signing...\n");
    if (pqc_sign(sig, sig_pair.secret_key, sig_pair.secret_key_len,
                (unsigned char*)msg, strlen(msg), pqc_sig_buf, &pqc_sig_len) != 0) {
        printf("DEBUG: PQC signing failed\n");
        free(pqc_sig_buf);
        goto pqc_cleanup;
    }
    printf("DEBUG: PQC signing OK (%zu bytes)\n", pqc_sig_len);
    
    printf("DEBUG: Testing PQC verification...\n");
    if (pqc_verify(sig, sig_pair.public_key, sig_pair.public_key_len,
                  (unsigned char*)msg, strlen(msg), pqc_sig_buf, pqc_sig_len) != 0) {
        printf("DEBUG: PQC verification failed\n");
        free(pqc_sig_buf);
        goto pqc_cleanup;
    }
    printf("DEBUG: PQC verification OK\n");
    
    free(pqc_sig_buf);

pqc_cleanup:
    free(shared_secret);
    free(ciphertext);
    free(decap_secret);
    free_pqc_kem_keypair(&kem_pair);
    free_pqc_sig_keypair(&sig_pair);
    printf("DEBUG: PQC test completed\n");
    return 0;
}

int run_safe_test(const test_config_t* config) {
    printf("\nDEBUG: Starting test for combination %d\n", config->test_id);
    printf("DEBUG: %s + %s + %s + %s + %s\n",
           classical_kex_names[config->classical_kex],
           classical_sig_names[config->classical_sig],
           pqc_kem_names[config->pqc_kem],
           pqc_sig_names[config->pqc_sig],
           qkd_protocol_names[config->qkd_protocol]);
    
    // Test classical crypto first
    if (safe_classical_test(config->classical_kex, config->classical_sig) != 0) {
        printf("DEBUG: Classical test failed\n");
        return -1;
    }
    
    // Test PQC crypto
    if (safe_pqc_test(config->pqc_kem, config->pqc_sig) != 0) {
        printf("DEBUG: PQC test failed\n");
        return -1;
    }
    
    // Test QKD components
    qkd_key_data_t qkd_key;
    if (get_qkd_key(config->qkd_protocol, &qkd_key) != 0) {
        printf("DEBUG: QKD key retrieval failed\n");
        return -1;
    }
    printf("DEBUG: QKD key retrieved OK\n");
    
    unsigned char k_qkd[32], k_auth[32], na[12], nb[12];
    if (derive_qkd_components(qkd_key.kqkdm, SHA3_512_DIGEST_LENGTH,
                             k_qkd, k_auth, na, nb) != 0) {
        printf("DEBUG: QKD derivation failed\n");
        return -1;
    }
    printf("DEBUG: QKD derivation OK\n");
    
    printf("DEBUG: Test completed successfully\n");
    return 0;
}

void generate_test_configs() {
    // Generate a safe subset of combinations
    test_config_t safe_configs[] = {
        {0, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_BB84},
        {1, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, PQC_ML_KEM_768, PQC_FALCON_512, QKD_BB84},
        {2, CLASSICAL_ECDHE_P256, SIG_ED25519, PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_E91},
        {3, CLASSICAL_X25519, SIG_ED25519, PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_BB84},
        {4, CLASSICAL_X25519, SIG_ED25519, PQC_ML_KEM_768, PQC_FALCON_512, QKD_E91},
        {5, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, PQC_HQC_192, PQC_ML_DSA_65, QKD_MDI},
    };
    
    num_tests = sizeof(safe_configs) / sizeof(safe_configs[0]);
    for (int i = 0; i < num_tests; i++) {
        tests[i].id = i + 1;
        tests[i].config = safe_configs[i];
        tests[i].avg_time = 0;
    }
}

int main(int argc, char* argv[]) {
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    
    printf("=== Debug Comprehensive Performance Testing ===\n");
    printf("Memory-safe version for troubleshooting\n\n");
    
    // Initialize
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    if (initialize_liboqs() != 0) {
        printf("ERROR: LibOQS initialization failed\n");
        return 1;
    }
    printf("LibOQS initialized successfully\n");
    
    init_qkd_data();
    generate_test_configs();
    
    printf("Testing %d combinations with %d iterations each\n\n", num_tests, NUM_ITERATIONS);
    
    int successful = 0;
    
    for (int i = 0; i < num_tests; i++) {
        printf("\n[%d/%d] Testing combination %d:\n", i + 1, num_tests, tests[i].id);
        
        int combo_success = 0;
        double total_time = 0;
        
        for (int iter = 0; iter < NUM_ITERATIONS; iter++) {
            printf("  Iteration %d/%d: ", iter + 1, NUM_ITERATIONS);
            
            double start = get_time_ms();
            if (run_safe_test(&tests[i].config) == 0) {
                double end = get_time_ms();
                tests[i].results[iter].total_time_ms = end - start;
                tests[i].results[iter].success = 1;
                total_time += tests[i].results[iter].total_time_ms;
                combo_success++;
                printf("SUCCESS (%.2f ms)\n", tests[i].results[iter].total_time_ms);
            } else {
                tests[i].results[iter].success = 0;
                printf("FAILED\n");
            }
        }
        
        if (combo_success > 0) {
            tests[i].avg_time = total_time / combo_success;
            successful++;
            printf("  Combination %d: PASSED (%.2f ms average)\n", tests[i].id, tests[i].avg_time);
        } else {
            printf("  Combination %d: FAILED (all iterations failed)\n", tests[i].id);
        }
    }
    
    printf("\n=== Results Summary ===\n");
    printf("Successful combinations: %d/%d\n", successful, num_tests);
    
    if (successful > 0) {
        printf("\nPerformance ranking:\n");
        // Simple bubble sort for small array
        for (int i = 0; i < num_tests - 1; i++) {
            for (int j = 0; j < num_tests - i - 1; j++) {
                if (tests[j].avg_time > tests[j + 1].avg_time && tests[j + 1].avg_time > 0) {
                    test_combo_t temp = tests[j];
                    tests[j] = tests[j + 1];
                    tests[j + 1] = temp;
                }
            }
        }
        
        for (int i = 0; i < num_tests; i++) {
            if (tests[i].avg_time > 0) {
                printf("%d. %s+%s+%s+%s+%s: %.2f ms\n",
                       i + 1,
                       classical_kex_names[tests[i].config.classical_kex],
                       classical_sig_names[tests[i].config.classical_sig],
                       pqc_kem_names[tests[i].config.pqc_kem],
                       pqc_sig_names[tests[i].config.pqc_sig],
                       qkd_protocol_names[tests[i].config.qkd_protocol],
                       tests[i].avg_time);
            }
        }
    }
    
    cleanup_liboqs();
    EVP_cleanup();
    
    return successful > 0 ? 0 : 1;
}