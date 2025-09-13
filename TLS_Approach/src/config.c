#include "config.h"
#include <stdio.h>
#include <string.h>

// Algorithm name mappings for display
const char* classical_kex_names[CLASSICAL_MAX] = {
    "ECDHE-P256",
    "ECDHE-P384", 
    "X25519"
};

const char* classical_sig_names[SIG_MAX] = {
    "ECDSA-P256",
    "ECDSA-P384",
    "Ed25519"
};

const char* pqc_kem_names[PQC_KEM_MAX] = {
    "ML-KEM-768",
    "HQC-192",
    "BIKE-L3"
};

const char* pqc_sig_names[PQC_SIG_MAX] = {
    "ML-DSA-65",
    "Falcon-512",
    "SPHINCS+-SHA2-192f-simple",
    "SPHINCS+-SHAKE-192f-simple"
};

const char* qkd_protocol_names[QKD_MAX] = {
    "BB84",
    "E91", 
    "MDI-QKD"
};

// LibOQS algorithm name mappings
const char* liboqs_kem_names[PQC_KEM_MAX] = {
    "ML-KEM-768",
    "HQC-192",
    "BIKE-L3"
};

const char* liboqs_sig_names[PQC_SIG_MAX] = {
    "ML-DSA-65",
    "Falcon-512",
    "SPHINCS+-SHA2-192f-simple",
    "SPHINCS+-SHAKE-192f-simple"
};

/**
 * Generate all possible test combinations
 */
void generate_test_matrix(test_config_t* tests, int* total_tests) {
    int test_id = 0;
    
    for (int c_kex = 0; c_kex < CLASSICAL_MAX; c_kex++) {
        for (int c_sig = 0; c_sig < SIG_MAX; c_sig++) {
            for (int pqc_kem = 0; pqc_kem < PQC_KEM_MAX; pqc_kem++) {
                for (int pqc_sig = 0; pqc_sig < PQC_SIG_MAX; pqc_sig++) {
                    for (int qkd = 0; qkd < QKD_MAX; qkd++) {
                        tests[test_id].test_id = test_id;
                        tests[test_id].classical_kex = c_kex;
                        tests[test_id].classical_sig = c_sig;
                        tests[test_id].pqc_kem = pqc_kem;
                        tests[test_id].pqc_sig = pqc_sig;
                        tests[test_id].qkd_protocol = qkd;
                        test_id++;
                    }
                }
            }
        }
    }
    *total_tests = test_id;
}

/**
 * Get human-readable description of test configuration
 */
const char* get_test_description(const test_config_t* config) {
    static char description[512];
    snprintf(description, sizeof(description), 
             "Test %d: %s + %s + %s + %s + %s",
             config->test_id,
             classical_kex_names[config->classical_kex],
             classical_sig_names[config->classical_sig],
             pqc_kem_names[config->pqc_kem],
             pqc_sig_names[config->pqc_sig],
             qkd_protocol_names[config->qkd_protocol]);
    return description;
}

/**
 * Calculate total number of test combinations
 */
int calculate_total_combinations(void) {
    return CLASSICAL_MAX * SIG_MAX * PQC_KEM_MAX * PQC_SIG_MAX * QKD_MAX;
}