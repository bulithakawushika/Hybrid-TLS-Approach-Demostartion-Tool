#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "hybrid_tls_protocol.h"
#include "qkd_interface.h"
#include "classical_crypto.h"
#include "pqc_crypto.h"
#include "mac_ops.h"
#include "qkd_data.h"

// External QKD key data - now defined in qkd_data.c
// (declarations moved to qkd_data.h)

/**
 * Initialize mock QKD data for protocol demo
 */
void initialize_demo_qkd_data() {
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
    
    printf("Demo QKD data initialized successfully\n");
}

/**
 * Run a single protocol demonstration
 */
int run_protocol_demo(const test_config_t* config) {
    printf("\n");
    printf("============================================================\n");
    printf("HYBRID TLS PROTOCOL DEMONSTRATION\n");
    printf("============================================================\n");
    printf("Configuration: %s\n", get_test_description(config));
    printf("============================================================\n");
    
    unsigned char shared_key[FINAL_KEY_SIZE];
    
    // Run the complete handshake protocol
    int result = run_hybrid_handshake(config, shared_key);
    
    if (result == 0) {
        printf("\n🎉 PROTOCOL DEMO SUCCESSFUL! 🎉\n");
        printf("Shared key established: ");
        for (int i = 0; i < FINAL_KEY_SIZE; i++) {
            printf("%02x", shared_key[i]);
        }
        printf("\n");
        return 0;
    } else {
        printf("\n❌ PROTOCOL DEMO FAILED!\n");
        return -1;
    }
}

/**
 * Run multiple protocol combinations
 */
int run_protocol_suite() {
    printf("=== Hybrid TLS Protocol Test Suite ===\n");
    
    // Test configurations covering different algorithm combinations
    test_config_t test_configs[] = {
        // Classical + PQC + QKD combinations
        {1, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_BB84},
        {2, CLASSICAL_X25519, SIG_ED25519, PQC_HQC_192, PQC_FALCON_512, QKD_E91},
        {3, CLASSICAL_ECDHE_P384, SIG_ECDSA_P384, PQC_BIKE_L3, PQC_SPHINCS_SHA2_192F, QKD_MDI},
        {4, CLASSICAL_ECDHE_P256, SIG_ED25519, PQC_ML_KEM_768, PQC_FALCON_512, QKD_BB84},
        {5, CLASSICAL_X25519, SIG_ECDSA_P256, PQC_HQC_192, PQC_ML_DSA_65, QKD_E91}
    };
    
    int total_tests = sizeof(test_configs) / sizeof(test_configs[0]);
    int passed = 0;
    
    printf("Running %d protocol demonstration tests...\n\n", total_tests);
    
    for (int i = 0; i < total_tests; i++) {
        printf("\n--- Test %d/%d ---\n", i + 1, total_tests);
        
        if (run_protocol_demo(&test_configs[i]) == 0) {
            passed++;
            printf("✅ Test %d PASSED\n", i + 1);
        } else {
            printf("❌ Test %d FAILED\n", i + 1);
        }
        
        printf("Press Enter to continue to next test...");
        getchar();
    }
    
    printf("\n=== Protocol Test Suite Results ===\n");
    printf("Passed: %d/%d tests (%.1f%%)\n", passed, total_tests, 
           (double)passed / total_tests * 100.0);
    
    return (passed == total_tests) ? 0 : -1;
}

/**
 * Interactive protocol demo menu
 */
void show_demo_menu() {
    printf("\n=== Hybrid TLS Protocol Demo Menu ===\n");
    printf("1. Quick Demo (ECDHE-P256 + ML-KEM-768 + BB84)\n");
    printf("2. X25519 Demo (X25519 + HQC-192 + E91)\n");
    printf("3. High Security Demo (P-384 + BIKE-L3 + MDI-QKD)\n");
    printf("4. Run Protocol Test Suite (5 configurations)\n");
    printf("5. Custom Configuration\n");
    printf("6. Performance Benchmark\n");
    printf("7. Exit\n");
    printf("Choose option (1-7): ");
}

/**
 * Get user choice for custom configuration
 */
int get_custom_config(test_config_t* config) {
    printf("\n=== Custom Configuration ===\n");
    
    // Classical KEX selection
    printf("Classical Key Exchange:\n");
    for (int i = 0; i < CLASSICAL_MAX; i++) {
        printf("  %d. %s\n", i, classical_kex_names[i]);
    }
    printf("Choose (0-%d): ", CLASSICAL_MAX - 1);
    int choice;
    if (scanf("%d", &choice) != 1 || choice < 0 || choice >= CLASSICAL_MAX) {
        printf("Invalid choice\n");
        return -1;
    }
    config->classical_kex = choice;
    
    // Classical Signature selection
    printf("\nClassical Digital Signature:\n");
    for (int i = 0; i < SIG_MAX; i++) {
        printf("  %d. %s\n", i, classical_sig_names[i]);
    }
    printf("Choose (0-%d): ", SIG_MAX - 1);
    if (scanf("%d", &choice) != 1 || choice < 0 || choice >= SIG_MAX) {
        printf("Invalid choice\n");
        return -1;
    }
    config->classical_sig = choice;
    
    // PQC KEM selection
    printf("\nPost-Quantum KEM:\n");
    for (int i = 0; i < PQC_KEM_MAX; i++) {
        printf("  %d. %s\n", i, pqc_kem_names[i]);
    }
    printf("Choose (0-%d): ", PQC_KEM_MAX - 1);
    if (scanf("%d", &choice) != 1 || choice < 0 || choice >= PQC_KEM_MAX) {
        printf("Invalid choice\n");
        return -1;
    }
    config->pqc_kem = choice;
    
    // PQC Signature selection
    printf("\nPost-Quantum Digital Signature:\n");
    for (int i = 0; i < PQC_SIG_MAX; i++) {
        printf("  %d. %s\n", i, pqc_sig_names[i]);
    }
    printf("Choose (0-%d): ", PQC_SIG_MAX - 1);
    if (scanf("%d", &choice) != 1 || choice < 0 || choice >= PQC_SIG_MAX) {
        printf("Invalid choice\n");
        return -1;
    }
    config->pqc_sig = choice;
    
    // QKD Protocol selection
    printf("\nQKD Protocol:\n");
    for (int i = 0; i < QKD_MAX; i++) {
        printf("  %d. %s\n", i, qkd_protocol_names[i]);
    }
    printf("Choose (0-%d): ", QKD_MAX - 1);
    if (scanf("%d", &choice) != 1 || choice < 0 || choice >= QKD_MAX) {
        printf("Invalid choice\n");
        return -1;
    }
    config->qkd_protocol = choice;
    
    config->test_id = 99; // Custom config ID
    
    printf("\nCustom configuration created:\n");
    printf("  %s\n", get_test_description(config));
    
    return 0;
}

/**
 * Run performance benchmark
 */
int run_performance_benchmark() {
    printf("\n=== Performance Benchmark ===\n");
    printf("Testing different algorithm combinations for performance...\n\n");
    
    test_config_t benchmark_configs[] = {
        // Fast algorithms
        {101, CLASSICAL_X25519, SIG_ED25519, PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_BB84},
        // Medium algorithms  
        {102, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, PQC_HQC_192, PQC_FALCON_512, QKD_E91},
        // Slower but secure algorithms
        {103, CLASSICAL_ECDHE_P384, SIG_ECDSA_P384, PQC_BIKE_L3, PQC_SPHINCS_SHA2_192F, QKD_MDI}
    };
    
    const char* benchmark_names[] = {
        "Fast Configuration",
        "Balanced Configuration", 
        "High Security Configuration"
    };
    
    int num_benchmarks = sizeof(benchmark_configs) / sizeof(benchmark_configs[0]);
    
    printf("Running %d benchmark configurations...\n", num_benchmarks);
    
    for (int i = 0; i < num_benchmarks; i++) {
        printf("\n--- %s ---\n", benchmark_names[i]);
        printf("Config: %s\n", get_test_description(&benchmark_configs[i]));
        
        // Run multiple iterations for more accurate timing
        const int iterations = 3;
        double total_time = 0.0;
        int successful_runs = 0;
        
        for (int iter = 0; iter < iterations; iter++) {
            printf("  Iteration %d/%d...", iter + 1, iterations);
            
            struct timeval tv_start, tv_end;
            gettimeofday(&tv_start, NULL);
            double start_time = tv_start.tv_sec * 1000.0 + tv_start.tv_usec / 1000.0;
            
            unsigned char shared_key[FINAL_KEY_SIZE];
            
            int result = run_hybrid_handshake(&benchmark_configs[i], shared_key);
            
            gettimeofday(&tv_end, NULL);
            double end_time = tv_end.tv_sec * 1000.0 + tv_end.tv_usec / 1000.0;
            double iteration_time = end_time - start_time;
            
            if (result == 0) {
                total_time += iteration_time;
                successful_runs++;
                printf(" %.3f ms ✅\n", iteration_time);
            } else {
                printf(" FAILED ❌\n");
            }
        }
        
        if (successful_runs > 0) {
            double avg_time = total_time / successful_runs;
            printf("Average time: %.3f ms (%d/%d successful)\n", avg_time, successful_runs, iterations);
        } else {
            printf("All iterations failed!\n");
        }
    }
    
    return 0;
}

/**
 * Main demo program
 */
int main(int argc, char* argv[]) {
    printf("=== Hybrid TLS Protocol Implementation Demo ===\n");
    printf("Quantum-Safe TLS with Classical + PQC + QKD\n");
    printf("=============================================\n");
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Initialize LibOQS
    if (initialize_liboqs() != 0) {
        fprintf(stderr, "Failed to initialize LibOQS\n");
        return 1;
    }
    
    // Initialize demo QKD data
    initialize_demo_qkd_data();
    
    // Check for command line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "--quick") == 0) {
            // Quick demo mode
            test_config_t quick_config = {0, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, 
                                        PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_BB84};
            int result = run_protocol_demo(&quick_config);
            cleanup_liboqs();
            return result == 0 ? 0 : 1;
        } else if (strcmp(argv[1], "--suite") == 0) {
            // Test suite mode
            int result = run_protocol_suite();
            cleanup_liboqs();
            return result == 0 ? 0 : 1;
        } else if (strcmp(argv[1], "--benchmark") == 0) {
            // Benchmark mode
            run_performance_benchmark();
            cleanup_liboqs();
            return 0;
        } else {
            printf("Usage: %s [--quick|--suite|--benchmark]\n", argv[0]);
            printf("  --quick     Run quick demo with default config\n");
            printf("  --suite     Run test suite with multiple configs\n");
            printf("  --benchmark Run performance benchmark\n");
            cleanup_liboqs();
            return 1;
        }
    }
    
    // Interactive mode
    int choice;
    do {
        show_demo_menu();
        
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please enter a number.\n");
            // Clear input buffer
            while (getchar() != '\n');
            continue;
        }
        
        switch (choice) {
            case 1: {
                // Quick demo
                test_config_t config = {0, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, 
                                      PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_BB84};
                run_protocol_demo(&config);
                break;
            }
            case 2: {
                // X25519 demo
                test_config_t config = {0, CLASSICAL_X25519, SIG_ED25519, 
                                      PQC_HQC_192, PQC_FALCON_512, QKD_E91};
                run_protocol_demo(&config);
                break;
            }
            case 3: {
                // High security demo
                test_config_t config = {0, CLASSICAL_ECDHE_P384, SIG_ECDSA_P384, 
                                      PQC_BIKE_L3, PQC_SPHINCS_SHA2_192F, QKD_MDI};
                run_protocol_demo(&config);
                break;
            }
            case 4: {
                // Test suite
                run_protocol_suite();
                break;
            }
            case 5: {
                // Custom configuration
                test_config_t config;
                if (get_custom_config(&config) == 0) {
                    run_protocol_demo(&config);
                }
                break;
            }
            case 6: {
                // Performance benchmark
                run_performance_benchmark();
                break;
            }
            case 7: {
                printf("Exiting demo...\n");
                break;
            }
            default: {
                printf("Invalid choice. Please choose 1-7.\n");
                break;
            }
        }
        
        if (choice != 7) {
            printf("\nPress Enter to return to menu...");
            getchar(); // Consume newline
            getchar(); // Wait for user input
        }
        
    } while (choice != 7);
    
    // Cleanup
    cleanup_liboqs();
    EVP_cleanup();
    
    printf("Demo completed successfully!\n");
    return 0;
}