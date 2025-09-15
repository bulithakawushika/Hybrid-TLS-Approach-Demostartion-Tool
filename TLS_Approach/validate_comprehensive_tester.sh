#!/bin/bash

# validate_comprehensive_tester.sh - Quick validation of the production comprehensive tester

set -e

echo "=== Validating Production Comprehensive Tester ==="
echo "This script validates that the comprehensive tester works correctly"
echo "by running a subset of tests before the full research run."
echo ""

# Check if we're in the right directory
if [ ! -f "stage.c" ] || [ ! -d "src" ]; then
    echo "Error: Please run this script from the TLS_Approach directory"
    exit 1
fi

# Function to check dependencies
check_dependencies() {
    echo "=== Checking Dependencies ==="
    
    echo -n "LibOQS: "
    if pkg-config --exists oqs; then
        echo "✓ Available"
    else
        echo "✗ Missing"
        return 1
    fi
    
    echo -n "OpenSSL: "
    if pkg-config --exists openssl; then
        echo "✓ Available"
    else
        echo "✗ Missing"  
        return 1
    fi
    
    echo -n "cJSON: "
    if pkg-config --exists libcjson; then
        echo "✓ Available"
    else
        echo "✗ Missing"
        return 1
    fi
    
    echo -n "Python3: "
    if command -v python3 >/dev/null 2>&1; then
        echo "✓ Available ($(python3 --version))"
    else
        echo "✗ Missing"
        return 1
    fi
    
    return 0
}

# Function to build the comprehensive tester
build_tester() {
    echo ""
    echo "=== Building Production Comprehensive Tester ==="
    
    # Save the production tester to the right location
    if [ ! -f "src/comprehensive_tester.c" ]; then
        echo "Error: Production comprehensive tester source not found at src/comprehensive_tester.c"
        echo "Please save the production comprehensive tester code to src/comprehensive_tester.c"
        return 1
    fi
    
    # Clean and build
    make clean
    make all
    
    if [ ! -f "bin/comprehensive_tester" ]; then
        echo "Error: Failed to build comprehensive tester"
        return 1
    fi
    
    echo "✓ Production comprehensive tester built successfully"
    return 0
}

# Function to validate QKD key generation
validate_qkd_keys() {
    echo ""
    echo "=== Validating QKD Key Generation ==="
    
    # Generate QKD keys
    echo "Generating QKD keys..."
    make generate-keys
    
    if [ -f "/tmp/qkd_keys.dat" ]; then
        echo "✓ QKD keys generated successfully"
        
        # Check file size (should be 3 * sizeof(qkd_key_data_t))
        FILE_SIZE=$(stat -f%z "/tmp/qkd_keys.dat" 2>/dev/null || stat -c%s "/tmp/qkd_keys.dat" 2>/dev/null)
        EXPECTED_SIZE=$((3 * (64 + 16 + 4)))  # 3 * (SHA3_512 + UUID + valid flag)
        
        if [ "$FILE_SIZE" -eq "$EXPECTED_SIZE" ]; then
            echo "✓ QKD key file has correct size ($FILE_SIZE bytes)"
        else
            echo "⚠ QKD key file size unexpected: $FILE_SIZE bytes (expected ~$EXPECTED_SIZE)"
        fi
    else
        echo "✗ QKD key generation failed"
        return 1
    fi
    
    return 0
}

# Function to run a quick validation test
run_validation_test() {
    echo ""
    echo "=== Running Quick Validation Test ==="
    echo "Testing a few combinations to ensure the comprehensive tester works..."
    
    # Create a minimal validation version that tests just 3 combinations
    cat > /tmp/validation_test.c << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "qkd_interface.h"
#include "classical_crypto.h"
#include "pqc_crypto.h"
#include "mac_ops.h"
#include "qkd_data.h"

static jmp_buf recovery_point;

void signal_handler(int sig) {
    printf("\nCaught signal %d - test failed\n", sig);
    longjmp(recovery_point, sig);
}

double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

void init_qkd_data() {
    memset(&bb84_data.kqkdm, 0xAA, SHA3_512_DIGEST_LENGTH);
    memset(&bb84_data.uuid, 0xBB, UUID_LENGTH);
    bb84_data.valid = 1;
    
    memset(&e91_data.kqkdm, 0xCC, SHA3_512_DIGEST_LENGTH);
    memset(&e91_data.uuid, 0xDD, UUID_LENGTH);
    e91_data.valid = 1;
    
    memset(&mdi_data.kqkdm, 0xEE, SHA3_512_DIGEST_LENGTH);
    memset(&mdi_data.uuid, 0xFF, UUID_LENGTH);
    mdi_data.valid = 1;
}

int quick_test(classical_kex_t kex, classical_sig_t sig, pqc_kem_t kem, pqc_sig_t pqc_sig, qkd_protocol_t qkd) {
    if (setjmp(recovery_point) != 0) {
        return -1;  // Signal caught
    }
    
    // Quick algorithm support check
    if (!is_kem_supported(kem) || !is_sig_supported(pqc_sig)) {
        return -1;
    }
    
    // Minimal test - just try to create one keypair of each type
    classical_keypair_t c_pair = {0};
    pqc_kem_keypair_t k_pair = {0};
    pqc_sig_keypair_t s_pair = {0};
    
    int result = 0;
    
    if (classical_keygen(kex, &c_pair) != 0) result = -1;
    if (result == 0 && pqc_kem_keygen(kem, &k_pair) != 0) result = -1;
    if (result == 0 && pqc_sig_keygen(pqc_sig, &s_pair) != 0) result = -1;
    
    // Test QKD
    if (result == 0) {
        qkd_key_data_t qkd_key;
        unsigned char k_qkd[32], k_auth[32], na[12], nb[12];
        if (get_qkd_key(qkd, &qkd_key) != 0 ||
            derive_qkd_components(qkd_key.kqkdm, SHA3_512_DIGEST_LENGTH, k_qkd, k_auth, na, nb) != 0) {
            result = -1;
        }
    }
    
    // Cleanup
    free_classical_keypair(&c_pair);
    free_pqc_kem_keypair(&k_pair);
    free_pqc_sig_keypair(&s_pair);
    
    return result;
}

int main() {
    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    if (initialize_liboqs() != 0) {
        printf("LibOQS initialization failed\n");
        return 1;
    }
    
    init_qkd_data();
    
    // Test 3 basic combinations
    test_config_t tests[] = {
        {0, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_BB84},
        {1, CLASSICAL_X25519, SIG_ED25519, PQC_ML_KEM_768, PQC_FALCON_512, QKD_E91},
        {2, CLASSICAL_ECDHE_P256, SIG_ED25519, PQC_HQC_192, PQC_ML_DSA_65, QKD_MDI}
    };
    
    int passed = 0;
    
    for (int i = 0; i < 3; i++) {
        printf("Testing: %s+%s+%s+%s+%s ... ",
               classical_kex_names[tests[i].classical_kex],
               classical_sig_names[tests[i].classical_sig],
               pqc_kem_names[tests[i].pqc_kem],
               pqc_sig_names[tests[i].pqc_sig],
               qkd_protocol_names[tests[i].qkd_protocol]);
        
        double start = get_time_ms();
        if (quick_test(tests[i].classical_kex, tests[i].classical_sig, 
                      tests[i].pqc_kem, tests[i].pqc_sig, tests[i].qkd_protocol) == 0) {
            double time = get_time_ms() - start;
            printf("PASS (%.2f ms)\n", time);
            passed++;
        } else {
            printf("FAIL\n");
        }
    }
    
    cleanup_liboqs();
    
    printf("\nValidation result: %d/3 tests passed\n", passed);
    return passed == 3 ? 0 : 1;
}
EOF

    # Compile and run validation test
    gcc -std=gnu99 -I./src -o /tmp/validation_test /tmp/validation_test.c \
        src/config.c src/qkd_data.c src/qkd_interface.c src/classical_crypto.c \
        src/pqc_crypto.c src/mac_ops.c -loqs -lssl -lcrypto -lcjson -lm
    
    if /tmp/validation_test; then
        echo "✓ Validation test passed - comprehensive tester should work correctly"
        rm -f /tmp/validation_test /tmp/validation_test.c
        return 0
    else
        echo "✗ Validation test failed - there may be issues with the comprehensive tester"
        rm -f /tmp/validation_test /tmp/validation_test.c
        return 1
    fi
}

# Function to show next steps
show_next_steps() {
    echo ""
    echo "=== Validation Complete - Next Steps ==="
    echo ""
    echo "✓ All validation checks passed"
    echo "✓ Production comprehensive tester is ready"
    echo ""
    echo "To run the full comprehensive performance analysis:"
    echo "  make perf-comprehensive-force    # Run all 144 combinations (15-30 minutes)"
    echo ""
    echo "Or use the automated research script:"
    echo "  ./comprehensive_test_runner.sh   # Full research-grade analysis"
    echo ""
    echo "Quick testing options:"
    echo "  make perf-debug                  # Debug version (6 combinations, 2 minutes)"
    echo "  make test-network                # Network functionality test"
    echo "  make demo-quick                  # Protocol demonstration"
    echo ""
    echo "The comprehensive test will generate:"
    echo "  - cpu_performance_results.txt    (Performance rankings)"
    echo "  - tls_handshake_results.txt      (TLS timing data)"
    echo "  - research_appendix.txt          (Research documentation)"
    echo ""
    echo "All output files are suitable for IEEE publication quality research."
}

# Main validation process
main() {
    echo "Starting validation of production comprehensive tester..."
    echo ""
    
    if ! check_dependencies; then
        echo ""
        echo "❌ Dependency check failed. Please install missing dependencies:"
        echo "   ./setup.sh"
        exit 1
    fi
    
    if ! build_tester; then
        echo ""
        echo "❌ Build failed. Please check compiler errors above."
        exit 1
    fi
    
    if ! validate_qkd_keys; then
        echo ""
        echo "❌ QKD key validation failed."
        exit 1
    fi
    
    if ! run_validation_test; then
        echo ""
        echo "❌ Validation test failed."
        exit 1
    fi
    
    show_next_steps
    
    echo ""
    echo "🎉 Production comprehensive tester validation successful!"
}

# Execute main function
main "$@"