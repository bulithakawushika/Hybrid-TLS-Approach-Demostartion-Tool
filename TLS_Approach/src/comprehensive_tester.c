#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "config.h"
#include "hybrid_tls_protocol.h"
#include "qkd_interface.h"
#include "classical_crypto.h"
#include "pqc_crypto.h"
#include "mac_ops.h"
#include "qkd_data.h"

// Global performance tracking
static test_performance_t performance_results[144];
static int completed_tests = 0;

// Global variables for crash recovery
static int current_test_id = -1;
static const char* current_test_name = "Unknown";

// CPU monitoring structure
typedef struct {
    struct timespec wall_start;
    struct timespec wall_end;
    clock_t cpu_start;
    clock_t cpu_end;
    double wall_time_ms;
    double cpu_time_ms;
    double cpu_percentage;
} cpu_monitor_t;

// Function prototypes
int test_classical_crypto(const test_config_t* config, test_performance_t* perf);
int test_pqc_crypto(const test_config_t* config, test_performance_t* perf);
int test_tls_handshake(const test_config_t* config, test_performance_t* perf);
void generate_qkd_performance_report(void);
void generate_tls_handshake_report(void);

double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

double get_timespec_ms(struct timespec* ts) {
    return ts->tv_sec * 1000.0 + ts->tv_nsec / 1000000.0;
}

void start_cpu_monitor(cpu_monitor_t* monitor) {
    clock_gettime(CLOCK_MONOTONIC, &monitor->wall_start);
    monitor->cpu_start = clock();
}

double end_cpu_monitor(cpu_monitor_t* monitor) {
    clock_gettime(CLOCK_MONOTONIC, &monitor->wall_end);
    monitor->cpu_end = clock();
    
    // Calculate wall time in milliseconds
    monitor->wall_time_ms = get_timespec_ms(&monitor->wall_end) - get_timespec_ms(&monitor->wall_start);
    
    // Calculate CPU time in milliseconds
    monitor->cpu_time_ms = ((double)(monitor->cpu_end - monitor->cpu_start) / CLOCKS_PER_SEC) * 1000.0;
    
    // Calculate CPU percentage: (CPU time / Wall time) * 100
    if (monitor->wall_time_ms > 0.1) {  // Avoid division by very small numbers
        monitor->cpu_percentage = (monitor->cpu_time_ms / monitor->wall_time_ms) * 100.0;
        // Cap at 100% for single-threaded operations
        if (monitor->cpu_percentage > 100.0) {
            monitor->cpu_percentage = 100.0;
        }
    } else {
        monitor->cpu_percentage = 0.0;
    }
    
    return monitor->cpu_percentage;
}

size_t get_memory_usage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss * 1024; // Convert to bytes
}

void crash_handler(int sig) {
    printf("\n\n!!! CRASH DETECTED !!!\n");
    printf("Signal: %d\n", sig);
    printf("Failed on Test ID: %d\n", current_test_id);
    printf("Test Name: %s\n", current_test_name);
    
    // Mark current test as failed
    if (current_test_id >= 0 && current_test_id < 144) {
        performance_results[current_test_id].test_success = 0;
        snprintf(performance_results[current_test_id].error_message, 
                sizeof(performance_results[current_test_id].error_message),
                "CRASH: Signal %d during test execution", sig);
    }
    
    exit(1);
}

int run_comprehensive_test(const test_config_t* config, test_performance_t* perf) {
    double test_start = get_time_ms();
    size_t start_memory = get_memory_usage();
    cpu_monitor_t total_cpu_monitor;
    
    // Initialize performance structure
    memset(perf, 0, sizeof(test_performance_t));
    perf->test_id = config->test_id;
    strncpy(perf->test_description, get_test_description(config), sizeof(perf->test_description) - 1);
    
    // Start total CPU monitoring
    start_cpu_monitor(&total_cpu_monitor);
    
    // Step 1: QKD Key Generation with CPU monitoring
    double qkd_start = get_time_ms();
    cpu_monitor_t qkd_cpu_monitor;
    start_cpu_monitor(&qkd_cpu_monitor);
    
    qkd_key_data_t qkd_key;
    int retry_count = 0;
    int qkd_success = 0;
    
    // Try up to 20 times for QKD key generation
    while (retry_count < 20 && !qkd_success) {
        retry_count++;
        if (get_qkd_key(config->qkd_protocol, &qkd_key) == 0) {
            qkd_success = 1;
            break;
        }
        usleep(10000); // 10ms delay between retries
    }
    
    if (!qkd_success) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "QKD key generation failed after %d retries", retry_count);
        return -1;
    }
    
    perf->qkd_generation_time = get_time_ms() - qkd_start;
    perf->qkd_cpu_utilization = end_cpu_monitor(&qkd_cpu_monitor);
    perf->qkd_retry_count = retry_count;
    
    // Step 2: Classical Cryptography Testing
    if (test_classical_crypto(config, perf) != 0) {
        if (strlen(perf->error_message) == 0) {
            snprintf(perf->error_message, sizeof(perf->error_message), "Classical crypto test failed");
        }
        return -1;
    }
    
    // Step 3: PQC Testing
    if (test_pqc_crypto(config, perf) != 0) {
        if (strlen(perf->error_message) == 0) {
            snprintf(perf->error_message, sizeof(perf->error_message), "PQC crypto test failed");
        }
        return -1;
    }
    
    // Step 4: TLS Handshake
    if (test_tls_handshake(config, perf) != 0) {
        if (strlen(perf->error_message) == 0) {
            snprintf(perf->error_message, sizeof(perf->error_message), "TLS handshake test failed");
        }
        return -1;
    }
    
    // Calculate total performance
    perf->handshake_total_time = get_time_ms() - test_start;
    perf->handshake_total_cpu = end_cpu_monitor(&total_cpu_monitor);
    perf->peak_memory_usage = get_memory_usage() - start_memory;
    perf->test_success = 1;
    
    return 0;
}

int test_classical_crypto(const test_config_t* config, test_performance_t* perf) {
    classical_keypair_t alice_kex = {0}, bob_kex = {0}, sig_keypair = {0};
    double start_time;
    cpu_monitor_t cpu_monitor;
    
    // Key generation with CPU monitoring
    start_cpu_monitor(&cpu_monitor);
    start_time = get_time_ms();
    if (classical_keygen(config->classical_kex, &alice_kex) != 0 ||
        classical_keygen(config->classical_kex, &bob_kex) != 0 ||
        classical_sig_keygen(config->classical_sig, &sig_keypair) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "Classical key generation failed");
        goto cleanup_classical;
    }
    perf->classical_keygen_time = get_time_ms() - start_time;
    perf->classical_keygen_cpu = end_cpu_monitor(&cpu_monitor);
    perf->classical_key_size = alice_kex.public_key_len;
    
    // Key agreement test
    unsigned char shared_secret1[64], shared_secret2[64];
    size_t ss_len1 = sizeof(shared_secret1), ss_len2 = sizeof(shared_secret2);
    
    if (classical_key_agreement(config->classical_kex, &alice_kex,
                               bob_kex.public_key_bytes, bob_kex.public_key_len,
                               shared_secret1, &ss_len1) != 0 ||
        classical_key_agreement(config->classical_kex, &bob_kex,
                               alice_kex.public_key_bytes, alice_kex.public_key_len,
                               shared_secret2, &ss_len2) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "Classical key agreement failed");
        goto cleanup_classical;
    }
    
    // Verify shared secrets match
    if (ss_len1 != ss_len2 || memcmp(shared_secret1, shared_secret2, ss_len1) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "Classical shared secrets mismatch");
        goto cleanup_classical;
    }
    
    // Signature testing with CPU monitoring
    const unsigned char test_msg[] = "Test message for performance testing";
    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);
    
    start_cpu_monitor(&cpu_monitor);
    start_time = get_time_ms();
    if (classical_sign(config->classical_sig, &sig_keypair,
                      test_msg, sizeof(test_msg) - 1, signature, &sig_len) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "Classical signature generation failed");
        goto cleanup_classical;
    }
    perf->classical_sign_time = get_time_ms() - start_time;
    perf->classical_sign_cpu = end_cpu_monitor(&cpu_monitor);
    perf->classical_signature_size = sig_len;
    
    start_cpu_monitor(&cpu_monitor);
    start_time = get_time_ms();
    if (classical_verify(config->classical_sig,
                        sig_keypair.public_key_bytes, sig_keypair.public_key_len,
                        test_msg, sizeof(test_msg) - 1, signature, sig_len) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "Classical signature verification failed");
        goto cleanup_classical;
    }
    perf->classical_verify_time = get_time_ms() - start_time;
    perf->classical_verify_cpu = end_cpu_monitor(&cpu_monitor);
    
    free_classical_keypair(&alice_kex);
    free_classical_keypair(&bob_kex);
    free_classical_keypair(&sig_keypair);
    return 0;
    
cleanup_classical:
    free_classical_keypair(&alice_kex);
    free_classical_keypair(&bob_kex);
    free_classical_keypair(&sig_keypair);
    return -1;
}

int test_pqc_crypto(const test_config_t* config, test_performance_t* perf) {
    pqc_kem_keypair_t kem_keypair = {0};
    pqc_sig_keypair_t sig_keypair = {0};
    double start_time;
    cpu_monitor_t cpu_monitor;
    
    // Check algorithm support first
    if (!is_kem_supported(config->pqc_kem)) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "PQC KEM algorithm not supported");
        return -1;
    }
    
    if (!is_sig_supported(config->pqc_sig)) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "PQC signature algorithm not supported");
        return -1;
    }
    
    // PQC KEM testing with CPU monitoring
    start_cpu_monitor(&cpu_monitor);
    start_time = get_time_ms();
    if (pqc_kem_keygen(config->pqc_kem, &kem_keypair) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "PQC KEM key generation failed");
        return -1;
    }
    perf->pqc_keygen_time = get_time_ms() - start_time;
    perf->pqc_keygen_cpu = end_cpu_monitor(&cpu_monitor);
    perf->pqc_public_key_size = kem_keypair.public_key_len;
    perf->pqc_secret_key_size = kem_keypair.secret_key_len;
    
    // Get buffer sizes safely
    size_t max_ss_len, max_ct_len;
    if (get_pqc_kem_sizes(config->pqc_kem, NULL, NULL, &max_ct_len, &max_ss_len) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "Failed to get KEM algorithm sizes");
        goto cleanup_pqc_kem;
    }
    
    // Allocate buffers
    unsigned char* shared_secret = malloc(max_ss_len);
    unsigned char* ciphertext = malloc(max_ct_len);
    unsigned char* decap_secret = malloc(max_ss_len);
    
    if (!shared_secret || !ciphertext || !decap_secret) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "Failed to allocate KEM buffers");
        goto cleanup_pqc_buffers;
    }
    
    size_t ss_len = max_ss_len, ct_len = max_ct_len, decap_len = max_ss_len;
    
    // Encapsulation with CPU monitoring
    start_cpu_monitor(&cpu_monitor);
    start_time = get_time_ms();
    if (pqc_kem_encapsulate(config->pqc_kem,
                           kem_keypair.public_key, kem_keypair.public_key_len,
                           shared_secret, &ss_len, ciphertext, &ct_len) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "PQC KEM encapsulation failed");
        goto cleanup_pqc_buffers;
    }
    perf->pqc_encap_time = get_time_ms() - start_time;
    perf->pqc_encap_cpu = end_cpu_monitor(&cpu_monitor);
    perf->pqc_ciphertext_size = ct_len;
    
    // Decapsulation with CPU monitoring
    start_cpu_monitor(&cpu_monitor);
    start_time = get_time_ms();
    if (pqc_kem_decapsulate(config->pqc_kem,
                           kem_keypair.secret_key, kem_keypair.secret_key_len,
                           ciphertext, ct_len, decap_secret, &decap_len) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "PQC KEM decapsulation failed");
        goto cleanup_pqc_buffers;
    }
    perf->pqc_decap_time = get_time_ms() - start_time;
    perf->pqc_decap_cpu = end_cpu_monitor(&cpu_monitor);
    
    // Verify shared secrets match
    if (ss_len != decap_len || memcmp(shared_secret, decap_secret, ss_len) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "PQC KEM shared secrets mismatch");
        goto cleanup_pqc_buffers;
    }
    
    // Clean up KEM buffers
    free(shared_secret);
    free(ciphertext);
    free(decap_secret);
    
    // PQC Signature testing
    if (pqc_sig_keygen(config->pqc_sig, &sig_keypair) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "PQC signature key generation failed");
        goto cleanup_pqc_kem;
    }
    
    // Get signature size
    size_t max_sig_len;
    if (get_pqc_sig_sizes(config->pqc_sig, NULL, NULL, &max_sig_len) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "Failed to get signature algorithm sizes");
        goto cleanup_pqc_sig;
    }
    
    // Allocate signature buffer
    unsigned char* pqc_signature = calloc(1, max_sig_len + 1024);
    if (!pqc_signature) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "Failed to allocate signature buffer (%zu bytes)", max_sig_len);
        goto cleanup_pqc_sig;
    }
    
    const unsigned char test_msg[] = "PQC performance test message";
    size_t pqc_sig_len = max_sig_len;
    
    // Signing with CPU monitoring
    start_cpu_monitor(&cpu_monitor);
    start_time = get_time_ms();
    if (pqc_sign(config->pqc_sig,
                sig_keypair.secret_key, sig_keypair.secret_key_len,
                test_msg, sizeof(test_msg) - 1, 
                pqc_signature, &pqc_sig_len) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "PQC signature generation failed");
        free(pqc_signature);
        goto cleanup_pqc_sig;
    }
    perf->pqc_sign_time = get_time_ms() - start_time;
    perf->pqc_sign_cpu = end_cpu_monitor(&cpu_monitor);
    perf->pqc_signature_size = pqc_sig_len;
    
    // Verification with CPU monitoring
    start_cpu_monitor(&cpu_monitor);
    start_time = get_time_ms();
    if (pqc_verify(config->pqc_sig,
                  sig_keypair.public_key, sig_keypair.public_key_len,
                  test_msg, sizeof(test_msg) - 1, 
                  pqc_signature, pqc_sig_len) != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "PQC signature verification failed");
        free(pqc_signature);
        goto cleanup_pqc_sig;
    }
    perf->pqc_verify_time = get_time_ms() - start_time;
    perf->pqc_verify_cpu = end_cpu_monitor(&cpu_monitor);
    
    free(pqc_signature);
    free_pqc_kem_keypair(&kem_keypair);
    free_pqc_sig_keypair(&sig_keypair);
    return 0;
    
cleanup_pqc_buffers:
    free(shared_secret);
    free(ciphertext);
    free(decap_secret);
cleanup_pqc_sig:
    free_pqc_sig_keypair(&sig_keypair);
cleanup_pqc_kem:
    free_pqc_kem_keypair(&kem_keypair);
    return -1;
}

int test_tls_handshake(const test_config_t* config, test_performance_t* perf) {
    unsigned char shared_key[FINAL_KEY_SIZE];
    
    double start_time = get_time_ms();
    int result = run_hybrid_handshake(config, shared_key);
    perf->handshake_total_time = get_time_ms() - start_time;
    
    if (result != 0) {
        snprintf(perf->error_message, sizeof(perf->error_message), 
                "TLS handshake failed");
    }
    
    return result;
}

void generate_qkd_performance_report() {
    FILE* fp = fopen("qkd_performance_report.txt", "w");
    if (!fp) return;
    
    time_t now = time(NULL);
    fprintf(fp, "=== QKD Key Generation Performance Report with CPU Usage ===\n");
    fprintf(fp, "Generated at: %s", ctime(&now));
    fprintf(fp, "Total Tests: %d\n\n", completed_tests);
    
    // Summary with CPU data
    double total_time = 0, total_cpu = 0;
    int successful = 0;
    
    for (int i = 0; i < completed_tests; i++) {
        if (performance_results[i].test_success) {
            total_time += performance_results[i].qkd_generation_time;
            total_cpu += performance_results[i].qkd_cpu_utilization;
            successful++;
        }
    }
    
    if (successful > 0) {
        fprintf(fp, "Average QKD Time: %.2f ms (%.1f%% CPU)\n", 
                total_time/successful, total_cpu/successful);
    }
    
    fprintf(fp, "\nDETAILED RESULTS:\n");
    fprintf(fp, "TestID | Time(ms) | CPU(%%) | Retries | Status\n");
    fprintf(fp, "-------|----------|--------|---------|--------\n");
    
    for (int i = 0; i < completed_tests; i++) {
        fprintf(fp, "%6d | %8.2f | %6.1f | %7d | %s\n",
                performance_results[i].test_id,
                performance_results[i].qkd_generation_time,
                performance_results[i].qkd_cpu_utilization,
                performance_results[i].qkd_retry_count,
                performance_results[i].test_success ? "SUCCESS" : "FAILED");
    }
    
    fclose(fp);
}

void generate_tls_handshake_report() {
    FILE* fp = fopen("tls_handshake_performance_report.txt", "w");
    if (!fp) return;
    
    time_t now = time(NULL);
    fprintf(fp, "=== TLS Handshake Performance Report with CPU Usage ===\n");
    fprintf(fp, "Generated at: %s", ctime(&now));
    fprintf(fp, "Total Tests: %d\n\n", completed_tests);
    
    // Statistics with CPU data
    int successful = 0;
    double total_time = 0, total_cpu = 0;
    double total_classical_cpu = 0, total_pqc_cpu = 0;
    
    for (int i = 0; i < completed_tests; i++) {
        if (performance_results[i].test_success) {
            total_time += performance_results[i].handshake_total_time;
            total_cpu += performance_results[i].handshake_total_cpu;
            total_classical_cpu += (performance_results[i].classical_keygen_cpu +
                                   performance_results[i].classical_sign_cpu +
                                   performance_results[i].classical_verify_cpu) / 3.0;
            total_pqc_cpu += (performance_results[i].pqc_keygen_cpu +
                             performance_results[i].pqc_encap_cpu +
                             performance_results[i].pqc_decap_cpu +
                             performance_results[i].pqc_sign_cpu +
                             performance_results[i].pqc_verify_cpu) / 5.0;
            successful++;
        }
    }
    
    if (successful > 0) {
        fprintf(fp, "PERFORMANCE SUMMARY:\n");
        fprintf(fp, "Successful Tests: %d/%d (%.1f%%)\n", successful, completed_tests,
                (double)successful/completed_tests*100);
        fprintf(fp, "Average Handshake Time: %.2f ms (%.1f%% CPU)\n", 
                total_time/successful, total_cpu/successful);
        fprintf(fp, "Average Classical CPU: %.1f%%\n", total_classical_cpu/successful);
        fprintf(fp, "Average PQC CPU: %.1f%%\n", total_pqc_cpu/successful);
        fprintf(fp, "\n");
    }
    
    fprintf(fp, "DETAILED PERFORMANCE WITH CPU USAGE:\n");
    fprintf(fp, "TestID | Total(ms) | Classical(ms) | PQC(ms) | ClassicalCPU(%%) | PQCCPU(%%) | Status\n");
    fprintf(fp, "-------|-----------|---------------|---------|------------------|-----------|--------\n");
    
    for (int i = 0; i < completed_tests; i++) {
        double classical_time = performance_results[i].classical_keygen_time + 
                               performance_results[i].classical_sign_time + 
                               performance_results[i].classical_verify_time;
        double pqc_time = performance_results[i].pqc_keygen_time + 
                         performance_results[i].pqc_encap_time + 
                         performance_results[i].pqc_decap_time + 
                         performance_results[i].pqc_sign_time + 
                         performance_results[i].pqc_verify_time;
        
        double classical_cpu = (performance_results[i].classical_keygen_cpu + 
                               performance_results[i].classical_sign_cpu + 
                               performance_results[i].classical_verify_cpu) / 3.0;
        double pqc_cpu = (performance_results[i].pqc_keygen_cpu + 
                         performance_results[i].pqc_encap_cpu + 
                         performance_results[i].pqc_decap_cpu + 
                         performance_results[i].pqc_sign_cpu + 
                         performance_results[i].pqc_verify_cpu) / 5.0;
        
        fprintf(fp, "%6d | %9.2f | %13.2f | %7.2f | %16.1f | %9.1f | %s\n",
                performance_results[i].test_id,
                performance_results[i].handshake_total_time,
                classical_time,
                pqc_time,
                classical_cpu,
                pqc_cpu,
                performance_results[i].test_success ? "SUCCESS" : "FAILED");
    }
    
    fclose(fp);
}

int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    
    printf("=== Comprehensive Hybrid TLS Performance Testing with CPU Monitoring ===\n");
    printf("Testing all 144 protocol combinations...\n\n");
    
    // Install crash handler
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGFPE, crash_handler);
    
    // Initialize OpenSSL and LibOQS
    SSL_library_init();
    SSL_load_error_strings();
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    
    if (initialize_liboqs() != 0) {
        fprintf(stderr, "Failed to initialize LibOQS\n");
        return 1;
    }
    
    // Generate all 144 test combinations
    test_config_t* all_tests = malloc(144 * sizeof(test_config_t));
    if (!all_tests) {
        fprintf(stderr, "Failed to allocate memory for test configurations\n");
        return 1;
    }
    
    int total_tests = 0;
    generate_144_test_combinations(all_tests, &total_tests);
    
    printf("Generated %d test combinations to execute\n", total_tests);
    printf("Estimated total time: %.1f - %.1f minutes\n\n", 
           total_tests * 0.05 / 60.0, total_tests * 0.2 / 60.0);
    
    // Execute all tests
    time_t start_time = time(NULL);
    
    for (int i = 0; i < total_tests; i++) {
        current_test_id = all_tests[i].test_id;
        current_test_name = get_test_description(&all_tests[i]);
        
        printf("Progress: %d/%d (%.1f%%) - ", i + 1, total_tests, 
               (double)(i + 1) / total_tests * 100);
        
        if (run_comprehensive_test(&all_tests[i], &performance_results[i]) == 0) {
            completed_tests++;
            printf("SUCCESS (%.1fms, %.1f%% CPU)\n", 
                   performance_results[i].handshake_total_time,
                   performance_results[i].handshake_total_cpu);
        } else {
            printf("FAILED - %s\n", performance_results[i].error_message);
        }
        
        // Memory cleanup every 10 tests
        if ((i + 1) % 10 == 0) {
            time_t current_time = time(NULL);
            double elapsed = difftime(current_time, start_time);
            double estimated_total = elapsed / (i + 1) * total_tests;
            double remaining = estimated_total - elapsed;
            
            printf("  Elapsed: %.1f min, Estimated remaining: %.1f min\n", 
                   elapsed / 60.0, remaining / 60.0);
        }
    }
    
    time_t end_time = time(NULL);
    double total_elapsed = difftime(end_time, start_time);
    
    printf("\n=== Testing Complete ===\n");
    printf("Total time: %.1f minutes\n", total_elapsed / 60.0);
    printf("Successful tests: %d/%d (%.1f%%)\n", completed_tests, total_tests,
           (double)completed_tests / total_tests * 100);
    
    // Generate performance reports
    printf("\nGenerating performance reports with CPU usage data...\n");
    generate_qkd_performance_report();
    generate_tls_handshake_report();
    
    printf("\nPerformance analysis complete!\n");
    printf("Reports saved with CPU monitoring data:\n");
    printf("  - qkd_performance_report.txt\n");
    printf("  - tls_handshake_performance_report.txt\n");
    
    // Cleanup
    free(all_tests);
    cleanup_liboqs();
    EVP_cleanup();
    
    return completed_tests == total_tests ? 0 : 1;
}