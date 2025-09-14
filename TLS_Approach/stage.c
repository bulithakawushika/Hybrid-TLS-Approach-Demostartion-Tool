#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cjson/cJSON.h>
#include "src/qkd_data.h"

// Configuration constants
#define MAX_RETRIES 200              // Increased from 10 to 200
#define MAX_OUTPUT_SIZE 32768        // Increased buffer size
#define SHA3_512_DIGEST_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define UUID_LENGTH 16  // 128 bits = 16 bytes

// QKD data is now defined in src/qkd_data.c and declared in src/qkd_data.h

/**
 * Execute a Python QKD script and capture its output
 */
int execute_qkd_script(const char* script_path, char* output, size_t output_size) {
    char command[512];
    snprintf(command, sizeof(command), 
             "cd QKD_Scripts && python3 %s --distance 10 --format json --quiet", 
             script_path);
    
    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to execute command: %s\n", command);
        return -1;
    }
    
    size_t total_read = 0;
    size_t bytes_read;
    
    // Read output from the script with better buffer management
    while ((bytes_read = fread(output + total_read, 1, 
                              output_size - total_read - 1, fp)) > 0) {
        total_read += bytes_read;
        if (total_read >= output_size - 1) {
            fprintf(stderr, "Output buffer overflow - output too large\n");
            pclose(fp);
            return -1;
        }
    }
    
    output[total_read] = '\0';
    
    int status = pclose(fp);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    
    return -1;
}

/**
 * Parse JSON output from QKD script and extract key and success status
 */
int parse_qkd_result(const char* json_output, char* key, size_t key_size, int* success) {
    if (json_output == NULL || strlen(json_output) == 0) {
        fprintf(stderr, "Empty JSON output\n");
        return -1;
    }
    
    cJSON* json = cJSON_Parse(json_output);
    if (json == NULL) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "JSON Parse Error before: %s\n", error_ptr);
        } else {
            fprintf(stderr, "Failed to parse JSON output\n");
        }
        return -1;
    }
    
    // Get success status
    cJSON* success_item = cJSON_GetObjectItem(json, "success");
    if (!cJSON_IsBool(success_item)) {
        fprintf(stderr, "Missing or invalid 'success' field in JSON\n");
        cJSON_Delete(json);
        return -1;
    }
    *success = cJSON_IsTrue(success_item);
    
    // If successful, get the key
    if (*success) {
        cJSON* alice_key = cJSON_GetObjectItem(json, "alice_key");
        if (!cJSON_IsString(alice_key)) {
            fprintf(stderr, "Missing or invalid 'alice_key' field in JSON\n");
            cJSON_Delete(json);
            return -1;
        }
        
        const char* key_str = cJSON_GetStringValue(alice_key);
        if (key_str == NULL) {
            fprintf(stderr, "Failed to get key string value\n");
            cJSON_Delete(json);
            return -1;
        }
        
        size_t key_len = strlen(key_str);
        if (key_len >= key_size) {
            fprintf(stderr, "Key too long: %zu >= %zu\n", key_len, key_size);
            cJSON_Delete(json);
            return -1;
        }
        
        strncpy(key, key_str, key_size - 1);
        key[key_size - 1] = '\0';
    }
    
    cJSON_Delete(json);
    return 0;
}

/**
 * Compute SHA3-512 hash of input data
 */
int hash_sha3_512(const char* input, unsigned char* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_DigestUpdate(ctx, input, strlen(input)) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    unsigned int digest_len;
    if (EVP_DigestFinal_ex(ctx, output, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    return 0;
}

/**
 * Compute SHA-256 hash and extract first 128 bits (16 bytes)
 */
int hash_sha256_128bits(const char* input, unsigned char* output) {
    unsigned char full_hash[SHA256_DIGEST_LENGTH];
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_DigestUpdate(ctx, input, strlen(input)) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    unsigned int digest_len;
    if (EVP_DigestFinal_ex(ctx, full_hash, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Copy first 128 bits (16 bytes)
    memcpy(output, full_hash, UUID_LENGTH);
    return 0;
}

/**
 * Print hex representation of binary data
 */
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

/**
 * Process a single QKD protocol and generate keys
 */
int process_qkd_protocol(const char* protocol_name, const char* script_name, 
                        qkd_key_data_t* key_data) {
    char* output = malloc(MAX_OUTPUT_SIZE);
    char* original_key = malloc(MAX_KEY_SIZE);
    
    if (output == NULL || original_key == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        free(output);
        free(original_key);
        return -1;
    }
    
    int success = 0;
    int retry_count = 0;
    
    printf("Starting %s key generation (max %d retries)...\n", protocol_name, MAX_RETRIES);
    
    // Retry until successful or max retries reached
    do {
        retry_count++;
        if (retry_count <= 10 || retry_count % 50 == 0) {
            printf("  Attempt %d: Executing %s...\n", retry_count, script_name);
        }
        
        // Execute the QKD script
        int exit_code = execute_qkd_script(script_name, output, MAX_OUTPUT_SIZE);
        
        if (exit_code == 0) {
            // Parse the output
            if (parse_qkd_result(output, original_key, MAX_KEY_SIZE, &success) == 0) {
                if (success) {
                    printf("  %s key generation successful after %d attempts! Key length: %zu bits\n", 
                           protocol_name, retry_count, strlen(original_key));
                    break;
                } else {
                    if (retry_count <= 10 || retry_count % 50 == 0) {
                        printf("  %s key generation failed (QBER too high or insufficient bits)\n", 
                               protocol_name);
                    }
                }
            } else {
                if (retry_count <= 10 || retry_count % 50 == 0) {
                    printf("  Failed to parse %s script output\n", protocol_name);
                }
            }
        } else {
            if (retry_count <= 10 || retry_count % 50 == 0) {
                printf("  %s script execution failed with exit code: %d\n", 
                       protocol_name, exit_code);
            }
        }
        
        if (retry_count >= MAX_RETRIES) {
            fprintf(stderr, "  Maximum retries (%d) reached for %s\n", 
                    MAX_RETRIES, protocol_name);
            free(output);
            free(original_key);
            return -1;
        }
        
        if (retry_count <= 10 || retry_count % 50 == 0) {
            printf("  Retrying %s key generation...\n", protocol_name);
        }
        
        // Brief delay before retry (shorter delay for faster iteration)
        if (retry_count < 50) {
            usleep(100000); // 0.1 second for first 50 attempts
        } else {
            usleep(50000);  // 0.05 second for subsequent attempts
        }
        
    } while (!success);
    
    // Generate kqkdm (SHA3-512 of original key)
    if (hash_sha3_512(original_key, key_data->kqkdm) != 0) {
        fprintf(stderr, "Failed to generate SHA3-512 hash for %s\n", protocol_name);
        free(output);
        free(original_key);
        return -1;
    }
    
    // Generate uuid (first 128 bits of SHA-256 of original key)
    if (hash_sha256_128bits(original_key, key_data->uuid) != 0) {
        fprintf(stderr, "Failed to generate SHA-256 hash for %s\n", protocol_name);
        free(output);
        free(original_key);
        return -1;
    }
    
    key_data->valid = 1;
    
    printf("  Generated kqkdm_%s (SHA3-512): ", protocol_name);
    print_hex(key_data->kqkdm, SHA3_512_DIGEST_LENGTH);
    printf("\n");
    
    printf("  Generated uuid_%s (SHA-256 128-bit): ", protocol_name);
    print_hex(key_data->uuid, UUID_LENGTH);
    printf("\n");
    
    printf("Complete %s Key management successfully.\n\n", protocol_name);
    
    // Clear the original key from memory for security
    memset(original_key, 0, MAX_KEY_SIZE);
    free(output);
    free(original_key);
    
    return 0;
}

/**
 * Clean up sensitive data from memory
 */
void cleanup_memory() {
    // Clear all sensitive key material
    memset(&bb84_data, 0, sizeof(bb84_data));
    memset(&e91_data, 0, sizeof(e91_data));
    memset(&mdi_data, 0, sizeof(mdi_data));
}

/**
 * Display summary of all generated keys
 */
void display_summary() {
    printf("=== QKD Key Management Summary ===\n");
    
    if (bb84_data.valid) {
        printf("BB84 - Status: SUCCESS\n");
        printf("  kqkdm_bb84: ");
        print_hex(bb84_data.kqkdm, SHA3_512_DIGEST_LENGTH);
        printf("\n  uuid_bb84:  ");
        print_hex(bb84_data.uuid, UUID_LENGTH);
        printf("\n");
    } else {
        printf("BB84 - Status: FAILED\n");
    }
    
    if (e91_data.valid) {
        printf("E91  - Status: SUCCESS\n");
        printf("  kqkdm_e91:  ");
        print_hex(e91_data.kqkdm, SHA3_512_DIGEST_LENGTH);
        printf("\n  uuid_e91:   ");
        print_hex(e91_data.uuid, UUID_LENGTH);
        printf("\n");
    } else {
        printf("E91  - Status: FAILED\n");
    }
    
    if (mdi_data.valid) {
        printf("MDI  - Status: SUCCESS\n");
        printf("  kqkdm_mdi:  ");
        print_hex(mdi_data.kqkdm, SHA3_512_DIGEST_LENGTH);
        printf("\n  uuid_mdi:   ");
        print_hex(mdi_data.uuid, UUID_LENGTH);
        printf("\n");
    } else {
        printf("MDI  - Status: FAILED\n");
    }
    
    printf("=====================================\n");
}

/**
 * Save QKD keys to a temporary file for other programs to load
 */
int save_qkd_keys_to_file() {
    FILE* fp = fopen("/tmp/qkd_keys.dat", "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to create QKD keys file\n");
        return -1;
    }
    
    // Write all three key structures
    fwrite(&bb84_data, sizeof(qkd_key_data_t), 1, fp);
    fwrite(&e91_data, sizeof(qkd_key_data_t), 1, fp);
    fwrite(&mdi_data, sizeof(qkd_key_data_t), 1, fp);
    
    fclose(fp);
    
    printf("QKD keys saved to /tmp/qkd_keys.dat\n");
    return 0;
}

/**
 * Main function - with non-blocking option
 */
int main(int argc, char* argv[]) {
    // Check if running in non-blocking mode
    int non_blocking = 0;
    if (argc > 1 && strcmp(argv[1], "--non-blocking") == 0) {
        non_blocking = 1;
    }
    
    printf("=== QKD Key Generation Stage ===\n");
    printf("Generating quantum keys for hybrid TLS implementation...\n");
    printf("Maximum retries per protocol: %d\n\n", MAX_RETRIES);
    
    // Initialize OpenSSL
    OpenSSL_add_all_digests();
    
    // Process BB84
    if (process_qkd_protocol("BB84", "bb84_keygen.py", &bb84_data) != 0) {
        fprintf(stderr, "Failed to process BB84 protocol\n");
        goto cleanup;
    }
    
    // Process E91
    if (process_qkd_protocol("E91", "e91_keygen.py", &e91_data) != 0) {
        fprintf(stderr, "Failed to process E91 protocol\n");
        goto cleanup;
    }
    
    // Process MDI-QKD
    if (process_qkd_protocol("MDI-QKD", "mdi_keygen.py", &mdi_data) != 0) {
        fprintf(stderr, "Failed to process MDI-QKD protocol\n");
        goto cleanup;
    }
    
    // Display summary
    display_summary();
    
    // Save keys to file for other programs to use
    if (save_qkd_keys_to_file() != 0) {
        fprintf(stderr, "Failed to save QKD keys to file\n");
        goto cleanup;
    }
    
    printf("All QKD protocols processed successfully!\n");
    printf("Keys are stored in /tmp/qkd_keys.dat for TLS integration.\n");
    
    if (non_blocking) {
        printf("Running in non-blocking mode - keys saved and ready for use.\n");
    } else {
        // Interactive mode - wait for user input
        printf("\nPress Enter to clear keys and exit...");
        getchar();
    }
    
cleanup:
    if (!non_blocking) {
        cleanup_memory();
    }
    EVP_cleanup();
    
    return 0;
}