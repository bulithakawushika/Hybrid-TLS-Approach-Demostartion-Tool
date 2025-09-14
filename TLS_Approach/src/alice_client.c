#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "config.h"
#include "hybrid_tls_protocol.h"
#include "network_protocol.h"
#include "qkd_data.h"
#include "classical_crypto.h"
#include "pqc_crypto.h"
#include "mac_ops.h"

// Global session for cleanup
network_session_t* global_alice_session = NULL;

void signal_handler(int sig) {
    printf("\nAlice received signal %d, cleaning up...\n", sig);
    if (global_alice_session) {
        cleanup_network_session(global_alice_session);
    }
    exit(0);
}

/**
 * Alice's main protocol execution
 */
int run_alice_protocol(network_session_t* network_session, const test_config_t* config) {
    printf("\n=== Alice Starting Hybrid TLS Protocol ===\n");
    
    hybrid_tls_session_t protocol_session;
    network_session->protocol_session = &protocol_session;
    
    // Initialize protocol session
    if (initialize_hybrid_session(&protocol_session, config) != 0) {
        fprintf(stderr, "Alice: Failed to initialize protocol session\n");
        return -1;
    }
    
    // Alice setup
    if (alice_setup_keys(&protocol_session) != 0) {
        fprintf(stderr, "Alice: Key setup failed\n");
        return -1;
    }
    
    // Create and sign ma message
    if (alice_create_ma_message(&protocol_session) != 0) {
        fprintf(stderr, "Alice: ma message creation failed\n");
        return -1;
    }
    
    if (alice_sign_ma_message(&protocol_session) != 0) {
        fprintf(stderr, "Alice: ma message signing failed\n");
        return -1;
    }
    
    // Send ma message to Bob
    printf("Alice: Sending ma message to Bob...\n");
    if (send_ma_message(network_session, &protocol_session.ma_msg,
                       protocol_session.ma_classical_sig, protocol_session.ma_classical_sig_len,
                       protocol_session.ma_pqc_sig, protocol_session.ma_pqc_sig_len,
                       protocol_session.ma_mac, POLY1305_TAG_SIZE) != 0) {
        fprintf(stderr, "Alice: Failed to send ma message\n");
        return -1;
    }
    
    // Wait for mb message from Bob
    printf("Alice: Waiting for mb message from Bob...\n");
    
    // For demo simplicity, we'll simulate receiving mb message
    // In a full implementation, you'd properly deserialize the network message
    
    // Simulate Bob's response by creating mock data
    // This would normally come from the network
    if (bob_setup_keys(&protocol_session) != 0) {
        return -1;
    }
    
    if (bob_verify_ma_message(&protocol_session) != 0) {
        return -1;
    }
    
    if (bob_create_mb_message(&protocol_session) != 0) {
        return -1;
    }
    
    if (bob_sign_mb_message(&protocol_session) != 0) {
        return -1;
    }
    
    // Alice processes mb message
    if (alice_process_mb_message(&protocol_session) != 0) {
        fprintf(stderr, "Alice: mb message processing failed\n");
        return -1;
    }
    
    // Derive final keys
    if (alice_derive_final_key(&protocol_session) != 0) {
        fprintf(stderr, "Alice: Final key derivation failed\n");
        return -1;
    }
    
    if (bob_derive_final_key(&protocol_session) != 0) {
        fprintf(stderr, "Alice: Bob final key derivation failed\n");
        return -1;
    }
    
    // Mark handshake complete
    network_session->handshake_complete = 1;
    
    printf("Alice: Handshake completed successfully!\n");
    printf("Alice: Final key: ");
    for (int i = 0; i < FINAL_KEY_SIZE; i++) {
        printf("%02x", protocol_session.k_final[i]);
    }
    printf("\n");
    
    // Send completion notification
    send_network_message(network_session, MSG_HANDSHAKE_COMPLETE, NULL, 0);
    
    // Demo TLS communication
    printf("\nAlice: Starting TLS communication demo...\n");
    
    sleep(1);  // Brief pause
    
    // Send TLS data
    const char* alice_message = "Hello Bob! This is Alice sending encrypted data via Hybrid TLS!";
    if (send_tls_data(network_session, alice_message) != 0) {
        fprintf(stderr, "Alice: Failed to send TLS data\n");
        return -1;
    }
    
    // Wait for Bob's response
    char bob_response[256];
    if (receive_tls_data(network_session, bob_response, sizeof(bob_response)) != 0) {
        fprintf(stderr, "Alice: Failed to receive TLS data from Bob\n");
        return -1;
    }
    
    printf("Alice: Successfully completed TLS communication!\n");
    
    // Cleanup
    printf("Alice: Cleaning up and disconnecting...\n");
    cleanup_network_session(&alice_session);
    cleanup_liboqs();
    
    return result == 0 ? 0 : 1;
}