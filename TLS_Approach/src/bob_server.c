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
network_session_t* global_bob_session = NULL;

void signal_handler(int sig) {
    printf("\nBob received signal %d, cleaning up...\n", sig);
    if (global_bob_session) {
        cleanup_network_session(global_bob_session);
    }
    exit(0);
}

/**
 * Bob's main protocol execution
 */
int run_bob_protocol(network_session_t* network_session, const test_config_t* config) {
    printf("\n=== Bob Starting Hybrid TLS Protocol ===\n");
    
    hybrid_tls_session_t protocol_session;
    network_session->protocol_session = &protocol_session;
    
    // Initialize protocol session
    if (initialize_hybrid_session(&protocol_session, config) != 0) {
        fprintf(stderr, "Bob: Failed to initialize protocol session\n");
        return -1;
    }
    
    // Bob setup
    if (bob_setup_keys(&protocol_session) != 0) {
        fprintf(stderr, "Bob: Key setup failed\n");
        return -1;
    }
    
    // Wait for ma message from Alice
    printf("Bob: Waiting for ma message from Alice...\n");
    
    network_message_type_t msg_type;
    unsigned char recv_buffer[BUFFER_SIZE];
    size_t recv_len = sizeof(recv_buffer);
    
    if (receive_network_message(network_session, &msg_type, recv_buffer, &recv_len) != 0) {
        fprintf(stderr, "Bob: Failed to receive ma message\n");
        return -1;
    }
    
    if (msg_type != MSG_MA_MESSAGE) {
        fprintf(stderr, "Bob: Expected ma message, got type %d\n", msg_type);
        return -1;
    }
    
    printf("Bob: Received ma message from Alice (%zu bytes)\n", recv_len);
    
    // For demo simplicity, simulate the protocol steps
    // In full implementation, you'd properly deserialize and process the received data
    
    // Simulate Alice's ma message processing
    if (alice_setup_keys(&protocol_session) != 0) {
        return -1;
    }
    
    if (alice_create_ma_message(&protocol_session) != 0) {
        return -1;
    }
    
    if (alice_sign_ma_message(&protocol_session) != 0) {
        return -1;
    }
    
    // Bob verifies ma message
    if (bob_verify_ma_message(&protocol_session) != 0) {
        fprintf(stderr, "Bob: ma message verification failed\n");
        return -1;
    }
    
    // Bob creates and signs mb message
    if (bob_create_mb_message(&protocol_session) != 0) {
        fprintf(stderr, "Bob: mb message creation failed\n");
        return -1;
    }
    
    if (bob_sign_mb_message(&protocol_session) != 0) {
        fprintf(stderr, "Bob: mb message signing failed\n");
        return -1;
    }
    
    // Send mb message to Alice
    printf("Bob: Sending mb message to Alice...\n");
    if (send_mb_message(network_session, &protocol_session.mb_msg,
                       protocol_session.mb_classical_sig, protocol_session.mb_classical_sig_len,
                       protocol_session.mb_pqc_sig, protocol_session.mb_pqc_sig_len,
                       protocol_session.mb_mac, POLY1305_TAG_SIZE) != 0) {
        fprintf(stderr, "Bob: Failed to send mb message\n");
        return -1;
    }
    
    // Continue with key derivation
    if (alice_process_mb_message(&protocol_session) != 0) {
        return -1;
    }
    
    if (alice_derive_final_key(&protocol_session) != 0) {
        return -1;
    }
    
    if (bob_derive_final_key(&protocol_session) != 0) {
        fprintf(stderr, "Bob: Final key derivation failed\n");
        return -1;
    }
    
    // Mark handshake complete
    network_session->handshake_complete = 1;
    
    printf("Bob: Handshake completed successfully!\n");
    printf("Bob: Final key: ");
    for (int i = 0; i < FINAL_KEY_SIZE; i++) {
        printf("%02x", protocol_session.k_final[i]);
    }
    printf("\n");
    
    // Wait for handshake completion from Alice
    if (receive_network_message(network_session, &msg_type, recv_buffer, &recv_len) != 0) {
        fprintf(stderr, "Bob: Failed to receive handshake completion\n");
        return -1;
    }
    
    if (msg_type != MSG_HANDSHAKE_COMPLETE) {
        fprintf(stderr, "Bob: Expected handshake completion, got type %d\n", msg_type);
        return -1;
    }
    
    printf("Bob: Received handshake completion from Alice\n");
    
    // Demo TLS communication
    printf("\nBob: Starting TLS communication demo...\n");
    
    // Wait for Alice's TLS data
    char alice_message[256];
    if (receive_tls_data(network_session, alice_message, sizeof(alice_message)) != 0) {
        fprintf(stderr, "Bob: Failed to receive TLS data from Alice\n");
        return -1;
    }
    
    // Send response to Alice
    const char* bob_response = "Hello Alice! This is Bob responding via secure Hybrid TLS channel!";
    if (send_tls_data(network_session, bob_response) != 0) {
        fprintf(stderr, "Bob: Failed to send TLS response to Alice\n");
        return -1;
    }
    
    printf("Bob: Successfully completed TLS communication!\n");
    
    // Cleanup protocol session
    cleanup_hybrid_session(&protocol_session);
    
    return 0;
}

/**
 * Main Bob server
 */
int main(int argc, char* argv[]) {
    printf("=== Bob - Hybrid TLS Server ===\n");
    
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Parse command line arguments
    int bob_port = DEFAULT_BOB_PORT;
    
    if (argc >= 2) {
        bob_port = atoi(argv[1]);
    }
    
    printf("Bob: Starting server on port %d\n", bob_port);
    printf("Bob: Use Ctrl+C to stop the server\n\n");
    
    // Initialize libraries
    if (initialize_liboqs() != 0) {
        fprintf(stderr, "Bob: Failed to initialize LibOQS\n");
        return 1;
    }
    
    // Initialize network session
    network_session_t bob_session;
    global_bob_session = &bob_session;
    
    if (init_network_session(&bob_session, "Bob", bob_port) != 0) {
        fprintf(stderr, "Bob: Failed to initialize network session\n");
        return 1;
    }
    
    // Start server
    if (start_server(&bob_session) != 0) {
        fprintf(stderr, "Bob: Failed to start server\n");
        cleanup_network_session(&bob_session);
        return 1;
    }
    
    // Server loop
    while (1) {
        printf("\n=== Bob waiting for Alice connection ===\n");
        
        // Accept connection from Alice
        if (accept_connection(&bob_session) != 0) {
            fprintf(stderr, "Bob: Failed to accept connection\n");
            continue;
        }
        
        print_network_info(&bob_session);
        
        // Run the hybrid TLS protocol
        test_config_t config = {0, CLASSICAL_ECDHE_P256, SIG_ECDSA_P256, 
                               PQC_ML_KEM_768, PQC_ML_DSA_65, QKD_BB84};
        
        int result = run_bob_protocol(&bob_session, &config);
        
        if (result == 0) {
            printf("\nBob: Protocol execution completed successfully!\n");
            printf("Bob: TLS connection established and data exchanged.\n");
            
            // Keep connection alive for a bit
            printf("Bob: Keeping connection alive for 15 seconds...\n");
            sleep(15);
        } else {
            printf("\nBob: Protocol execution failed!\n");
        }
        
        // Close client connection
        if (bob_session.client_fd >= 0 && bob_session.client_fd != bob_session.socket_fd) {
            close(bob_session.client_fd);
            bob_session.client_fd = -1;
        }
        bob_session.connected = 0;
        bob_session.handshake_complete = 0;
        
        printf("Bob: Client disconnected, ready for next connection...\n");
    }
    
    // Cleanup (unreachable in normal operation)
    cleanup_network_session(&bob_session);
    cleanup_liboqs();
    
    return 0;
}