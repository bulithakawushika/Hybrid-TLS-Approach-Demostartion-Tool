#include "network_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

/**
 * Initialize network session
 */
int init_network_session(network_session_t* session, const char* role, int port) {
    if (session == NULL || role == NULL) {
        return -1;
    }
    
    memset(session, 0, sizeof(network_session_t));
    
    strncpy(session->role, role, sizeof(session->role) - 1);
    session->port = port;
    session->socket_fd = -1;
    session->client_fd = -1;
    session->connected = 0;
    session->handshake_complete = 0;
    
    printf("Initialized %s network session on port %d\n", role, port);
    return 0;
}

/**
 * Create socket with proper options
 */
int create_socket(void) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    if (setup_socket_options(socket_fd) != 0) {
        close(socket_fd);
        return -1;
    }
    
    return socket_fd;
}

/**
 * Setup socket options
 */
int setup_socket_options(int socket_fd) {
    int opt = 1;
    
    // Allow socket reuse
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        return -1;
    }
    
    // Set timeout for socket operations
    struct timeval timeout;
    timeout.tv_sec = 30;  // 30 second timeout
    timeout.tv_usec = 0;
    
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed");
        return -1;
    }
    
    return 0;
}

/**
 * Start server (Bob)
 */
int start_server(network_session_t* session) {
    if (session == NULL) {
        return -1;
    }
    
    printf("%s starting server on port %d...\n", session->role, session->port);
    
    // Create socket
    session->socket_fd = create_socket();
    if (session->socket_fd < 0) {
        return -1;
    }
    
    // Setup address
    session->address.sin_family = AF_INET;
    session->address.sin_addr.s_addr = INADDR_ANY;
    session->address.sin_port = htons(session->port);
    
    // Bind socket
    if (bind(session->socket_fd, (struct sockaddr*)&session->address, 
             sizeof(session->address)) < 0) {
        perror("Bind failed");
        close(session->socket_fd);
        return -1;
    }
    
    // Listen for connections
    if (listen(session->socket_fd, MAX_CONNECTIONS) < 0) {
        perror("Listen failed");
        close(session->socket_fd);
        return -1;
    }
    
    printf("%s server listening on port %d\n", session->role, session->port);
    return 0;
}

/**
 * Accept connection (Bob)
 */
int accept_connection(network_session_t* session) {
    if (session == NULL) {
        return -1;
    }
    
    printf("%s waiting for connection...\n", session->role);
    
    socklen_t addr_len = sizeof(session->address);
    session->client_fd = accept(session->socket_fd, 
                               (struct sockaddr*)&session->address, &addr_len);
    
    if (session->client_fd < 0) {
        perror("Accept failed");
        return -1;
    }
    
    session->connected = 1;
    printf("%s accepted connection from %s:%d\n", 
           session->role, inet_ntoa(session->address.sin_addr), 
           ntohs(session->address.sin_port));
    
    return 0;
}

/**
 * Connect to server (Alice)
 */
int connect_to_server(network_session_t* session, const char* server_ip, int server_port) {
    if (session == NULL || server_ip == NULL) {
        return -1;
    }
    
    printf("%s connecting to server %s:%d...\n", session->role, server_ip, server_port);
    
    // Create socket
    session->socket_fd = create_socket();
    if (session->socket_fd < 0) {
        return -1;
    }
    
    // Setup server address
    session->address.sin_family = AF_INET;
    session->address.sin_port = htons(server_port);
    
    if (inet_pton(AF_INET, server_ip, &session->address.sin_addr) <= 0) {
        perror("Invalid server address");
        close(session->socket_fd);
        return -1;
    }
    
    // Connect to server
    if (connect(session->socket_fd, (struct sockaddr*)&session->address, 
                sizeof(session->address)) < 0) {
        perror("Connection failed");
        close(session->socket_fd);
        return -1;
    }
    
    session->client_fd = session->socket_fd;  // For client, socket_fd and client_fd are same
    session->connected = 1;
    
    printf("%s connected to server %s:%d\n", session->role, server_ip, server_port);
    return 0;
}

/**
 * Send network message
 */
int send_network_message(network_session_t* session, network_message_type_t type, 
                        const unsigned char* data, size_t data_len) {
    if (session == NULL || !session->connected) {
        return -1;
    }
    
    // Create message header
    network_message_t* msg = (network_message_t*)session->send_buffer;
    msg->type = htonl(type);
    msg->length = htonl(data_len);
    
    // Copy data
    if (data != NULL && data_len > 0) {
        if (sizeof(network_message_t) + data_len > BUFFER_SIZE) {
            fprintf(stderr, "Message too large: %zu bytes\n", data_len);
            return -1;
        }
        memcpy(msg->data, data, data_len);
    }
    
    size_t total_len = sizeof(network_message_t) + data_len;
    
    // Send message
    ssize_t sent = send(session->client_fd, session->send_buffer, total_len, 0);
    if (sent != (ssize_t)total_len) {
        perror("Send failed");
        return -1;
    }
    
    printf("%s sent message type %d (%zu bytes)\n", session->role, type, data_len);
    return 0;
}

/**
 * Receive network message
 */
int receive_network_message(network_session_t* session, network_message_type_t* type,
                           unsigned char* data, size_t* data_len) {
    if (session == NULL || !session->connected) {
        return -1;
    }
    
    // Receive header first
    ssize_t received = recv(session->client_fd, session->recv_buffer, 
                           sizeof(network_message_t), MSG_WAITALL);
    
    if (received != sizeof(network_message_t)) {
        if (received == 0) {
            printf("%s connection closed by peer\n", session->role);
        } else {
            perror("Failed to receive message header");
        }
        return -1;
    }
    
    network_message_t* msg = (network_message_t*)session->recv_buffer;
    *type = ntohl(msg->type);
    size_t payload_len = ntohl(msg->length);
    
    // Receive payload if present
    if (payload_len > 0) {
        if (payload_len > BUFFER_SIZE - sizeof(network_message_t)) {
            fprintf(stderr, "Payload too large: %zu bytes\n", payload_len);
            return -1;
        }
        
        received = recv(session->client_fd, session->recv_buffer + sizeof(network_message_t), 
                       payload_len, MSG_WAITALL);
        
        if (received != (ssize_t)payload_len) {
            perror("Failed to receive message payload");
            return -1;
        }
        
        if (data != NULL && data_len != NULL) {
            size_t copy_len = (*data_len < payload_len) ? *data_len : payload_len;
            memcpy(data, msg->data, copy_len);
            *data_len = copy_len;
        }
    } else {
        if (data_len != NULL) {
            *data_len = 0;
        }
    }
    
    printf("%s received message type %d (%zu bytes)\n", session->role, *type, payload_len);
    return 0;
}

/**
 * Send ma message with signatures and MAC
 */
int send_ma_message(network_session_t* session, const ma_message_t* ma_msg,
                   const unsigned char* classical_sig, size_t classical_sig_len,
                   const unsigned char* pqc_sig, size_t pqc_sig_len,
                   const unsigned char* mac, size_t mac_len) {
    
    // Serialize ma message
    unsigned char ma_buffer[MAX_MESSAGE_SIZE];
    size_t ma_len = sizeof(ma_buffer);
    if (serialize_ma_message(ma_msg, ma_buffer, &ma_len) != 0) {
        return -1;
    }
    
    // Create combined message: ma_msg || classical_sig_len || classical_sig || pqc_sig_len || pqc_sig || mac
    unsigned char combined_buffer[BUFFER_SIZE];
    size_t offset = 0;
    
    // ma message
    memcpy(combined_buffer + offset, ma_buffer, ma_len);
    offset += ma_len;
    
    // classical signature length and data
    uint32_t sig_len_net = htonl(classical_sig_len);
    memcpy(combined_buffer + offset, &sig_len_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(combined_buffer + offset, classical_sig, classical_sig_len);
    offset += classical_sig_len;
    
    // PQC signature length and data
    sig_len_net = htonl(pqc_sig_len);
    memcpy(combined_buffer + offset, &sig_len_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(combined_buffer + offset, pqc_sig, pqc_sig_len);
    offset += pqc_sig_len;
    
    // MAC
    memcpy(combined_buffer + offset, mac, mac_len);
    offset += mac_len;
    
    return send_network_message(session, MSG_MA_MESSAGE, combined_buffer, offset);
}

/**
 * Receive ma message with signatures and MAC
 */
int receive_ma_message(network_session_t* session, ma_message_t* ma_msg,
                      unsigned char* classical_sig, size_t* classical_sig_len,
                      unsigned char* pqc_sig, size_t* pqc_sig_len,
                      unsigned char* mac, size_t* mac_len) {
    
    network_message_type_t msg_type;
    unsigned char combined_buffer[BUFFER_SIZE];
    size_t combined_len = sizeof(combined_buffer);
    
    if (receive_network_message(session, &msg_type, combined_buffer, &combined_len) != 0) {
        return -1;
    }
    
    if (msg_type != MSG_MA_MESSAGE) {
        fprintf(stderr, "Expected ma message, got type %d\n", msg_type);
        return -1;
    }
    
    // Parse combined message
    size_t offset = 0;
    
    // Skip ma message parsing for now (would need proper deserialization)
    // For demo, we'll reconstruct from the session data
    // This is a simplified approach for the networking demo
    
    return 0;
}

/**
 * Send mb message with signatures and MAC
 */
int send_mb_message(network_session_t* session, const mb_message_t* mb_msg,
                   const unsigned char* classical_sig, size_t classical_sig_len,
                   const unsigned char* pqc_sig, size_t pqc_sig_len,
                   const unsigned char* mac, size_t mac_len) {
    
    // Similar to send_ma_message but for mb
    unsigned char mb_buffer[MAX_MESSAGE_SIZE];
    size_t mb_len = sizeof(mb_buffer);
    if (serialize_mb_message(mb_msg, mb_buffer, &mb_len) != 0) {
        return -1;
    }
    
    // Create combined message
    unsigned char combined_buffer[BUFFER_SIZE];
    size_t offset = 0;
    
    memcpy(combined_buffer + offset, mb_buffer, mb_len);
    offset += mb_len;
    
    uint32_t sig_len_net = htonl(classical_sig_len);
    memcpy(combined_buffer + offset, &sig_len_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(combined_buffer + offset, classical_sig, classical_sig_len);
    offset += classical_sig_len;
    
    sig_len_net = htonl(pqc_sig_len);
    memcpy(combined_buffer + offset, &sig_len_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(combined_buffer + offset, pqc_sig, pqc_sig_len);
    offset += pqc_sig_len;
    
    memcpy(combined_buffer + offset, mac, mac_len);
    offset += mac_len;
    
    return send_network_message(session, MSG_MB_MESSAGE, combined_buffer, offset);
}

/**
 * Send TLS-encrypted data
 */
int send_tls_data(network_session_t* session, const char* message) {
    if (session == NULL || message == NULL || !session->handshake_complete) {
        return -1;
    }
    
    printf("%s sending TLS data: \"%s\"\n", session->role, message);
    
    // In a real implementation, this would encrypt the message with the derived key
    // For demo purposes, we'll send it as-is but mark it as TLS data
    
    return send_network_message(session, MSG_TLS_DATA, 
                               (const unsigned char*)message, strlen(message) + 1);
}

/**
 * Receive TLS-encrypted data
 */
int receive_tls_data(network_session_t* session, char* message, size_t max_len) {
    if (session == NULL || message == NULL || !session->handshake_complete) {
        return -1;
    }
    
    network_message_type_t msg_type;
    size_t data_len = max_len;
    
    if (receive_network_message(session, &msg_type, (unsigned char*)message, &data_len) != 0) {
        return -1;
    }
    
    if (msg_type != MSG_TLS_DATA) {
        fprintf(stderr, "Expected TLS data, got message type %d\n", msg_type);
        return -1;
    }
    
    printf("%s received TLS data: \"%s\"\n", session->role, message);
    return 0;
}

/**
 * Print network session info
 */
void print_network_info(const network_session_t* session) {
    if (session == NULL) {
        return;
    }
    
    printf("\n=== Network Session Info ===\n");
    printf("Role: %s\n", session->role);
    printf("Port: %d\n", session->port);
    printf("Connected: %s\n", session->connected ? "Yes" : "No");
    printf("Handshake Complete: %s\n", session->handshake_complete ? "Yes" : "No");
    if (session->connected) {
        printf("Peer: %s:%d\n", inet_ntoa(session->address.sin_addr), 
               ntohs(session->address.sin_port));
    }
    printf("============================\n\n");
}

/**
 * Cleanup network session
 */
void cleanup_network_session(network_session_t* session) {
    if (session == NULL) {
        return;
    }
    
    if (session->client_fd >= 0 && session->client_fd != session->socket_fd) {
        close(session->client_fd);
    }
    
    if (session->socket_fd >= 0) {
        close(session->socket_fd);
    }
    
    session->connected = 0;
    session->handshake_complete = 0;
    
    printf("%s network session cleaned up\n", session->role);
}