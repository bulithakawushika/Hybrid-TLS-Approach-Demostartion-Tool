#ifndef NETWORK_PROTOCOL_H
#define NETWORK_PROTOCOL_H

#include "config.h"
#include "hybrid_tls_protocol.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Network configuration
#define DEFAULT_ALICE_PORT 8080
#define DEFAULT_BOB_PORT 8081
#define MAX_CONNECTIONS 1
#define BUFFER_SIZE 16384

// Message types for network protocol
typedef enum {
    MSG_MA_MESSAGE = 1,
    MSG_MA_SIGNATURE = 2,
    MSG_MB_MESSAGE = 3,
    MSG_MB_SIGNATURE = 4,
    MSG_TLS_DATA = 5,
    MSG_HANDSHAKE_COMPLETE = 6,
    MSG_ERROR = 255
} network_message_type_t;

// Network message structure
typedef struct {
    network_message_type_t type;
    uint32_t length;
    unsigned char data[];
} network_message_t;

// Network session data
typedef struct {
    int socket_fd;
    int client_fd;
    struct sockaddr_in address;
    int port;
    char role[10];  // "Alice" or "Bob"
    
    // Protocol session
    hybrid_tls_session_t* protocol_session;
    
    // Network buffers
    unsigned char send_buffer[BUFFER_SIZE];
    unsigned char recv_buffer[BUFFER_SIZE];
    
    // Connection state
    int connected;
    int handshake_complete;
} network_session_t;

// Function prototypes

// Network initialization
int init_network_session(network_session_t* session, const char* role, int port);
void cleanup_network_session(network_session_t* session);

// Server/Client functions
int start_server(network_session_t* session);
int connect_to_server(network_session_t* session, const char* server_ip, int server_port);
int accept_connection(network_session_t* session);

// Message transmission
int send_network_message(network_session_t* session, network_message_type_t type, 
                        const unsigned char* data, size_t data_len);
int receive_network_message(network_session_t* session, network_message_type_t* type,
                           unsigned char* data, size_t* data_len);

// Protocol message handlers
int send_ma_message(network_session_t* session, const ma_message_t* ma_msg,
                   const unsigned char* classical_sig, size_t classical_sig_len,
                   const unsigned char* pqc_sig, size_t pqc_sig_len,
                   const unsigned char* mac, size_t mac_len);

int receive_ma_message(network_session_t* session, ma_message_t* ma_msg,
                      unsigned char* classical_sig, size_t* classical_sig_len,
                      unsigned char* pqc_sig, size_t* pqc_sig_len,
                      unsigned char* mac, size_t* mac_len);

int send_mb_message(network_session_t* session, const mb_message_t* mb_msg,
                   const unsigned char* classical_sig, size_t classical_sig_len,
                   const unsigned char* pqc_sig, size_t pqc_sig_len,
                   const unsigned char* mac, size_t mac_len);

int receive_mb_message(network_session_t* session, mb_message_t* mb_msg,
                      unsigned char* classical_sig, size_t* classical_sig_len,
                      unsigned char* pqc_sig, size_t* pqc_sig_len,
                      unsigned char* mac, size_t* mac_len);

// TLS demo functions
int send_tls_data(network_session_t* session, const char* message);
int receive_tls_data(network_session_t* session, char* message, size_t max_len);

// Network utility functions
int create_socket(void);
int bind_socket(int socket_fd, int port);
int setup_socket_options(int socket_fd);
void print_network_info(const network_session_t* session);

#endif // NETWORK_PROTOCOL_H