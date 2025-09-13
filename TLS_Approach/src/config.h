#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

// Maximum limits
#define MAX_KEY_SIZE 1024
#define MAX_SIGNATURE_SIZE 2048
#define MAX_MESSAGE_SIZE 4096
#define SHA3_512_DIGEST_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define UUID_LENGTH 16

// Classical Key Exchange Algorithms
typedef enum {
    CLASSICAL_ECDHE_P256 = 0,
    CLASSICAL_ECDHE_P384,
    CLASSICAL_X25519,
    CLASSICAL_MAX
} classical_kex_t;

// Classical Digital Signature Algorithms  
typedef enum {
    SIG_ECDSA_P256 = 0,
    SIG_ECDSA_P384,
    SIG_ED25519,
    SIG_MAX
} classical_sig_t;

// Post-Quantum Key Encapsulation Mechanisms
typedef enum {
    PQC_ML_KEM_768 = 0,
    PQC_HQC_192,
    PQC_BIKE_L3,
    PQC_KEM_MAX
} pqc_kem_t;

// Post-Quantum Digital Signature Algorithms
typedef enum {
    PQC_ML_DSA_65 = 0,
    PQC_FALCON_512,
    PQC_SPHINCS_SHA2_192F,
    PQC_SPHINCS_SHAKE_192F,
    PQC_SIG_MAX
} pqc_sig_t;

// QKD Protocols
typedef enum {
    QKD_BB84 = 0,
    QKD_E91,
    QKD_MDI,
    QKD_MAX
} qkd_protocol_t;

// Test configuration structure
typedef struct {
    int test_id;
    classical_kex_t classical_kex;
    classical_sig_t classical_sig;
    pqc_kem_t pqc_kem;
    pqc_sig_t pqc_sig;
    qkd_protocol_t qkd_protocol;
} test_config_t;

// QKD key data structure (matching stage.c)
typedef struct {
    unsigned char kqkdm[SHA3_512_DIGEST_LENGTH];  // SHA3-512 hash of original key
    unsigned char uuid[UUID_LENGTH];              // First 128 bits of SHA-256 hash
    int valid;                                    // Flag to indicate if data is valid
} qkd_key_data_t;

// Performance metrics structure
typedef struct {
    double classical_keygen_time;
    double classical_sign_time;
    double classical_verify_time;
    double pqc_keygen_time;
    double pqc_encap_time;
    double pqc_decap_time;
    double pqc_sign_time;
    double pqc_verify_time;
    double qkd_derive_time;
    double mac_compute_time;
    double mac_verify_time;
    double total_handshake_time;
    size_t memory_usage;
} performance_metrics_t;

// Algorithm name mappings for display
extern const char* classical_kex_names[CLASSICAL_MAX];
extern const char* classical_sig_names[SIG_MAX];
extern const char* pqc_kem_names[PQC_KEM_MAX];
extern const char* pqc_sig_names[PQC_SIG_MAX];
extern const char* qkd_protocol_names[QKD_MAX];

// LibOQS algorithm name mappings
extern const char* liboqs_kem_names[PQC_KEM_MAX];
extern const char* liboqs_sig_names[PQC_SIG_MAX];

// Function prototypes
void generate_test_matrix(test_config_t* tests, int* total_tests);
const char* get_test_description(const test_config_t* config);
int calculate_total_combinations(void);

#endif // CONFIG_H