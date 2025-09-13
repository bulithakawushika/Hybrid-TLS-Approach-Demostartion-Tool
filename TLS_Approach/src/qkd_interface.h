#ifndef QKD_INTERFACE_H
#define QKD_INTERFACE_H

#include "config.h"

// Function prototypes for QKD interface
int get_qkd_key(qkd_protocol_t protocol, qkd_key_data_t* key_out);
int derive_qkd_components(const unsigned char* kqkdm, size_t kqkdm_len,
                         unsigned char* k_qkd, unsigned char* k_auth,
                         unsigned char* na, unsigned char* nb);
int check_qkd_availability(void);
void print_qkd_key_info(qkd_protocol_t protocol);

#endif // QKD_INTERFACE_H