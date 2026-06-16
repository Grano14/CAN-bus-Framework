#include <stdint.h>

void send_auth_frame(const uint8_t data_in[8], uint8_t auth[8], uint8_t encrypted_data[8], uint8_t prev_nonce[4], uint8_t next_nonce[4], uint8_t sync_nonce[4]);
int receive_auth_frame(const uint8_t msg_in[8], uint8_t last_encripted_data[8], uint8_t last_tag[4], uint8_t *auth_out, uint8_t sync_nonce[4]);