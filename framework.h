#include <stdint.h>

void send_data_frame(const uint8_t data_in[8], uint8_t data_out[8]);
void send_auth_frame(const uint8_t data_in[8], uint8_t auth[8], uint8_t data_out[8]);
void receive_data_frame(const uint8_t msg_in[8], uint8_t status);
void receive_auth_frame(const uint8_t msg_in[8], uint8_t auth_out[8], uint8_t status);