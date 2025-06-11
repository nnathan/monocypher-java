#include "monocypher.h"
#include <stdio.h>
#include <stdint.h>

int is_big_endian(void) {
    uint16_t x = 0x0102;
    return *((uint8_t*)&x) == 0x01;
}

void to_hex_string(const uint8_t *data, size_t len, char *hex_buf) {
    for (size_t i = 0; i < len; i++) {
      sprintf(&hex_buf[i * 2], "%02x", (unsigned int)data[i]);
    }
    hex_buf[len * 2] = '\0'; // Null-terminate
}

int main(int argc, char **argv) {
  uint8_t hash32[32];
  uint8_t msg8[8];

  for (int i = 0; i < sizeof(msg8); i++) { msg8[i] = i; };
  for (int i = 0; i < sizeof(hash32); i++) { hash32[i] = i; };

  char key32_hex_buf[64 + 1] = {0};
  to_hex_string(hash32, 32, key32_hex_buf);
  printf("key32 (inplace): %s\n", key32_hex_buf);

  crypto_blake2b_keyed(hash32, sizeof(hash32), hash32, sizeof(hash32), msg8, sizeof(msg8));

  char msg8_hex_buf[16 + 1] = {0};
  to_hex_string(msg8, 8, msg8_hex_buf);

  char hash32_hex_buf[64 + 1] = {0};
  to_hex_string(hash32, 32, hash32_hex_buf);

  printf("msg: %s\n", msg8_hex_buf);
  printf("hash32: %s\n", hash32_hex_buf);

  return 0;
}
