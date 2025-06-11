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
  uint8_t hash1[1];
  uint8_t hash32[32];
  uint8_t hash64[64];
  uint8_t msg8[8];

  for (int i = 0; i < sizeof(msg8); i++) { msg8[i] = i; };

  crypto_blake2b(hash1, sizeof(hash1), msg8, sizeof(msg8));
  crypto_blake2b(hash32, sizeof(hash32), msg8, sizeof(msg8));
  crypto_blake2b(hash64, sizeof(hash64), msg8, sizeof(msg8));

  char msg8_hex_buf[16 + 1] = {0};
  to_hex_string(msg8, 8, msg8_hex_buf);

  char hash1_hex_buf[3] = {0};
  char hash32_hex_buf[64 + 1] = {0};
  char hash64_hex_buf[128 + 1] = {0};
  to_hex_string(hash1, 1, hash1_hex_buf);
  to_hex_string(hash32, 32, hash32_hex_buf);
  to_hex_string(hash64, 64, hash64_hex_buf);

  printf("msg: %s\n", msg8_hex_buf);
  printf("hash1: %s\n", hash1_hex_buf);
  printf("hash32: %s\n", hash32_hex_buf);
  printf("hash64: %s\n", hash64_hex_buf);

  printf("msg: <null>\n");
  crypto_blake2b(hash32, sizeof(hash32), NULL, 0);
  to_hex_string(hash32, 32, hash32_hex_buf);
  printf("hash32: %s\n", hash32_hex_buf);

  return 0;
}
