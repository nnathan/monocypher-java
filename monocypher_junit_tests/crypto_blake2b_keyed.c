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
  uint8_t key1[1];
  uint8_t key32[32];
  uint8_t key64[64];

  for (int i = 0; i < sizeof(msg8); i++) { msg8[i] = i; };
  for (int i = 0; i < sizeof(key1); i++) { key1[i] = i; };
  for (int i = 0; i < sizeof(key32); i++) { key32[i] = i; };
  for (int i = 0; i < sizeof(key64); i++) { key64[i] = i; };

  crypto_blake2b_keyed(hash1, sizeof(hash1), key1, sizeof(key1), msg8, sizeof(msg8));
  crypto_blake2b_keyed(hash32, sizeof(hash32), key32, sizeof(key32), msg8, sizeof(msg8));
  crypto_blake2b_keyed(hash64, sizeof(hash64), key64, sizeof(key64), msg8, sizeof(msg8));

  char msg8_hex_buf[16 + 1] = {0};
  to_hex_string(msg8, 8, msg8_hex_buf);

  char hash1_hex_buf[3] = {0};
  char key1_hex_buf[3] = {0};
  char hash32_hex_buf[64 + 1] = {0};
  char key32_hex_buf[64 + 1] = {0};
  char hash64_hex_buf[128 + 1] = {0};
  char key64_hex_buf[128 + 1] = {0};
  to_hex_string(hash1, 1, hash1_hex_buf);
  to_hex_string(key1, 1, key1_hex_buf);
  to_hex_string(hash32, 32, hash32_hex_buf);
  to_hex_string(key32, 32, key32_hex_buf);
  to_hex_string(hash64, 64, hash64_hex_buf);
  to_hex_string(key64, 64, key64_hex_buf);

  printf("msg: %s\n", msg8_hex_buf);
  printf("key1: %s\n", key1_hex_buf);
  printf("hash1: %s\n", hash1_hex_buf);
  printf("key32: %s\n", key32_hex_buf);
  printf("hash32: %s\n", hash32_hex_buf);
  printf("key64: %s\n", key64_hex_buf);
  printf("hash64: %s\n", hash64_hex_buf);

  printf("msg: <null>\n");
  printf("key: <null>\n");
  crypto_blake2b_keyed(hash32, sizeof(hash32), NULL, 0, NULL, 0);
  to_hex_string(hash32, 32, hash32_hex_buf);
  printf("hash32: %s\n", hash32_hex_buf);

  return 0;
}
