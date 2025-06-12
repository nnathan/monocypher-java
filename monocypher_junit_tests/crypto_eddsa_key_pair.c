#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "monocypher.h"

int is_big_endian(void) {
  uint16_t x = 0x0102;
  return *((uint8_t *)&x) == 0x01;
}

void to_hex_string(const uint8_t *data, size_t len, char *hex_buf) {
  for (size_t i = 0; i < len; i++) {
    sprintf(&hex_buf[i * 2], "%02x", (unsigned int)data[i]);
  }
  hex_buf[len * 2] = '\0';  // Null-terminate
}

void to_le64_hex(uint64_t v, char out[17]) {
  to_hex_string((const uint8_t *)&v, sizeof(v), out);
}

int main(int argc, char **argv) {
  {
    uint8_t seed[32];
    uint8_t public_key[32];
    uint8_t secret_key[32];

    for (int i = 0; i < sizeof(seed); i++) {
      seed[i] = i;
    };

    char seed_hex_buf[64 + 1] = {0};
    to_hex_string(seed, 32, seed_hex_buf);
    printf("seed (before): %s\n", seed_hex_buf);

    crypto_eddsa_key_pair(secret_key, public_key, seed);

    char secret_key_hex_buf[128 + 1] = {0};
    char public_key_hex_buf[64 + 1] = {0};
    to_hex_string(secret_key, 64, secret_key_hex_buf);
    to_hex_string(public_key, 32, public_key_hex_buf);
    to_hex_string(seed, 32, seed_hex_buf);

    printf("secret_key: %s\n", secret_key_hex_buf);
    printf("public_key: %s\n", public_key_hex_buf);
    printf("seed (after): %s\n", seed_hex_buf);
  }

  return 0;
}
