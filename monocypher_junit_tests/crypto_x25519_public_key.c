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
    uint8_t secret[32];
    uint8_t public[32];

    for (int i = 0; i < sizeof(secret); i++) {
      secret[i] = i;
    };

    crypto_x25519_public_key(public, secret);

    char secret_hex_buf[64 + 1] = {0};
    char public_hex_buf[64 + 1] = {0};
    to_hex_string(secret, 32, secret_hex_buf);
    to_hex_string(public, 32, public_hex_buf);

    printf("secret: %s\n", secret_hex_buf);
    printf("public: %s\n", public_hex_buf);
  }

  return 0;
}
