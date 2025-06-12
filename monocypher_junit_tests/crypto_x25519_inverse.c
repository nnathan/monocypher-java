#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    uint8_t b[32];
    uint8_t base[32];
    uint8_t private_key[32];
    uint8_t curve_point[32];
    uint8_t blind_salt[32];

    for (int i = 0; i < sizeof(private_key); i++) {
      private_key[i] = i;
    };

    for (int i = sizeof(b) - 1; i >= 0; i--) {
      b[i] = i;
    };

    crypto_x25519_public_key(base, b);

    crypto_x25519(curve_point, private_key, base);

    crypto_x25519_inverse(blind_salt, private_key, curve_point);

    assert(memcmp(blind_salt, base, 32) == 0);

    char curve_point_hex_buf[64 + 1] = {0};
    char private_key_hex_buf[64 + 1] = {0};
    char blind_salt_hex_buf[64 + 1] = {0};
    to_hex_string(curve_point, 32, curve_point_hex_buf);
    to_hex_string(private_key, 32, private_key_hex_buf);
    to_hex_string(blind_salt, 32, blind_salt_hex_buf);

    printf("curve_point: %s\n", curve_point_hex_buf);
    printf("private_key: %s\n", private_key_hex_buf);
    printf("blind_salt: %s\n", blind_salt_hex_buf);
  }

  return 0;
}
