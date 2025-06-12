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
    uint8_t sk[32];
    uint8_t pk[32];

    for (int i = 0; i < sizeof(sk); i++) {
      sk[i] = i;
    };

    crypto_x25519_dirty_small(pk, sk);

    char sk_hex_buf[64 + 1] = {0};
    char pk_hex_buf[64 + 1] = {0};
    to_hex_string(sk, 32, sk_hex_buf);
    to_hex_string(pk, 32, pk_hex_buf);

    printf("sk: %s\n", sk_hex_buf);
    printf("pk: %s\n", pk_hex_buf);
  }

  return 0;
}
