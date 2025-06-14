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

#define INIT_BUF(x)                       \
  do {                                    \
    for (int i = 0; i < sizeof(x); i++) { \
      x[i] = i;                           \
    }                                     \
  } while (0)

#define TO_HEX(var)                                 \
  do {                                              \
    to_hex_string(var, sizeof(var), var##_hex_buf); \
  } while (0)

int main(int argc, char **argv) {
  {
    uint8_t hidden[32];
    uint8_t secret[32];
    uint8_t tweak[1];
    int result = -1;

    INIT_BUF(secret);

    char secret_hex_buf[64 + 1] = {0};

    tweak[0] = 0;
    char tweak_hex_buf[2 + 1] = {0};
    char pk_hex_buf[64 + 1] = {0};
    char hidden_hex_buf[64 + 1] = {0};

    TO_HEX(tweak);
    printf("tweak: %s\n", tweak_hex_buf);
    while (result != 0) {
      TO_HEX(secret);
      printf("secret: %s\n", secret_hex_buf);

      crypto_x25519_dirty_small(hidden, secret);
      to_hex_string(hidden, sizeof(hidden), pk_hex_buf);
      printf("pk: %s\n", pk_hex_buf);

      result = crypto_elligator_rev(hidden, hidden, tweak[0]);

      printf("result: %d\n", result);
      if (result == 0) {
        TO_HEX(hidden);
        printf("hidden: %s\n", hidden_hex_buf);
      }

      secret[0]++;
    }
  }

  return 0;
}
