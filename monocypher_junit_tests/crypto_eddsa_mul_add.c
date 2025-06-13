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
    uint8_t r[32];
    uint8_t a[32];
    uint8_t b[32];
    uint8_t c[32];

    for (int i = 0; i < sizeof(a); i++) {
      a[i] = 0xaa;
    };

    for (int i = 0; i < sizeof(b); i++) {
      b[i] = 0xbb;
    };

    for (int i = 0; i < sizeof(c); i++) {
      c[i] = 0xcc;
    };

    crypto_eddsa_mul_add(r, a, b, c);

    char r_hex_buf[64 + 1] = {0};
    char a_hex_buf[64 + 1] = {0};
    char b_hex_buf[64 + 1] = {0};
    char c_hex_buf[64 + 1] = {0};
    to_hex_string(r, sizeof(r), r_hex_buf);
    to_hex_string(a, sizeof(a), a_hex_buf);
    to_hex_string(b, sizeof(b), b_hex_buf);
    to_hex_string(c, sizeof(c), c_hex_buf);

    printf("a: %s\n", a_hex_buf);
    printf("b: %s\n", b_hex_buf);
    printf("c: %s\n", c_hex_buf);
    printf("r: %s\n", r_hex_buf);
  }

  return 0;
}
