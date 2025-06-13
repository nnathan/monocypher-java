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
    uint8_t out[32];
    uint8_t key[32];
    uint8_t in[16];

    for (int i = 0; i < sizeof(key); i++) {
      key[i] = i;
    };

    for (int i = 0; i < sizeof(in); i++) {
      in[i] = i;
    };

    crypto_chacha20_h(out, key, in);

    char out_hex_buf[64 + 1] = {0};
    char key_hex_buf[64 + 1] = {0};
    char in_hex_buf[32 + 1] = {0};
    to_hex_string(out, sizeof(out), out_hex_buf);
    to_hex_string(key, sizeof(key), key_hex_buf);
    to_hex_string(in, sizeof(in), in_hex_buf);

    printf("in: %s\n", in_hex_buf);
    printf("key: %s\n", key_hex_buf);
    printf("out: %s\n", out_hex_buf);
  }

  return 0;
}
