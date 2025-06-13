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
    uint8_t mac[16];
    uint8_t key[32];

    INIT_BUF(mac);
    INIT_BUF(key);

    printf("[simple poly1305 (inplace)]\n");
    char mac_hex_buf[32 + 1] = {0};
    TO_HEX(mac);

    crypto_poly1305(mac, mac, sizeof(mac), key);
    printf("message: %s\n", mac_hex_buf);

    char key_hex_buf[64 + 1] = {0};
    TO_HEX(key);
    TO_HEX(mac);

    printf("key: %s\n", key_hex_buf);
    printf("mac: %s\n", mac_hex_buf);
  }

  {
    uint8_t mac[16];
    uint8_t key[32];

    INIT_BUF(mac);
    INIT_BUF(key);

    crypto_poly1305(mac, NULL, 0, key);

    char mac_hex_buf[32 + 1] = {0};
    char key_hex_buf[64 + 1] = {0};
    TO_HEX(key);
    TO_HEX(mac);

    printf("[simple poly1305 (null message)]\n");
    printf("message: <null>\n");
    printf("mac: %s\n", mac_hex_buf);
  }

  return 0;
}
