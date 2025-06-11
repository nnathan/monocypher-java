#include "monocypher.h"
#include <stdio.h>
#include <stdint.h>

void to_hex_string(const uint8_t *data, size_t len, char *hex_buf) {
    for (size_t i = 0; i < len; i++) {
      sprintf(&hex_buf[i * 2], "%02x", (unsigned int)data[i]);
    }
    hex_buf[len * 2] = '\0'; // Null-terminate
}


int main(int argc, char **argv) {
  uint8_t key[32];

  for (int i = 0; i < 32; i++) { key[i] = i; };

  uint8_t buf[128] = {0};
  char hex_buf[256 + 1] = {0};
  uint8_t *nonce = &buf[0];
  uint8_t *mac = &buf[24];
  uint8_t *ad = &buf[40];
  uint8_t *pt = &buf[64];

  for (int i = 0; i < 24; i++) {
    nonce[i] = 0x41;
  }

  for (int i = 0; i < 24; i++) {
    ad[i] = 0x42;
  }

  for (int i = 0; i < 64; i++) {
    pt[i] = 0x43;
  }

  crypto_aead_lock(pt, mac, key, nonce, ad, 24, pt, 64);

  to_hex_string(buf, 128, hex_buf);

  printf("%s\n", hex_buf);
  return 0;
}
