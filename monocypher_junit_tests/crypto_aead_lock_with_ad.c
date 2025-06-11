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
  uint8_t nonce[24] = {0};
  uint8_t mac[16] = {0};
  uint8_t ad[24] = {0};
  uint8_t pt[64] = {0};
  uint8_t ct[64] = {0};

  for (int i = 0; i < 32; i++) { key[i] = i; };

  for (int i = 0; i < 24; i++) {
    nonce[i] = 0x41;
  }

  for (int i = 0; i < 24; i++) {
    ad[i] = 0x42;
  }

  for (int i = 0; i < 64; i++) {
    pt[i] = 0x43;
  }

  crypto_aead_lock(ct, mac, key, nonce, ad, sizeof(ad), pt, sizeof(pt));

  char ct_hex_buf[128 + 1];
  char mac_hex_buf[32 + 1];
  char nonce_hex_buf[48 + 1];

  to_hex_string(ct, sizeof(ct), ct_hex_buf);
  to_hex_string(mac, sizeof(mac), mac_hex_buf);

  printf("ciphertext: %s\n", ct_hex_buf);
  printf("mac: %s\n", mac_hex_buf);

  return 0;
}
