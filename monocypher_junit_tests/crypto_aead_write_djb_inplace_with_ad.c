#include "monocypher.h"
#include <stdio.h>
#include <stdint.h>

int is_big_endian(void) {
    uint16_t x = 0x0102;
    return *((uint8_t*)&x) == 0x01;
}

void to_hex_string(const uint8_t *data, size_t len, char *hex_buf) {
    for (size_t i = 0; i < len; i++) {
      sprintf(&hex_buf[i * 2], "%02x", (unsigned int)data[i]);
    }
    hex_buf[len * 2] = '\0'; // Null-terminate
}

void print_ctx(crypto_aead_ctx ctx) {
  char counter_hex[17] = {0};
  char key_hex[65] = {0};
  char nonce_hex[17] = {0};

  {
    uint8_t counter_le_bytes[8];

    for (int i = 0; i < 8; i++) {
        counter_le_bytes[i] = ((uint8_t *)&ctx.counter)[i];
    }

    if (is_big_endian()) {
        counter_le_bytes[0] = (uint8_t)((ctx.counter >> 0)  & 0xFF);
        counter_le_bytes[1] = (uint8_t)((ctx.counter >> 8)  & 0xFF);
        counter_le_bytes[2] = (uint8_t)((ctx.counter >> 16) & 0xFF);
        counter_le_bytes[3] = (uint8_t)((ctx.counter >> 24) & 0xFF);
        counter_le_bytes[4] = (uint8_t)((ctx.counter >> 32) & 0xFF);
        counter_le_bytes[5] = (uint8_t)((ctx.counter >> 40) & 0xFF);
        counter_le_bytes[6] = (uint8_t)((ctx.counter >> 48) & 0xFF);
        counter_le_bytes[7] = (uint8_t)((ctx.counter >> 56) & 0xFF);
    }

    to_hex_string(counter_le_bytes, sizeof(ctx.counter), counter_hex);
  }


  to_hex_string(ctx.key, sizeof(ctx.key), key_hex);
  to_hex_string(ctx.nonce, sizeof(ctx.nonce), nonce_hex);

  printf("counter (little-endian): %s\n", counter_hex);
  printf("key: %s\n", key_hex);
  printf("nonce: %s\n", nonce_hex);
}

int main(int argc, char **argv) {
  uint8_t key[32];

  for (int i = 0; i < 32; i++) { key[i] = i; };

  uint8_t buf[128] = {0};
  uint8_t *nonce = &buf[0];
  uint8_t *mac = &buf[24];
  uint8_t *ad = &buf[40];
  uint8_t *pt = &buf[64];

  for (int i = 0; i < 24; i++) {
    nonce[i] = i;
  }

  for (int i = 0; i < 24; i++) {
    ad[i] = 0x42;
  }

  for (int i = 0; i < 64; i++) {
    pt[i] = 0x43;
  }

  crypto_aead_ctx ctx;

  crypto_aead_init_djb(&ctx, key, nonce);
  print_ctx(ctx);

  crypto_aead_write(&ctx, pt, mac, ad, 24, pt, 64);
  print_ctx(ctx);

  char hex_buf[256 + 1] = {0};
  to_hex_string(buf, 128, hex_buf);

  printf("encrypted_message: %s\n", hex_buf);

  return 0;
}
