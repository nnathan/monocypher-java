#include "monocypher.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <ctype.h>

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

static uint8_t hex_char_to_value(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    else if ('a' <= c && c <= 'f') return c - 'a' + 10;
    else if ('A' <= c && c <= 'F') return c - 'A' + 10;
    else return 255; // invalid
}

// Returns 0 on success, -1 on invalid input.
int from_hex_string(const char *hex_str, uint8_t *out, size_t out_len) {
    size_t i = 0;
    while (hex_str[i * 2] && hex_str[i * 2 + 1]) {
        if (i >= out_len) return -1;

        uint8_t hi = hex_char_to_value(hex_str[i * 2]);
        uint8_t lo = hex_char_to_value(hex_str[i * 2 + 1]);
        if (hi > 15 || lo > 15) return -1;

        out[i] = (hi << 4) | lo;
        i++;
    }
    return 0;
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
  uint8_t *ct = &buf[64];

  from_hex_string(
    "000102030405060708090a0b0c0d0e0f10111213141516175318bc062203b6c214b24c1f98b84dfa424242424242424242424242424242424242424242424242dd814c3cd391ceed7007658d8811ebab08046be6be955ea83c597cf57eeeb61a1d45f5a702244a2796d6ed1a8c62102132f9a11a0437b85a44d8d07ecca407b7",
    buf,
    sizeof(buf));

  crypto_aead_ctx ctx;

  crypto_aead_init_x(&ctx, key, nonce);
  print_ctx(ctx);

  crypto_aead_read(&ctx, ct, mac, ad, 24, ct, 64);
  print_ctx(ctx);

  char hex_buf[256 + 1] = {0};
  to_hex_string(buf, 128, hex_buf);

  printf("plaintext_message: %s\n", hex_buf);

  return 0;
}
