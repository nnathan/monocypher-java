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

void to_le32_hex(uint32_t v, char out[9]) {
  to_hex_string((const uint8_t *)&v, sizeof(v), out);
}

void print_poly1305_ctx(crypto_poly1305_ctx ctx) {
  char c_hex_buf[32 + 1];
  to_hex_string(ctx.c, sizeof(ctx.c), c_hex_buf);

  char c_idx_hex_buf[17];
  to_le64_hex(ctx.c_idx, c_idx_hex_buf);

  char r_hex_buf[4][9] = {0};
  for (int i = 0; i < 4; i++) {
    to_le32_hex(ctx.r[i], r_hex_buf[i]);
  }

  char pad_hex_buf[4][9] = {0};
  for (int i = 0; i < 4; i++) {
    to_le32_hex(ctx.pad[i], pad_hex_buf[i]);
  }

  char h_hex_buf[5][9] = {0};
  for (int i = 0; i < 5; i++) {
    to_le32_hex(ctx.h[i], h_hex_buf[i]);
  }

  printf("c (uninitialised): %s\n", c_hex_buf);
  printf("c_idx: %s\n", c_idx_hex_buf);
  printf("r: [ \"%s\" \"%s\" \"%s\" \"%s\" ]\n", r_hex_buf[0], r_hex_buf[1],
         r_hex_buf[2], r_hex_buf[3]);
  printf("pad: [ \"%s\" \"%s\" \"%s\" \"%s\" ]\n", pad_hex_buf[0],
         pad_hex_buf[1], pad_hex_buf[2], pad_hex_buf[3]);
  printf("h: [ \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" ]\n", h_hex_buf[0],
         h_hex_buf[1], h_hex_buf[2], h_hex_buf[3], h_hex_buf[4]);
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
    uint8_t key[32];
    uint8_t message[35];
    INIT_BUF(key);
    INIT_BUF(message);

    crypto_poly1305_ctx ctx;
    crypto_poly1305_init(&ctx, (const uint8_t *)key);

    printf("[poly1305_update]\n");
    char key_hex_buf[64 + 1] = {0};
    TO_HEX(key);
    printf("key: %s\n", key_hex_buf);

    char message_hex_buf[70 + 1] = {0};
    TO_HEX(message);
    printf("message: %s\n", message_hex_buf);
    crypto_poly1305_update(&ctx, message, sizeof(message));
    print_poly1305_ctx(ctx);
    printf("message: <null>\n");
    crypto_poly1305_update(&ctx, NULL, 0);
    print_poly1305_ctx(ctx);
    printf("message: %s\n", message_hex_buf);
    crypto_poly1305_update(&ctx, message, sizeof(message));
    print_poly1305_ctx(ctx);
  }

  {
    uint8_t key[32];
    uint8_t message[35];
    INIT_BUF(key);
    INIT_BUF(message);

    crypto_poly1305_ctx ctx;
    crypto_poly1305_init(&ctx, (const uint8_t *)key);

    printf("[poly1305_update]\n");
    char key_hex_buf[64 + 1] = {0};
    TO_HEX(key);
    printf("key: %s\n", key_hex_buf);

    char message_hex_buf[70 + 1] = {0};
    TO_HEX(message);
    printf("message: %s\n", message_hex_buf);
    crypto_poly1305_update(&ctx, message, sizeof(message));
    print_poly1305_ctx(ctx);
    printf("message: <null>\n");
    crypto_poly1305_update(&ctx, NULL, 0);
    print_poly1305_ctx(ctx);
    printf("message: %s\n", message_hex_buf);
    crypto_poly1305_update(&ctx, message, sizeof(message));
    print_poly1305_ctx(ctx);
  }

  return 0;
}
