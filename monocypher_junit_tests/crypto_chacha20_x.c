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
    uint8_t cipher_text[65];
    uint8_t plain_text[65];
    uint8_t key[32];
    uint8_t nonce[24];
    uint64_t ctr = 0;

    INIT_BUF(plain_text);
    INIT_BUF(key);
    INIT_BUF(nonce);

    printf("[simple chacha20]\n");
    ctr = crypto_chacha20_x(cipher_text, plain_text, sizeof(plain_text), key,
                            nonce, ctr);
    printf("ctr: %llu\n", ctr);

    char cipher_text_hex_buf[130 + 1] = {0};
    char plain_text_hex_buf[130 + 1] = {0};
    char key_hex_buf[64 + 1] = {0};
    char nonce_hex_buf[48 + 1] = {0};
    TO_HEX(cipher_text);
    TO_HEX(plain_text);
    TO_HEX(key);
    TO_HEX(nonce);

    printf("key: %s\n", key_hex_buf);
    printf("nonce: %s\n", nonce_hex_buf);
    printf("plain_text: %s\n", plain_text_hex_buf);
    printf("cipher_text: %s\n", cipher_text_hex_buf);
  }

  {
    uint8_t cipher_text[65];
    uint8_t plain_text[65];
    uint8_t key[32];
    uint8_t nonce[24];
    uint64_t ctr = 0;

    INIT_BUF(plain_text);
    INIT_BUF(key);
    INIT_BUF(nonce);

    printf("[incremental chacha20]\n");
    ctr = crypto_chacha20_x(cipher_text, plain_text, 64, key, nonce, ctr);
    printf("counter: %llu\n", ctr);
    ctr = crypto_chacha20_x(cipher_text + 64, plain_text + 64, 1, key, nonce,
                            ctr);
    printf("counter: %llu\n", ctr);

    char cipher_text_hex_buf[130 + 1] = {0};
    char plain_text_hex_buf[130 + 1] = {0};
    char key_hex_buf[64 + 1] = {0};
    char nonce_hex_buf[48 + 1] = {0};
    TO_HEX(cipher_text);
    TO_HEX(plain_text);
    TO_HEX(key);
    TO_HEX(nonce);

    printf("key: %s\n", key_hex_buf);
    printf("nonce: %s\n", nonce_hex_buf);
    printf("plain_text: %s\n", plain_text_hex_buf);
    printf("cipher_text: %s\n", cipher_text_hex_buf);
  }

  {
    uint8_t cipher_text[65];
    uint8_t key[32];
    uint8_t nonce[24];
    uint64_t ctr = 0;

    INIT_BUF(key);
    INIT_BUF(nonce);

    printf("[simple chacha20 (null plain_text)]\n");
    ctr = crypto_chacha20_x(cipher_text, NULL, sizeof(cipher_text), key, nonce,
                            ctr);
    printf("ctr: %llu\n", ctr);

    char cipher_text_hex_buf[130 + 1] = {0};
    char key_hex_buf[64 + 1] = {0};
    char nonce_hex_buf[48 + 1] = {0};
    TO_HEX(cipher_text);
    TO_HEX(key);
    TO_HEX(nonce);

    printf("key: %s\n", key_hex_buf);
    printf("nonce: %s\n", nonce_hex_buf);
    printf("cipher_text: %s\n", cipher_text_hex_buf);
  }

  return 0;
}
