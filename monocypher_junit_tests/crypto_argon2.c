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
    uint8_t pass10[10];
    uint8_t salt16[16];
    uint8_t hash32[32];

    for (int i = 0; i < sizeof(pass10); i++) {
      pass10[i] = i;
    };

    for (int i = 0; i < sizeof(salt16); i++) {
      salt16[i] = i;
    };

    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_D,
        .nb_blocks = 10,
        .nb_lanes = 1,
        .nb_passes = 1,
    };

    crypto_argon2_inputs inp = {
        .pass = &pass10[0],
        .pass_size = sizeof(pass10),
        .salt = &salt16[0],
        .salt_size = sizeof(salt16),
    };

    void *work_area = malloc(10 * 1024);
    crypto_argon2(hash32, sizeof(hash32), work_area, cfg, inp,
                  crypto_argon2_no_extras);
    free(work_area);

    char pass10_hex_buf[21] = {0};
    to_hex_string(pass10, sizeof(pass10), pass10_hex_buf);

    char salt16_hex_buf[33] = {0};
    to_hex_string(salt16, sizeof(salt16), salt16_hex_buf);

    char hash32_hex_buf[65] = {0};
    to_hex_string(hash32, sizeof(hash32), hash32_hex_buf);

    printf("algorithm: D\n");
    printf("pass: %s\n", pass10_hex_buf);
    printf("salt: %s\n", salt16_hex_buf);
    printf("hash: %s\n", hash32_hex_buf);
  }

  {
    uint8_t salt16[16];
    uint8_t hash32[32];

    for (int i = 0; i < sizeof(salt16); i++) {
      salt16[i] = i;
    };

    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_I,
        .nb_blocks = 10,
        .nb_lanes = 1,
        .nb_passes = 1,
    };

    crypto_argon2_inputs inp = {
        .pass = NULL,
        .pass_size = 0,
        .salt = &salt16[0],
        .salt_size = sizeof(salt16),
    };

    void *work_area = malloc(10 * 1024);
    crypto_argon2(hash32, sizeof(hash32), work_area, cfg, inp,
                  crypto_argon2_no_extras);
    free(work_area);

    char salt16_hex_buf[33] = {0};
    to_hex_string(salt16, sizeof(salt16), salt16_hex_buf);

    char hash32_hex_buf[65] = {0};
    to_hex_string(hash32, sizeof(hash32), hash32_hex_buf);

    printf("algorithm: I\n");
    printf("pass: <null>\n");
    printf("salt: %s\n", salt16_hex_buf);
    printf("hash: %s\n", hash32_hex_buf);
  }

  {
    uint8_t key8[8];
    uint8_t ad8[8];
    uint8_t salt16[16];
    uint8_t hash32[32];

    for (int i = 0; i < sizeof(key8); i++) {
      key8[i] = i;
    };

    for (int i = 0; i < sizeof(ad8); i++) {
      ad8[i] = i;
    };

    for (int i = 0; i < sizeof(salt16); i++) {
      salt16[i] = i;
    };

    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_D,
        .nb_blocks = 10,
        .nb_lanes = 1,
        .nb_passes = 1,
    };

    crypto_argon2_inputs inp = {
        .pass = NULL,
        .pass_size = 0,
        .salt = &salt16[0],
        .salt_size = sizeof(salt16),
    };

    crypto_argon2_extras ext = {
        .ad = &ad8[0],
        .ad_size = sizeof(ad8),
        .key = &key8[0],
        .key_size = sizeof(key8),
    };

    void *work_area = malloc(10 * 1024);
    crypto_argon2(hash32, sizeof(hash32), work_area, cfg, inp, ext);
    free(work_area);

    char ad8_hex_buf[33] = {0};
    to_hex_string(ad8, sizeof(ad8), ad8_hex_buf);

    char key8_hex_buf[33] = {0};
    to_hex_string(key8, sizeof(key8), key8_hex_buf);

    char salt16_hex_buf[33] = {0};
    to_hex_string(salt16, sizeof(salt16), salt16_hex_buf);

    char hash32_hex_buf[65] = {0};
    to_hex_string(hash32, sizeof(hash32), hash32_hex_buf);

    printf("algorithm: I\n");
    printf("pass: <null>\n");
    printf("ad: %s\n", ad8_hex_buf);
    printf("key: %s\n", key8_hex_buf);
    printf("salt: %s\n", salt16_hex_buf);
    printf("hash: %s\n", hash32_hex_buf);
  }

  {
    uint8_t key8[8];
    uint8_t ad8[8];
    uint8_t salt16[16];
    uint8_t hash1[1];

    for (int i = 0; i < sizeof(key8); i++) {
      key8[i] = i;
    };

    for (int i = 0; i < sizeof(ad8); i++) {
      ad8[i] = i;
    };

    for (int i = 0; i < sizeof(salt16); i++) {
      salt16[i] = i;
    };

    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_D,
        .nb_blocks = 10,
        .nb_lanes = 1,
        .nb_passes = 1,
    };

    crypto_argon2_inputs inp = {
        .pass = NULL,
        .pass_size = 0,
        .salt = &salt16[0],
        .salt_size = sizeof(salt16),
    };

    crypto_argon2_extras ext = {
        .ad = &ad8[0],
        .ad_size = sizeof(ad8),
        .key = &key8[0],
        .key_size = sizeof(key8),
    };

    void *work_area = malloc(10 * 1024);
    crypto_argon2(hash1, sizeof(hash1), work_area, cfg, inp, ext);
    free(work_area);

    char ad8_hex_buf[33] = {0};
    to_hex_string(ad8, sizeof(ad8), ad8_hex_buf);

    char key8_hex_buf[33] = {0};
    to_hex_string(key8, sizeof(key8), key8_hex_buf);

    char salt16_hex_buf[33] = {0};
    to_hex_string(salt16, sizeof(salt16), salt16_hex_buf);

    char hash1_hex_buf[2] = {0};
    to_hex_string(hash1, sizeof(hash1), hash1_hex_buf);

    printf("algorithm: I\n");
    printf("pass: <null>\n");
    printf("ad: %s\n", ad8_hex_buf);
    printf("key: %s\n", key8_hex_buf);
    printf("salt: %s\n", salt16_hex_buf);
    printf("hash: %s\n", hash1_hex_buf);
  }

  return 0;
}
