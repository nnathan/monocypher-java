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

void to_le64_hex(uint64_t v, char out[17]) {
  to_hex_string((const uint8_t *)&v, sizeof(v), out);
}

void print_blake2b_ctx(crypto_blake2b_ctx ctx) {
  char hash[8][17] = {0};
  for (int i = 0; i < 8; i++) {
    to_le64_hex(ctx.hash[i], hash[i]);
  }

  char input_offset[2][17] = {0};
  for (int i = 0; i < 2; i++) {
    to_le64_hex(ctx.input_offset[i], input_offset[i]);
  }

  char input[16][17] = {0};
  for (int i = 0; i < 16; i++) {
    to_le64_hex(ctx.input[i], input[i]);
  }

  char input_idx[17];
  to_le64_hex(ctx.input_idx, input_idx);

  char hash_size[17];
  to_le64_hex(ctx.hash_size, hash_size);

  printf("hash: [ \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" ]\n",
         hash[0],
         hash[1],
         hash[2],
         hash[3],
         hash[4],
         hash[5],
         hash[6],
         hash[7]
  );

  printf("input_offset: [ \"%s\" \"%s\" ]\n",
         input_offset[0],
         input_offset[1]
  );

  printf("input: [ \"%s\" \"%s\" \"%s\" \"%s\"\n"
         "         \"%s\" \"%s\" \"%s\" \"%s\"\n"
         "         \"%s\" \"%s\" \"%s\" \"%s\"\n"
         "         \"%s\" \"%s\" \"%s\" \"%s\" ]\n",
         input[0],
         input[1],
         input[2],
         input[3],
         input[4],
         input[5],
         input[6],
         input[7],
         input[8],
         input[9],
         input[10],
         input[11],
         input[12],
         input[13],
         input[14],
         input[15]
  );

  printf("input_idx: \"%s\"\n", input_idx);

  printf("hash_size: \"%s\"\n", hash_size);
}

int main(int argc, char **argv) {
  uint8_t msg256[256];

  for (int i = 0; i < sizeof(msg256); i++) { msg256[i] = i; };

  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, 32);
  crypto_blake2b_update(&ctx, msg256, sizeof(msg256));

  char msg_hex_buf[289] = {0};
  to_hex_string(msg256, sizeof(msg256), msg_hex_buf);

  printf("message: %s\n", msg_hex_buf);
  print_blake2b_ctx(ctx);

  return 0;
}
