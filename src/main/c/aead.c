#include "jni_util.h"

typedef struct {
  mc_buf output;
  mc_buf mac;
  mc_buf ad;
  mc_buf input;
} aead_text;

/* Collects and validates the text arguments shared by every AEAD call. */
static bool text_args(JNIEnv *env,
                      jobject j_output,
                      const char *output_name,
                      jobject j_mac,
                      bool mac_is_output,
                      jobject j_ad,
                      jobject j_input,
                      const char *input_name,
                      aead_text *t) {
  if (!mc_output(env, j_output, output_name, &t->output)) return false;
  if (mac_is_output) {
    if (!mc_output(env, j_mac, "mac", &t->mac)) return false;
  } else {
    if (!mc_input(env, j_mac, "mac", &t->mac)) return false;
  }
  if (!mc_input_opt(env, j_ad, "ad", &t->ad)) return false;
  if (!mc_input(env, j_input, input_name, &t->input)) return false;

  if (!mc_require_len(env, &t->mac, "mac", 16)) return false;
  if (!mc_require_same_len(env, &t->output, output_name, &t->input, input_name)) return false;

  return mc_check_overlap(env, &t->output, output_name, &t->input, input_name) &&
         mc_check_disjoint(env, &t->mac, "mac", &t->output, output_name) &&
         mc_check_disjoint(env, &t->mac, "mac", &t->input, input_name) &&
         mc_check_disjoint(env, &t->ad, "ad", &t->output, output_name) &&
         mc_check_disjoint(env, &t->ad, "ad", &t->mac, "mac");
}

/* Validates a key and nonce, which must not share memory with anything written. */
static bool key_nonce_args(JNIEnv *env,
                           jobject j_key,
                           jobject j_nonce,
                           size_t nonce_len,
                           mc_buf *key,
                           mc_buf *nonce) {
  return mc_input(env, j_key, "key", key) && mc_input(env, j_nonce, "nonce", nonce) &&
         mc_require_len(env, key, "key", 32) && mc_require_len(env, nonce, "nonce", nonce_len);
}

static bool key_nonce_disjoint(JNIEnv *env,
                               const mc_buf *key,
                               const mc_buf *nonce,
                               const aead_text *t,
                               const char *output_name) {
  return mc_check_disjoint(env, key, "key", &t->output, output_name) &&
         mc_check_disjoint(env, key, "key", &t->mac, "mac") &&
         mc_check_disjoint(env, nonce, "nonce", &t->output, output_name) &&
         mc_check_disjoint(env, nonce, "nonce", &t->mac, "mac");
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_sizeof_1aead_1ctx(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;

  return mc_ctx_alloc_size(sizeof(crypto_aead_ctx));
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1lock(JNIEnv *env,
                                                            jclass cls,
                                                            jobject j_cipher_text,
                                                            jobject j_mac,
                                                            jobject j_key,
                                                            jobject j_nonce,
                                                            jobject j_ad,
                                                            jobject j_plain_text) {
  (void)cls;

  aead_text t;
  mc_buf key, nonce;
  if (!text_args(env, j_cipher_text, "cipher_text", j_mac, true, j_ad, j_plain_text, "plain_text",
                 &t)) {
    return;
  }
  if (!key_nonce_args(env, j_key, j_nonce, 24, &key, &nonce)) return;
  if (!key_nonce_disjoint(env, &key, &nonce, &t, "cipher_text")) return;

  crypto_aead_lock(t.output.ptr, t.mac.ptr, key.ptr, nonce.ptr, t.ad.ptr, t.ad.len, t.input.ptr,
                   t.input.len);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1unlock(JNIEnv *env,
                                                              jclass cls,
                                                              jobject j_plain_text,
                                                              jobject j_mac,
                                                              jobject j_key,
                                                              jobject j_nonce,
                                                              jobject j_ad,
                                                              jobject j_cipher_text) {
  (void)cls;

  aead_text t;
  mc_buf key, nonce;
  if (!text_args(env, j_plain_text, "plain_text", j_mac, false, j_ad, j_cipher_text, "cipher_text",
                 &t)) {
    return -1;
  }
  if (!key_nonce_args(env, j_key, j_nonce, 24, &key, &nonce)) return -1;
  if (!key_nonce_disjoint(env, &key, &nonce, &t, "plain_text")) return -1;

  return crypto_aead_unlock(t.output.ptr, t.mac.ptr, key.ptr, nonce.ptr, t.ad.ptr, t.ad.len,
                            t.input.ptr, t.input.len);
}

typedef void aead_init_fn(crypto_aead_ctx *ctx, const uint8_t *key, const uint8_t *nonce);

static void aead_init(JNIEnv *env,
                      jobject j_ctx,
                      jobject j_key,
                      jobject j_nonce,
                      size_t nonce_len,
                      aead_init_fn *init) {
  crypto_aead_ctx *ctx;
  mc_buf key, nonce;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!key_nonce_args(env, j_key, j_nonce, nonce_len, &key, &nonce)) return;

  init(ctx, key.ptr, nonce.ptr);
  mc_ctx_mark(ctx, sizeof(*ctx), true);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1init_1x(JNIEnv *env,
                                                               jclass cls,
                                                               jobject j_ctx,
                                                               jobject j_key,
                                                               jobject j_nonce) {
  (void)cls;

  aead_init(env, j_ctx, j_key, j_nonce, 24, crypto_aead_init_x);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1init_1djb(JNIEnv *env,
                                                                 jclass cls,
                                                                 jobject j_ctx,
                                                                 jobject j_key,
                                                                 jobject j_nonce) {
  (void)cls;

  aead_init(env, j_ctx, j_key, j_nonce, 8, crypto_aead_init_djb);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1init_1ietf(JNIEnv *env,
                                                                  jclass cls,
                                                                  jobject j_ctx,
                                                                  jobject j_key,
                                                                  jobject j_nonce) {
  (void)cls;

  aead_init(env, j_ctx, j_key, j_nonce, 12, crypto_aead_init_ietf);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024AEAD_1ctx_2(
    JNIEnv *env,
    jclass cls,
    jobject j_ctx) {
  (void)cls;

  if (j_ctx == NULL) {
    return;
  }

  crypto_aead_ctx *ctx;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;

  crypto_wipe(ctx, sizeof(*ctx));
  mc_ctx_mark(ctx, sizeof(*ctx), false);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1write(JNIEnv *env,
                                                             jclass cls,
                                                             jobject j_ctx,
                                                             jobject j_cipher_text,
                                                             jobject j_mac,
                                                             jobject j_ad,
                                                             jobject j_plain_text) {
  (void)cls;

  crypto_aead_ctx *ctx;
  aead_text t;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!text_args(env, j_cipher_text, "cipher_text", j_mac, true, j_ad, j_plain_text, "plain_text",
                 &t)) {
    return;
  }

  crypto_aead_write(ctx, t.output.ptr, t.mac.ptr, t.ad.ptr, t.ad.len, t.input.ptr, t.input.len);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1read(JNIEnv *env,
                                                            jclass cls,
                                                            jobject j_ctx,
                                                            jobject j_plain_text,
                                                            jobject j_mac,
                                                            jobject j_ad,
                                                            jobject j_cipher_text) {
  (void)cls;

  crypto_aead_ctx *ctx;
  aead_text t;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return -1;
  if (!text_args(env, j_plain_text, "plain_text", j_mac, false, j_ad, j_cipher_text, "cipher_text",
                 &t)) {
    return -1;
  }

  return crypto_aead_read(ctx, t.output.ptr, t.mac.ptr, t.ad.ptr, t.ad.len, t.input.ptr,
                          t.input.len);
}
