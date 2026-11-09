#include "jni_util.h"

/* No overlap checks: the manual allows mac to overlap message. */

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1poly1305(JNIEnv *env,
                                                          jclass cls,
                                                          jobject j_mac,
                                                          jobject j_message,
                                                          jobject j_key) {
  (void)cls;

  mc_buf mac, message, key;
  if (!mc_output(env, j_mac, "mac", &mac)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;
  if (!mc_input(env, j_key, "key", &key)) return;
  if (!mc_require_len(env, &mac, "mac", 16)) return;
  if (!mc_require_len(env, &key, "key", 32)) return;

  crypto_poly1305(mac.ptr, message.ptr, message.len, key.ptr);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_sizeof_1poly1305_1ctx(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;

  return mc_ctx_alloc_size(sizeof(crypto_poly1305_ctx));
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1poly1305_1init(JNIEnv *env,
                                                               jclass cls,
                                                               jobject j_ctx,
                                                               jobject j_key) {
  (void)cls;

  crypto_poly1305_ctx *ctx;
  mc_buf key;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_input(env, j_key, "key", &key)) return;
  if (!mc_require_len(env, &key, "key", 32)) return;

  crypto_poly1305_init(ctx, key.ptr);
  mc_ctx_mark(ctx, sizeof(*ctx), true);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1poly1305_1update(JNIEnv *env,
                                                                 jclass cls,
                                                                 jobject j_ctx,
                                                                 jobject j_message) {
  (void)cls;

  crypto_poly1305_ctx *ctx;
  mc_buf message;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_poly1305_update(ctx, message.ptr, message.len);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1poly1305_1final(JNIEnv *env,
                                                                jclass cls,
                                                                jobject j_ctx,
                                                                jobject j_mac) {
  (void)cls;

  crypto_poly1305_ctx *ctx;
  mc_buf mac;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_output(env, j_mac, "mac", &mac)) return;
  if (!mc_require_len(env, &mac, "mac", 16)) return;

  crypto_poly1305_final(ctx, mac.ptr);

  /* Wipe here too, rather than rely on final's own wiping. */
  crypto_wipe(ctx, sizeof(*ctx));
  mc_ctx_mark(ctx, sizeof(*ctx), false);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024Poly1305_1ctx_2(
    JNIEnv *env,
    jclass cls,
    jobject j_ctx) {
  (void)cls;

  if (j_ctx == NULL) {
    return;
  }

  crypto_poly1305_ctx *ctx;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;

  crypto_wipe(ctx, sizeof(*ctx));
  mc_ctx_mark(ctx, sizeof(*ctx), false);
}
