#include "jni_util.h"
#include "optional/monocypher-ed25519.h"

/*
 * SHA-512 and HMAC: no overlap checks, as upstream tests write the output over the input.
 * HKDF: okm never overlaps an input (mc_check_disjoint), as the manual requires.
 */

/* The largest okm the manual allows: 255 blocks of 64 bytes. */
#define HKDF_MAX_OKM 16320

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512(JNIEnv *env,
                                                        jclass cls,
                                                        jobject j_hash,
                                                        jobject j_message) {
  (void)cls;

  mc_buf hash, message;
  if (!mc_output_len(env, j_hash, "hash", 64, &hash)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_sha512(hash.ptr, message.ptr, message.len);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_sizeof_1sha512_1ctx(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;

  return mc_ctx_alloc_size(sizeof(crypto_sha512_ctx));
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512_1init(JNIEnv *env,
                                                              jclass cls,
                                                              jobject j_ctx) {
  (void)cls;

  crypto_sha512_ctx *ctx;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;

  crypto_sha512_init(ctx);
  mc_ctx_mark(ctx, sizeof(*ctx), true);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512_1update(JNIEnv *env,
                                                                jclass cls,
                                                                jobject j_ctx,
                                                                jobject j_message) {
  (void)cls;

  crypto_sha512_ctx *ctx;
  mc_buf message;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_sha512_update(ctx, message.ptr, message.len);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512_1final(JNIEnv *env,
                                                               jclass cls,
                                                               jobject j_ctx,
                                                               jobject j_hash) {
  (void)cls;

  crypto_sha512_ctx *ctx;
  mc_buf hash;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_output_len(env, j_hash, "hash", 64, &hash)) return;

  /* Monocypher wipes the context, so it must be initialised again before reuse. */
  crypto_sha512_final(ctx, hash.ptr);
  mc_ctx_mark(ctx, sizeof(*ctx), false);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024SHA512_1ctx_2(
    JNIEnv *env,
    jclass cls,
    jobject j_ctx) {
  (void)cls;

  if (j_ctx == NULL) return;

  crypto_sha512_ctx *ctx;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;

  crypto_wipe(ctx, sizeof(*ctx));
  mc_ctx_mark(ctx, sizeof(*ctx), false);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512_1hmac(JNIEnv *env,
                                                              jclass cls,
                                                              jobject j_hmac,
                                                              jobject j_key,
                                                              jobject j_message) {
  (void)cls;

  mc_buf hmac, key, message;
  if (!mc_output_len(env, j_hmac, "hmac", 64, &hmac)) return;
  if (!mc_input(env, j_key, "key", &key)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_sha512_hmac(hmac.ptr, key.ptr, key.len, message.ptr, message.len);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_sizeof_1sha512_1hmac_1ctx(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;

  return mc_ctx_alloc_size(sizeof(crypto_sha512_hmac_ctx));
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512_1hmac_1init(JNIEnv *env,
                                                                    jclass cls,
                                                                    jobject j_ctx,
                                                                    jobject j_key) {
  (void)cls;

  crypto_sha512_hmac_ctx *ctx;
  mc_buf key;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_input(env, j_key, "key", &key)) return;

  crypto_sha512_hmac_init(ctx, key.ptr, key.len);
  mc_ctx_mark(ctx, sizeof(*ctx), true);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512_1hmac_1update(JNIEnv *env,
                                                                      jclass cls,
                                                                      jobject j_ctx,
                                                                      jobject j_message) {
  (void)cls;

  crypto_sha512_hmac_ctx *ctx;
  mc_buf message;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_sha512_hmac_update(ctx, message.ptr, message.len);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512_1hmac_1final(JNIEnv *env,
                                                                     jclass cls,
                                                                     jobject j_ctx,
                                                                     jobject j_hmac) {
  (void)cls;

  crypto_sha512_hmac_ctx *ctx;
  mc_buf hmac;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_output_len(env, j_hmac, "hmac", 64, &hmac)) return;

  /* Monocypher wipes the context, so it must be initialised again before reuse. */
  crypto_sha512_hmac_final(ctx, hmac.ptr);
  mc_ctx_mark(ctx, sizeof(*ctx), false);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024SHA512_1HMAC_1ctx_2(
    JNIEnv *env,
    jclass cls,
    jobject j_ctx) {
  (void)cls;

  if (j_ctx == NULL) return;

  crypto_sha512_hmac_ctx *ctx;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;

  crypto_wipe(ctx, sizeof(*ctx));
  mc_ctx_mark(ctx, sizeof(*ctx), false);
}

static bool okm_arg(JNIEnv *env, jobject j_okm, mc_buf *okm) {
  if (!mc_output(env, j_okm, "okm", okm)) return false;
  if (okm->len > HKDF_MAX_OKM) {
    return mc_throw_iae(env, "okm", "must have at most 16320 bytes remaining");
  }
  return true;
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512_1hkdf_1expand(JNIEnv *env,
                                                                      jclass cls,
                                                                      jobject j_okm,
                                                                      jobject j_prk,
                                                                      jobject j_info) {
  (void)cls;

  mc_buf okm, prk, info;
  if (!okm_arg(env, j_okm, &okm)) return;
  if (!mc_input(env, j_prk, "prk", &prk)) return;
  if (!mc_input_opt(env, j_info, "info", &info)) return;

  if (!mc_check_disjoint(env, &okm, "okm", &prk, "prk") ||
      !mc_check_disjoint(env, &okm, "okm", &info, "info")) {
    return;
  }

  crypto_sha512_hkdf_expand(okm.ptr, okm.len, prk.ptr, prk.len, info.ptr, info.len);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1sha512_1hkdf(JNIEnv *env,
                                                              jclass cls,
                                                              jobject j_okm,
                                                              jobject j_ikm,
                                                              jobject j_salt,
                                                              jobject j_info) {
  (void)cls;

  mc_buf okm, ikm, salt, info;
  if (!okm_arg(env, j_okm, &okm)) return;
  if (!mc_input(env, j_ikm, "ikm", &ikm)) return;
  if (!mc_input_opt(env, j_salt, "salt", &salt)) return;
  if (!mc_input_opt(env, j_info, "info", &info)) return;

  if (!mc_check_disjoint(env, &okm, "okm", &ikm, "ikm") ||
      !mc_check_disjoint(env, &okm, "okm", &salt, "salt") ||
      !mc_check_disjoint(env, &okm, "okm", &info, "info")) {
    return;
  }

  crypto_sha512_hkdf(okm.ptr, okm.len, ikm.ptr, ikm.len, salt.ptr, salt.len, info.ptr, info.len);
}
