#include "jni_util.h"

/* No overlap checks: the manual allows hash, key and message to overlap. */

static bool hash_arg(JNIEnv *env, jobject j_hash, mc_buf *hash) {
  if (!mc_output(env, j_hash, "hash", hash)) return false;
  if (hash->len < 1 || hash->len > 64) {
    return mc_throw_iae(env, "hash", "must have between 1 and 64 bytes remaining");
  }
  return true;
}

static bool key_arg(JNIEnv *env, jobject j_key, mc_buf *key) {
  if (!mc_input_opt(env, j_key, "key", key)) return false;
  if (key->len > 64) return mc_throw_iae(env, "key", "must have at most 64 bytes remaining");
  return true;
}

static bool hash_size_arg(JNIEnv *env, jint hash_size) {
  if (hash_size < 1 || hash_size > 64) {
    return mc_throw_iae(env, "hash_size", "must be between 1 and 64");
  }
  return true;
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b(JNIEnv *env,
                                                         jclass cls,
                                                         jobject j_hash,
                                                         jobject j_message) {
  (void)cls;

  mc_buf hash, message;
  if (!hash_arg(env, j_hash, &hash)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_blake2b(hash.ptr, hash.len, message.ptr, message.len);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b_1keyed(JNIEnv *env,
                                                                jclass cls,
                                                                jobject j_hash,
                                                                jobject j_key,
                                                                jobject j_message) {
  (void)cls;

  mc_buf hash, key, message;
  if (!hash_arg(env, j_hash, &hash)) return;
  if (!key_arg(env, j_key, &key)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_blake2b_keyed(hash.ptr, hash.len, key.ptr, key.len, message.ptr, message.len);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_sizeof_1blake2b_1ctx(JNIEnv *env, jclass cls) {
  (void)env;
  (void)cls;

  return mc_ctx_alloc_size(sizeof(crypto_blake2b_ctx));
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b_1init(JNIEnv *env,
                                                               jclass cls,
                                                               jobject j_ctx,
                                                               jint hash_size) {
  (void)cls;

  crypto_blake2b_ctx *ctx;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!hash_size_arg(env, hash_size)) return;

  crypto_blake2b_init(ctx, (size_t)hash_size);
  mc_ctx_mark(ctx, sizeof(*ctx), true);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b_1keyed_1init(JNIEnv *env,
                                                                      jclass cls,
                                                                      jobject j_ctx,
                                                                      jint hash_size,
                                                                      jobject j_key) {
  (void)cls;

  crypto_blake2b_ctx *ctx;
  mc_buf key;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!hash_size_arg(env, hash_size)) return;
  if (!key_arg(env, j_key, &key)) return;

  crypto_blake2b_keyed_init(ctx, (size_t)hash_size, key.ptr, key.len);
  mc_ctx_mark(ctx, sizeof(*ctx), true);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b_1update(JNIEnv *env,
                                                                 jclass cls,
                                                                 jobject j_ctx,
                                                                 jobject j_message) {
  (void)cls;

  crypto_blake2b_ctx *ctx;
  mc_buf message;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_blake2b_update(ctx, message.ptr, message.len);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b_1final(JNIEnv *env,
                                                                jclass cls,
                                                                jobject j_ctx,
                                                                jobject j_hash) {
  (void)cls;

  crypto_blake2b_ctx *ctx;
  mc_buf hash;
  if (!mc_ctx_ready(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;
  if (!mc_output(env, j_hash, "hash", &hash)) return;
  if (hash.len != ctx->hash_size) {
    mc_throw_iae(env, "hash", "must have exactly the hash_size given to init remaining");
    return;
  }

  /* Monocypher wipes the context, so it must be initialised again before reuse. */
  crypto_blake2b_final(ctx, hash.ptr);
  mc_ctx_mark(ctx, sizeof(*ctx), false);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024Blake2b_1ctx_2(
    JNIEnv *env,
    jclass cls,
    jobject j_ctx) {
  (void)cls;

  if (j_ctx == NULL) return;

  crypto_blake2b_ctx *ctx;
  if (!mc_ctx_get(env, j_ctx, sizeof(*ctx), (void **)&ctx)) return;

  crypto_wipe(ctx, sizeof(*ctx));
  mc_ctx_mark(ctx, sizeof(*ctx), false);
}
