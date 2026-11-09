#include "jni_util.h"

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1chacha20_1h(JNIEnv *env,
                                                             jclass cls,
                                                             jobject j_out,
                                                             jobject j_key,
                                                             jobject j_in) {
  (void)cls;

  /* No overlap check: Monocypher's tests require arbitrary overlap to work here. */
  mc_buf out, key, in;
  if (!mc_output(env, j_out, "out", &out)) return;
  if (!mc_input(env, j_key, "key", &key)) return;
  if (!mc_input(env, j_in, "in", &in)) return;
  if (!mc_require_len(env, &out, "out", 32)) return;
  if (!mc_require_len(env, &key, "key", 32)) return;
  if (!mc_require_len(env, &in, "in", 16)) return;

  crypto_chacha20_h(out.ptr, key.ptr, in.ptr);
}

typedef struct {
  mc_buf cipher_text;
  mc_buf plain_text;
  mc_buf key;
  mc_buf nonce;
} stream_args;

/* A null plain_text is allowed, and stands for an all-zero input. */
static bool get_stream_args(JNIEnv *env,
                            jobject j_cipher_text,
                            jobject j_plain_text,
                            jobject j_key,
                            jobject j_nonce,
                            size_t nonce_len,
                            stream_args *a) {
  if (!mc_output(env, j_cipher_text, "cipher_text", &a->cipher_text)) return false;
  if (!mc_input_opt(env, j_plain_text, "plain_text", &a->plain_text)) return false;
  if (!mc_input(env, j_key, "key", &a->key)) return false;
  if (!mc_input(env, j_nonce, "nonce", &a->nonce)) return false;

  if (!mc_require_len(env, &a->key, "key", 32)) return false;
  if (!mc_require_len(env, &a->nonce, "nonce", nonce_len)) return false;
  if (j_plain_text != NULL &&
      !mc_require_same_len(env, &a->plain_text, "plain_text", &a->cipher_text, "cipher_text")) {
    return false;
  }

  return mc_check_overlap(env, &a->cipher_text, "cipher_text", &a->plain_text, "plain_text") &&
         mc_check_disjoint(env, &a->key, "key", &a->cipher_text, "cipher_text") &&
         mc_check_disjoint(env, &a->nonce, "nonce", &a->cipher_text, "cipher_text");
}

JNIEXPORT jlong JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1chacha20_1djb(JNIEnv *env,
                                                               jclass cls,
                                                               jobject j_cipher_text,
                                                               jobject j_plain_text,
                                                               jobject j_key,
                                                               jobject j_nonce,
                                                               jlong ctr) {
  (void)cls;

  stream_args a;
  if (!get_stream_args(env, j_cipher_text, j_plain_text, j_key, j_nonce, 8, &a)) return 0;

  return (jlong)crypto_chacha20_djb(a.cipher_text.ptr, a.plain_text.ptr, a.cipher_text.len,
                                    a.key.ptr, a.nonce.ptr, (uint64_t)ctr);
}

JNIEXPORT jlong JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1chacha20_1ietf(JNIEnv *env,
                                                                jclass cls,
                                                                jobject j_cipher_text,
                                                                jobject j_plain_text,
                                                                jobject j_key,
                                                                jobject j_nonce,
                                                                jlong ctr) {
  (void)cls;

  /* The C counter is 32 bits: truncating a larger value would reuse keystream. */
  if (ctr < 0 || ctr > (jlong)UINT32_MAX) {
    mc_throw_iae(env, "ctr", "must be between 0 and 4294967295");
    return 0;
  }

  stream_args a;
  if (!get_stream_args(env, j_cipher_text, j_plain_text, j_key, j_nonce, 12, &a)) return 0;

  return (jlong)crypto_chacha20_ietf(a.cipher_text.ptr, a.plain_text.ptr, a.cipher_text.len,
                                     a.key.ptr, a.nonce.ptr, (uint32_t)ctr);
}

JNIEXPORT jlong JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1chacha20_1x(JNIEnv *env,
                                                             jclass cls,
                                                             jobject j_cipher_text,
                                                             jobject j_plain_text,
                                                             jobject j_key,
                                                             jobject j_nonce,
                                                             jlong ctr) {
  (void)cls;

  stream_args a;
  if (!get_stream_args(env, j_cipher_text, j_plain_text, j_key, j_nonce, 24, &a)) return 0;

  return (jlong)crypto_chacha20_x(a.cipher_text.ptr, a.plain_text.ptr, a.cipher_text.len,
                                  a.key.ptr, a.nonce.ptr, (uint64_t)ctr);
}
