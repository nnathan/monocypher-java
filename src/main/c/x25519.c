#include "jni_util.h"

/* No overlap checks: the manual and upstream tests allow overlapping buffers. */

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1public_1key(JNIEnv *env,
                                                                     jclass cls,
                                                                     jobject j_public_key,
                                                                     jobject j_secret_key) {
  (void)cls;

  mc_buf public_key, secret_key;
  if (!mc_output_len(env, j_public_key, "public_key", 32, &public_key)) return;
  if (!mc_input_len(env, j_secret_key, "secret_key", 32, &secret_key)) return;

  crypto_x25519_public_key(public_key.ptr, secret_key.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519(JNIEnv *env,
                                                        jclass cls,
                                                        jobject j_raw_shared_secret,
                                                        jobject j_your_secret_key,
                                                        jobject j_their_public_key) {
  (void)cls;

  mc_buf raw_shared_secret, your_secret_key, their_public_key;
  if (!mc_output_len(env, j_raw_shared_secret, "raw_shared_secret", 32, &raw_shared_secret)) {
    return;
  }
  if (!mc_input_len(env, j_your_secret_key, "your_secret_key", 32, &your_secret_key)) return;
  if (!mc_input_len(env, j_their_public_key, "their_public_key", 32, &their_public_key)) return;

  crypto_x25519(raw_shared_secret.ptr, your_secret_key.ptr, their_public_key.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1to_1eddsa(JNIEnv *env,
                                                                   jclass cls,
                                                                   jobject j_eddsa,
                                                                   jobject j_x25519) {
  (void)cls;

  mc_buf eddsa, x25519;
  if (!mc_output_len(env, j_eddsa, "eddsa", 32, &eddsa)) return;
  if (!mc_input_len(env, j_x25519, "x25519", 32, &x25519)) return;

  crypto_x25519_to_eddsa(eddsa.ptr, x25519.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1inverse(JNIEnv *env,
                                                                 jclass cls,
                                                                 jobject j_blind_salt,
                                                                 jobject j_private_key,
                                                                 jobject j_curve_point) {
  (void)cls;

  mc_buf blind_salt, private_key, curve_point;
  if (!mc_output_len(env, j_blind_salt, "blind_salt", 32, &blind_salt)) return;
  if (!mc_input_len(env, j_private_key, "private_key", 32, &private_key)) return;
  if (!mc_input_len(env, j_curve_point, "curve_point", 32, &curve_point)) return;

  crypto_x25519_inverse(blind_salt.ptr, private_key.ptr, curve_point.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1dirty_1small(JNIEnv *env,
                                                                      jclass cls,
                                                                      jobject j_pk,
                                                                      jobject j_sk) {
  (void)cls;

  mc_buf pk, sk;
  if (!mc_output_len(env, j_pk, "pk", 32, &pk)) return;
  if (!mc_input_len(env, j_sk, "sk", 32, &sk)) return;

  crypto_x25519_dirty_small(pk.ptr, sk.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1dirty_1fast(JNIEnv *env,
                                                                     jclass cls,
                                                                     jobject j_pk,
                                                                     jobject j_sk) {
  (void)cls;

  mc_buf pk, sk;
  if (!mc_output_len(env, j_pk, "pk", 32, &pk)) return;
  if (!mc_input_len(env, j_sk, "sk", 32, &sk)) return;

  crypto_x25519_dirty_fast(pk.ptr, sk.ptr);
}
