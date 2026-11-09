#include "jni_util.h"

/* No overlap checks: the manual and upstream tests allow overlapping buffers. */

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1elligator_1key_1pair(JNIEnv *env,
                                                                      jclass cls,
                                                                      jobject j_hidden,
                                                                      jobject j_secret_key,
                                                                      jobject j_seed) {
  (void)cls;

  /* Monocypher wipes the seed, so it is written to like an output. */
  mc_buf hidden, secret_key, seed;
  if (!mc_output_len(env, j_hidden, "hidden", 32, &hidden)) return;
  if (!mc_output_len(env, j_secret_key, "secret_key", 32, &secret_key)) return;
  if (!mc_output_len(env, j_seed, "seed", 32, &seed)) return;

  crypto_elligator_key_pair(hidden.ptr, secret_key.ptr, seed.ptr);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1elligator_1rev(JNIEnv *env,
                                                                jclass cls,
                                                                jobject j_hidden,
                                                                jobject j_curve,
                                                                jint tweak) {
  (void)cls;

  /* The C tweak is a uint8_t; truncating a larger value would change its meaning. */
  if (tweak < 0 || tweak > 255) {
    mc_throw_iae(env, "tweak", "must be between 0 and 255");
    return -1;
  }

  mc_buf hidden, curve;
  if (!mc_output_len(env, j_hidden, "hidden", 32, &hidden)) return -1;
  if (!mc_input_len(env, j_curve, "curve", 32, &curve)) return -1;

  return crypto_elligator_rev(hidden.ptr, curve.ptr, (uint8_t)tweak);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1elligator_1map(JNIEnv *env,
                                                                jclass cls,
                                                                jobject j_curve,
                                                                jobject j_hidden) {
  (void)cls;

  mc_buf curve, hidden;
  if (!mc_output_len(env, j_curve, "curve", 32, &curve)) return;
  if (!mc_input_len(env, j_hidden, "hidden", 32, &hidden)) return;

  crypto_elligator_map(curve.ptr, hidden.ptr);
}
