#include "jni_util.h"

/* No overlap checks: the manual and upstream tests allow overlapping buffers. */

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1key_1pair(JNIEnv *env,
                                                                  jclass cls,
                                                                  jobject j_secret_key,
                                                                  jobject j_public_key,
                                                                  jobject j_seed) {
  (void)cls;

  /* Monocypher wipes the seed, so it is written to like an output. */
  mc_buf secret_key, public_key, seed;
  if (!mc_output_len(env, j_secret_key, "secret_key", 64, &secret_key)) return;
  if (!mc_output_len(env, j_public_key, "public_key", 32, &public_key)) return;
  if (!mc_output_len(env, j_seed, "seed", 32, &seed)) return;

  crypto_eddsa_key_pair(secret_key.ptr, public_key.ptr, seed.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1sign(JNIEnv *env,
                                                             jclass cls,
                                                             jobject j_signature,
                                                             jobject j_secret_key,
                                                             jobject j_message) {
  (void)cls;

  mc_buf signature, secret_key, message;
  if (!mc_output_len(env, j_signature, "signature", 64, &signature)) return;
  if (!mc_input_len(env, j_secret_key, "secret_key", 64, &secret_key)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_eddsa_sign(signature.ptr, secret_key.ptr, message.ptr, message.len);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1check(JNIEnv *env,
                                                              jclass cls,
                                                              jobject j_signature,
                                                              jobject j_public_key,
                                                              jobject j_message) {
  (void)cls;

  mc_buf signature, public_key, message;
  if (!mc_input_len(env, j_signature, "signature", 64, &signature)) return -1;
  if (!mc_input_len(env, j_public_key, "public_key", 32, &public_key)) return -1;
  if (!mc_input_opt(env, j_message, "message", &message)) return -1;

  return crypto_eddsa_check(signature.ptr, public_key.ptr, message.ptr, message.len);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1to_1x25519(JNIEnv *env,
                                                                   jclass cls,
                                                                   jobject j_x25519,
                                                                   jobject j_eddsa) {
  (void)cls;

  mc_buf x25519, eddsa;
  if (!mc_output_len(env, j_x25519, "x25519", 32, &x25519)) return;
  if (!mc_input_len(env, j_eddsa, "eddsa", 32, &eddsa)) return;

  crypto_eddsa_to_x25519(x25519.ptr, eddsa.ptr);
}
