#include "jni_util.h"
#include "optional/monocypher-ed25519.h"

/*
 * No overlap checks, as for EdDSA: Ed25519 runs the same signing code with SHA-512 in place of
 * BLAKE2b. The manual says nothing and upstream has no Ed25519 overlap test.
 */

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1ed25519_1key_1pair(JNIEnv *env,
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

  crypto_ed25519_key_pair(secret_key.ptr, public_key.ptr, seed.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1ed25519_1sign(JNIEnv *env,
                                                               jclass cls,
                                                               jobject j_signature,
                                                               jobject j_secret_key,
                                                               jobject j_message) {
  (void)cls;

  mc_buf signature, secret_key, message;
  if (!mc_output_len(env, j_signature, "signature", 64, &signature)) return;
  if (!mc_input_len(env, j_secret_key, "secret_key", 64, &secret_key)) return;
  if (!mc_input_opt(env, j_message, "message", &message)) return;

  crypto_ed25519_sign(signature.ptr, secret_key.ptr, message.ptr, message.len);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1ed25519_1check(JNIEnv *env,
                                                                jclass cls,
                                                                jobject j_signature,
                                                                jobject j_public_key,
                                                                jobject j_message) {
  (void)cls;

  mc_buf signature, public_key, message;
  if (!mc_input_len(env, j_signature, "signature", 64, &signature)) return -1;
  if (!mc_input_len(env, j_public_key, "public_key", 32, &public_key)) return -1;
  if (!mc_input_opt(env, j_message, "message", &message)) return -1;

  return crypto_ed25519_check(signature.ptr, public_key.ptr, message.ptr, message.len);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1ed25519_1ph_1sign(JNIEnv *env,
                                                                   jclass cls,
                                                                   jobject j_signature,
                                                                   jobject j_secret_key,
                                                                   jobject j_message_hash) {
  (void)cls;

  mc_buf signature, secret_key, message_hash;
  if (!mc_output_len(env, j_signature, "signature", 64, &signature)) return;
  if (!mc_input_len(env, j_secret_key, "secret_key", 64, &secret_key)) return;
  if (!mc_input_len(env, j_message_hash, "message_hash", 64, &message_hash)) return;

  crypto_ed25519_ph_sign(signature.ptr, secret_key.ptr, message_hash.ptr);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1ed25519_1ph_1check(JNIEnv *env,
                                                                    jclass cls,
                                                                    jobject j_signature,
                                                                    jobject j_public_key,
                                                                    jobject j_message_hash) {
  (void)cls;

  mc_buf signature, public_key, message_hash;
  if (!mc_input_len(env, j_signature, "signature", 64, &signature)) return -1;
  if (!mc_input_len(env, j_public_key, "public_key", 32, &public_key)) return -1;
  if (!mc_input_len(env, j_message_hash, "message_hash", 64, &message_hash)) return -1;

  return crypto_ed25519_ph_check(signature.ptr, public_key.ptr, message_hash.ptr);
}
