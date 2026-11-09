#include "jni_util.h"

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1elligator_1key_1pair(
    JNIEnv *env,
    jobject obj,
    jbyteArray hidden,
    jbyteArray secret_key,
    jbyteArray seed) {
  (void)obj;

  CHECK_NULL(hidden, );
  CHECK_NULL(secret_key, );
  CHECK_NULL(seed, );

  ENSURE_ARRAY_LENGTH(hidden, 32, );
  ENSURE_ARRAY_LENGTH(secret_key, 32, );
  ENSURE_ARRAY_LENGTH(seed, 32, );

  jbyte *hidden_ptr = (*env)->GetByteArrayElements(env, hidden, NULL);
  jbyte *secret_key_ptr = (*env)->GetByteArrayElements(env, secret_key, NULL);
  jbyte *seed_ptr = (*env)->GetByteArrayElements(env, seed, NULL);

  crypto_elligator_key_pair((uint8_t *)hidden_ptr, (uint8_t *)secret_key_ptr,
                            (uint8_t *)seed_ptr);

  (*env)->ReleaseByteArrayElements(env, hidden, hidden_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, secret_key, secret_key_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, seed, seed_ptr, 0);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1elligator_1rev(
    JNIEnv *env,
    jobject obj,
    jbyteArray hidden,
    jbyteArray curve,
    jbyte tweak) {
  (void)obj;

  CHECK_NULL(hidden, -1);
  CHECK_NULL(curve, -1);

  ENSURE_ARRAY_LENGTH(hidden, 32, -1);
  ENSURE_ARRAY_LENGTH(curve, 32, -1);

  jbyte *hidden_ptr = (*env)->GetByteArrayElements(env, hidden, NULL);
  jbyte *curve_ptr = (*env)->GetByteArrayElements(env, curve, NULL);

  int result = crypto_elligator_rev((uint8_t *)hidden_ptr,
                                    (const uint8_t *)curve_ptr, (uint8_t)tweak);

  (*env)->ReleaseByteArrayElements(env, hidden, hidden_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, curve, curve_ptr, JNI_ABORT);

  return result;
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1elligator_1map(
    JNIEnv *env,
    jobject obj,
    jbyteArray curve,
    jbyteArray hidden) {
  (void)obj;

  CHECK_NULL(curve, );
  CHECK_NULL(hidden, );

  ENSURE_ARRAY_LENGTH(curve, 32, );
  ENSURE_ARRAY_LENGTH(hidden, 32, );

  jbyte *hidden_ptr = (*env)->GetByteArrayElements(env, hidden, NULL);
  jbyte *curve_ptr = (*env)->GetByteArrayElements(env, curve, NULL);

  crypto_elligator_map((uint8_t *)curve_ptr, (const uint8_t *)hidden_ptr);

  (*env)->ReleaseByteArrayElements(env, curve, curve_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, hidden, hidden_ptr, JNI_ABORT);
}
