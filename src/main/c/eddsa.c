#include "jni_util.h"

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1key_1pair(
    JNIEnv *env,
    jobject obj,
    jbyteArray secret_key,
    jbyteArray public_key,
    jbyteArray seed) {
  (void)obj;

  CHECK_NULL(secret_key, );
  CHECK_NULL(public_key, );
  CHECK_NULL(seed, );

  ENSURE_ARRAY_LENGTH(secret_key, 64, );
  ENSURE_ARRAY_LENGTH(public_key, 32, );
  ENSURE_ARRAY_LENGTH(seed, 32, );

  jbyte *secret_key_ptr = (*env)->GetByteArrayElements(env, secret_key, NULL);
  jbyte *public_key_ptr = (*env)->GetByteArrayElements(env, public_key, NULL);
  jbyte *seed_ptr = (*env)->GetByteArrayElements(env, seed, NULL);

  crypto_eddsa_key_pair((uint8_t *)secret_key_ptr, (uint8_t *)public_key_ptr,
                        (uint8_t *)seed_ptr);

  (*env)->ReleaseByteArrayElements(env, secret_key, secret_key_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, public_key, public_key_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, seed, seed_ptr, 0);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1sign(
    JNIEnv *env,
    jobject obj,
    jbyteArray signature,
    jbyteArray secret_key,
    jbyteArray message) {
  (void)obj;

  CHECK_NULL(signature, );
  CHECK_NULL(secret_key, );

  ENSURE_ARRAY_LENGTH(signature, 64, );
  ENSURE_ARRAY_LENGTH(secret_key, 64, );

  jbyte *message_ptr = NULL;
  jint message_len = 0;

  if (message) {
    message_ptr = (*env)->GetByteArrayElements(env, message, NULL);
    message_len = (*env)->GetArrayLength(env, message);
  }

  jbyte *signature_ptr = (*env)->GetByteArrayElements(env, signature, NULL);
  jbyte *secret_key_ptr = (*env)->GetByteArrayElements(env, secret_key, NULL);

  crypto_eddsa_sign((uint8_t *)signature_ptr, (const uint8_t *)secret_key_ptr,
                    (const uint8_t *)message_ptr, (size_t)message_len);

  (*env)->ReleaseByteArrayElements(env, signature, signature_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, secret_key, secret_key_ptr, JNI_ABORT);
  if (message) {
    (*env)->ReleaseByteArrayElements(env, message, message_ptr, JNI_ABORT);
  }
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1check(
    JNIEnv *env,
    jobject obj,
    jbyteArray signature,
    jbyteArray public_key,
    jbyteArray message) {
  (void)obj;

  CHECK_NULL(signature, -1);
  CHECK_NULL(public_key, -1);

  ENSURE_ARRAY_LENGTH(signature, 64, -1);
  ENSURE_ARRAY_LENGTH(public_key, 32, -1);

  jbyte *message_ptr = NULL;
  jint message_len = 0;

  if (message) {
    message_ptr = (*env)->GetByteArrayElements(env, message, NULL);
    message_len = (*env)->GetArrayLength(env, message);
  }

  jbyte *signature_ptr = (*env)->GetByteArrayElements(env, signature, NULL);
  jbyte *public_key_ptr = (*env)->GetByteArrayElements(env, public_key, NULL);

  int result = crypto_eddsa_check(
      (uint8_t *)signature_ptr, (const uint8_t *)public_key_ptr,
      (const uint8_t *)message_ptr, (size_t)message_len);

  (*env)->ReleaseByteArrayElements(env, signature, signature_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, public_key, public_key_ptr, JNI_ABORT);
  if (message) {
    (*env)->ReleaseByteArrayElements(env, message, message_ptr, JNI_ABORT);
  }

  return (jint)result;
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1to_1x25519(
    JNIEnv *env,
    jobject obj,
    jbyteArray x25519,
    jbyteArray eddsa) {
  (void)obj;

  CHECK_NULL(x25519, );
  CHECK_NULL(eddsa, );

  ENSURE_ARRAY_LENGTH(x25519, 32, );
  ENSURE_ARRAY_LENGTH(eddsa, 32, );

  jbyte *x25519_ptr = (*env)->GetByteArrayElements(env, x25519, NULL);
  jbyte *eddsa_ptr = (*env)->GetByteArrayElements(env, eddsa, NULL);

  crypto_eddsa_to_x25519((uint8_t *)x25519_ptr, (const uint8_t *)eddsa_ptr);

  (*env)->ReleaseByteArrayElements(env, x25519, x25519_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, eddsa, eddsa_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1trim_1scalar(
    JNIEnv *env,
    jobject obj,
    jbyteArray out,
    jbyteArray in) {
  (void)obj;

  CHECK_NULL(out, );
  CHECK_NULL(in, );

  ENSURE_ARRAY_LENGTH(out, 32, );
  ENSURE_ARRAY_LENGTH(in, 32, );

  jbyte *out_ptr = (*env)->GetByteArrayElements(env, out, NULL);
  jbyte *in_ptr = (*env)->GetByteArrayElements(env, in, NULL);

  crypto_eddsa_trim_scalar((uint8_t *)out_ptr, (const uint8_t *)in_ptr);

  (*env)->ReleaseByteArrayElements(env, out, out_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, in, in_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1reduce(
    JNIEnv *env,
    jobject obj,
    jbyteArray reduced,
    jbyteArray expanded) {
  (void)obj;

  CHECK_NULL(reduced, );
  CHECK_NULL(expanded, );

  ENSURE_ARRAY_LENGTH(reduced, 32, );
  ENSURE_ARRAY_LENGTH(expanded, 64, );

  jbyte *reduced_ptr = (*env)->GetByteArrayElements(env, reduced, NULL);
  jbyte *expanded_ptr = (*env)->GetByteArrayElements(env, expanded, NULL);

  crypto_eddsa_reduce((uint8_t *)reduced_ptr, (const uint8_t *)expanded_ptr);

  (*env)->ReleaseByteArrayElements(env, reduced, reduced_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, expanded, expanded_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1mul_1add(JNIEnv *env,
                                                                 jobject obj,
                                                                 jbyteArray r,
                                                                 jbyteArray a,
                                                                 jbyteArray b,
                                                                 jbyteArray c) {
  (void)obj;

  CHECK_NULL(r, );
  CHECK_NULL(a, );
  CHECK_NULL(b, );
  CHECK_NULL(c, );

  ENSURE_ARRAY_LENGTH(r, 32, );
  ENSURE_ARRAY_LENGTH(a, 32, );
  ENSURE_ARRAY_LENGTH(b, 32, );
  ENSURE_ARRAY_LENGTH(c, 32, );

  jbyte *r_ptr = (*env)->GetByteArrayElements(env, r, NULL);
  jbyte *a_ptr = (*env)->GetByteArrayElements(env, a, NULL);
  jbyte *b_ptr = (*env)->GetByteArrayElements(env, b, NULL);
  jbyte *c_ptr = (*env)->GetByteArrayElements(env, c, NULL);

  crypto_eddsa_mul_add((uint8_t *)r_ptr, (const uint8_t *)a_ptr,
                       (const uint8_t *)b_ptr, (const uint8_t *)c_ptr);

  (*env)->ReleaseByteArrayElements(env, r, r_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, a, a_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, b, b_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, c, c_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1eddsa_1scalarbase(
    JNIEnv *env,
    jobject obj,
    jbyteArray point,
    jbyteArray scalar) {
  (void)obj;

  CHECK_NULL(point, );
  CHECK_NULL(scalar, );

  ENSURE_ARRAY_LENGTH(point, 32, );
  ENSURE_ARRAY_LENGTH(scalar, 32, );

  jbyte *point_ptr = (*env)->GetByteArrayElements(env, point, NULL);
  jbyte *scalar_ptr = (*env)->GetByteArrayElements(env, scalar, NULL);

  crypto_eddsa_scalarbase((uint8_t *)point_ptr, (const uint8_t *)scalar_ptr);

  (*env)->ReleaseByteArrayElements(env, point, point_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, scalar, scalar_ptr, JNI_ABORT);
}
