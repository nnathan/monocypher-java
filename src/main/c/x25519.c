#include "jni_util.h"

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1public_1key(
    JNIEnv *env,
    jobject obj,
    jbyteArray public_key,
    jbyteArray secret_key) {
  (void)obj;

  CHECK_NULL(public_key, );
  CHECK_NULL(secret_key, );

  ENSURE_ARRAY_LENGTH(public_key, 32, );
  ENSURE_ARRAY_LENGTH(secret_key, 32, );

  jbyte *public_key_ptr = (*env)->GetByteArrayElements(env, public_key, NULL);
  jbyte *secret_key_ptr = (*env)->GetByteArrayElements(env, secret_key, NULL);

  crypto_x25519_public_key((uint8_t *)public_key_ptr,
                           (const uint8_t *)secret_key_ptr);

  (*env)->ReleaseByteArrayElements(env, public_key, public_key_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, secret_key, secret_key_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1x25519(
    JNIEnv *env,
    jobject obj,
    jbyteArray raw_shared_secret,
    jbyteArray your_secret_key,
    jbyteArray their_public_key) {
  (void)obj;

  CHECK_NULL(raw_shared_secret, );
  CHECK_NULL(your_secret_key, );
  CHECK_NULL(their_public_key, );

  ENSURE_ARRAY_LENGTH(raw_shared_secret, 32, );
  ENSURE_ARRAY_LENGTH(your_secret_key, 32, );
  ENSURE_ARRAY_LENGTH(their_public_key, 32, );

  jbyte *raw_shared_secret_ptr =
      (*env)->GetByteArrayElements(env, raw_shared_secret, NULL);
  jbyte *your_secret_key_ptr =
      (*env)->GetByteArrayElements(env, your_secret_key, NULL);
  jbyte *their_public_key_ptr =
      (*env)->GetByteArrayElements(env, their_public_key, NULL);

  crypto_x25519((uint8_t *)raw_shared_secret_ptr,
                (const uint8_t *)your_secret_key_ptr,
                (const uint8_t *)their_public_key_ptr);

  (*env)->ReleaseByteArrayElements(env, raw_shared_secret,
                                   raw_shared_secret_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, your_secret_key, your_secret_key_ptr,
                                   JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, their_public_key, their_public_key_ptr,
                                   JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1to_1eddsa(
    JNIEnv *env,
    jobject obj,
    jbyteArray eddsa,
    jbyteArray x25519) {
  (void)obj;

  CHECK_NULL(eddsa, );
  CHECK_NULL(x25519, );

  ENSURE_ARRAY_LENGTH(eddsa, 32, );
  ENSURE_ARRAY_LENGTH(x25519, 32, );

  jbyte *eddsa_ptr = (*env)->GetByteArrayElements(env, eddsa, NULL);
  jbyte *x25519_ptr = (*env)->GetByteArrayElements(env, x25519, NULL);

  crypto_x25519_to_eddsa((uint8_t *)eddsa_ptr, (const uint8_t *)x25519_ptr);

  (*env)->ReleaseByteArrayElements(env, eddsa, eddsa_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, x25519, x25519_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1inverse(
    JNIEnv *env,
    jobject obj,
    jbyteArray blind_salt,
    jbyteArray private_key,
    jbyteArray curve_point) {
  (void)obj;

  CHECK_NULL(blind_salt, );
  CHECK_NULL(private_key, );
  CHECK_NULL(curve_point, );

  ENSURE_ARRAY_LENGTH(blind_salt, 32, );
  ENSURE_ARRAY_LENGTH(private_key, 32, );
  ENSURE_ARRAY_LENGTH(curve_point, 32, );

  jbyte *blind_salt_ptr = (*env)->GetByteArrayElements(env, blind_salt, NULL);
  jbyte *private_key_ptr = (*env)->GetByteArrayElements(env, private_key, NULL);
  jbyte *curve_point_ptr = (*env)->GetByteArrayElements(env, curve_point, NULL);

  crypto_x25519_inverse((uint8_t *)blind_salt_ptr,
                        (const uint8_t *)private_key_ptr,
                        (const uint8_t *)curve_point_ptr);

  (*env)->ReleaseByteArrayElements(env, blind_salt, blind_salt_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, private_key, private_key_ptr,
                                   JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, curve_point, curve_point_ptr,
                                   JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1dirty_1small(
    JNIEnv *env,
    jobject obj,
    jbyteArray pk,
    jbyteArray sk) {
  (void)obj;

  CHECK_NULL(pk, );
  CHECK_NULL(sk, );

  ENSURE_ARRAY_LENGTH(pk, 32, );
  ENSURE_ARRAY_LENGTH(sk, 32, );

  jbyte *pk_ptr = (*env)->GetByteArrayElements(env, pk, NULL);
  jbyte *sk_ptr = (*env)->GetByteArrayElements(env, sk, NULL);

  crypto_x25519_dirty_small((uint8_t *)pk_ptr, (const uint8_t *)sk_ptr);

  (*env)->ReleaseByteArrayElements(env, pk, pk_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, sk, sk_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1x25519_1dirty_1fast(
    JNIEnv *env,
    jobject obj,
    jbyteArray pk,
    jbyteArray sk) {
  (void)obj;

  CHECK_NULL(pk, );
  CHECK_NULL(sk, );

  ENSURE_ARRAY_LENGTH(pk, 32, );
  ENSURE_ARRAY_LENGTH(sk, 32, );

  jbyte *pk_ptr = (*env)->GetByteArrayElements(env, pk, NULL);
  jbyte *sk_ptr = (*env)->GetByteArrayElements(env, sk, NULL);

  crypto_x25519_dirty_fast((uint8_t *)pk_ptr, (const uint8_t *)sk_ptr);

  (*env)->ReleaseByteArrayElements(env, pk, pk_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, sk, sk_ptr, JNI_ABORT);
}
