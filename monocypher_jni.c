#include "monocypher.h"
#include "net_lastninja_monocypher_Monocypher.h"
#include <jni.h>
#include <stdbool.h>

JNIEXPORT jint JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1verify16(
    JNIEnv *env, jobject obj, jbyteArray j_a, jbyteArray j_b) {

  if ((*env)->GetArrayLength(env, j_a) != 16 ||
      (*env)->GetArrayLength(env, j_b) != 16) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "Both arrays must be 16 bytes long");
    return -1;
  }

  jbyte *a = (*env)->GetByteArrayElements(env, j_a, NULL);
  jbyte *b = (*env)->GetByteArrayElements(env, j_b, NULL);

  // Monocypher expects const uint8_t*, so cast
  int result = crypto_verify16((const uint8_t *)a, (const uint8_t *)b);

  (*env)->ReleaseByteArrayElements(env, j_a, a,
                                   JNI_ABORT); // no write-back needed
  (*env)->ReleaseByteArrayElements(env, j_b, b, JNI_ABORT);

  return result;
}

JNIEXPORT jint JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1verify32(
    JNIEnv *env, jobject obj, jbyteArray j_a, jbyteArray j_b) {

  if ((*env)->GetArrayLength(env, j_a) != 32 ||
      (*env)->GetArrayLength(env, j_b) != 32) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    if (exc != NULL) {
      (*env)->ThrowNew(env, exc, "Both arrays must be 32 bytes long");
    } else {
      // should be unreachable
      return -1;
    }
    return 0;
  }

  jbyte *a = (*env)->GetByteArrayElements(env, j_a, NULL);
  jbyte *b = (*env)->GetByteArrayElements(env, j_b, NULL);

  // Monocypher expects const uint8_t*, so cast
  int result = crypto_verify32((const uint8_t *)a, (const uint8_t *)b);

  (*env)->ReleaseByteArrayElements(env, j_a, a,
                                   JNI_ABORT); // no write-back needed
  (*env)->ReleaseByteArrayElements(env, j_b, b, JNI_ABORT);

  return result;
}

JNIEXPORT jint JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1verify64(
    JNIEnv *env, jobject obj, jbyteArray j_a, jbyteArray j_b) {

  if ((*env)->GetArrayLength(env, j_a) != 64 ||
      (*env)->GetArrayLength(env, j_b) != 64) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    if (exc != NULL) {
      (*env)->ThrowNew(env, exc, "Both arrays must be 64 bytes long");
    } else {
      // should be unreachable
      return -1;
    }
    return 0;
  }

  jbyte *a = (*env)->GetByteArrayElements(env, j_a, NULL);
  jbyte *b = (*env)->GetByteArrayElements(env, j_b, NULL);

  // Monocypher expects const uint8_t*, so cast
  int result = crypto_verify64((const uint8_t *)a, (const uint8_t *)b);

  (*env)->ReleaseByteArrayElements(env, j_a, a,
                                   JNI_ABORT); // no write-back needed
  (*env)->ReleaseByteArrayElements(env, j_b, b, JNI_ABORT);

  return result;
}

JNIEXPORT void JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1wipe
  (JNIEnv *env, jobject obj, jbyteArray buf) {

  if (buf == NULL) {
    return;
  }

  jsize len = (*env)->GetArrayLength(env, buf);
  jbyte* ptr = (*env)->GetByteArrayElements(env, buf, NULL);
  if (ptr == NULL) {
    return;
  }

  crypto_wipe((void *) ptr, (size_t) len);

  (*env)->ReleaseByteArrayElements(env, buf, ptr, 0);

  return;
}

JNIEXPORT void JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1lock(
  JNIEnv *env,
  jobject obj,
  jobject cipher_text,
  jobject mac,
  jbyteArray key,
  jobject nonce,
  jobject ad,
  jobject plain_text) {

  // If npeClass is NULL, the JVM will already have thrown a ClassNotFoundException
  if (!cipher_text) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "cipher_text cannot be null");
    return;
  }

  if (!mac) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "mac cannot be null");
    return;
  }

  if (!key) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "key cannot be null");
    return;
  }

  if (!nonce) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "nonce cannot be null");
    return;
  }

  if (!plain_text) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "plain_text cannot be null");
    return;
  }

  jclass bufferClass = (*env)->FindClass(env, "java/nio/ByteBuffer");
  jmethodID isDirect = (*env)->GetMethodID(env, bufferClass, "isDirect", "()Z");

  if (!(*env)->CallBooleanMethod(env, cipher_text, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "cipher_text must be a direct ByteBuffer");
    return;
  }

  if (!(*env)->CallBooleanMethod(env, mac, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "mac must be a direct ByteBuffer");
    return;
  }

  if (!(*env)->CallBooleanMethod(env, nonce, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "nonce must be a direct ByteBuffer");
    return;
  }

  if (ad && !(*env)->CallBooleanMethod(env, ad, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "ad must be a direct ByteBuffer");
    return;
  }

  if (!(*env)->CallBooleanMethod(env, plain_text, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "plain_text must be a direct ByteBuffer");
    return;
  }

  jmethodID remaining = (*env)->GetMethodID(env, bufferClass, "remaining", "()I");

  jint mac_len = (*env)->CallIntMethod(env, mac, remaining);
  if (mac_len != 16) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "mac must be a buffer of length 16 bytes");
    return;
  }

  jint nonce_len = (*env)->CallIntMethod(env, nonce, remaining);
  if (nonce_len != 24) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "nonce must be a buffer of length 24 bytes");
    return;
  }

  jsize key_len = (*env)->GetArrayLength(env, key);
  if (key_len != 32) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "key must be a byte array of length 32 bytes");
    return;
  }


  uint8_t *ct_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, cipher_text);
  uint8_t *mac_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, mac);
  jbyte *jkey_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  const uint8_t *key_ptr = (const uint8_t *)jkey_ptr;
  const uint8_t *nonce_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, nonce);
  const uint8_t *ad_ptr = ad ? (uint8_t*)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len = (size_t)(ad ? (*env)->CallIntMethod(env, ad, remaining) : 0);
  uint8_t *pt_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, plain_text);
  const size_t pt_len = (size_t)(*env)->CallIntMethod(env, plain_text, remaining);

  crypto_aead_lock(
    ct_ptr,
    mac_ptr,
    key_ptr,
    nonce_ptr,
    ad_ptr,
    ad_len,
    pt_ptr,
    pt_len);

  (*env)->ReleaseByteArrayElements(env, key, jkey_ptr, JNI_ABORT);
}

JNIEXPORT jint JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1unlock(
  JNIEnv *env,
  jobject obj,
  jobject plain_text,
  jobject mac,
  jbyteArray key,
  jobject nonce,
  jobject ad,
  jobject cipher_text) {

  // If npeClass is NULL, the JVM will already have thrown a ClassNotFoundException
  if (!plain_text) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "plain_text cannot be null");
    return -1;
  }

  if (!mac) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "mac cannot be null");
    return -1;
  }

  if (!key) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "key cannot be null");
    return -1;
  }

  if (!nonce) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "nonce cannot be null");
    return -1;
  }

  if (!cipher_text) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, npeClass, "cipher_text cannot be null");
    return -1;
  }

  jclass bufferClass = (*env)->FindClass(env, "java/nio/ByteBuffer");
  jmethodID isDirect = (*env)->GetMethodID(env, bufferClass, "isDirect", "()Z");

  if (!(*env)->CallBooleanMethod(env, plain_text, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "plain_text must be a direct ByteBuffer");
    return -1;
  }

  if (!(*env)->CallBooleanMethod(env, mac, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "mac must be a direct ByteBuffer");
    return -1;
  }

  if (!(*env)->CallBooleanMethod(env, nonce, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "nonce must be a direct ByteBuffer");
    return -1;
  }

  if (ad && !(*env)->CallBooleanMethod(env, ad, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "ad must be a direct ByteBuffer");
    return -1;
  }

  if (!(*env)->CallBooleanMethod(env, cipher_text, isDirect)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "cipher_text must be a direct ByteBuffer");
    return -1;
  }

  jmethodID remaining = (*env)->GetMethodID(env, bufferClass, "remaining", "()I");

  jint mac_len = (*env)->CallIntMethod(env, mac, remaining);
  if (mac_len != 16) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "mac must be a buffer of length 16 bytes");
    return -1;
  }

  jint nonce_len = (*env)->CallIntMethod(env, nonce, remaining);
  if (nonce_len != 24) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "nonce must be a buffer of length 24 bytes");
    return -1;
  }

  jsize key_len = (*env)->GetArrayLength(env, key);
  if (key_len != 32) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "key must be a byte array of length 32 bytes");
    return -1;
  }

  uint8_t *pt_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, plain_text);
  uint8_t *mac_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, mac);
  jbyte *jkey_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  const uint8_t *key_ptr = (const uint8_t *)jkey_ptr;
  const uint8_t *nonce_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, nonce);
  const uint8_t *ad_ptr = ad ? (uint8_t*)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len = (size_t)(ad ? (*env)->CallIntMethod(env, ad, remaining) : 0);
  uint8_t *ct_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, cipher_text);
  const size_t ct_len = (size_t)(*env)->CallIntMethod(env, cipher_text, remaining);

  int result = crypto_aead_unlock(
    pt_ptr,
    mac_ptr,
    key_ptr,
    nonce_ptr,
    ad_ptr,
    ad_len,
    ct_ptr,
    ct_len);

  (*env)->ReleaseByteArrayElements(env, key, jkey_ptr, JNI_ABORT);

  return result;
}
