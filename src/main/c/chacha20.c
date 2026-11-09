#include "jni_util.h"

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1chacha20_1h(JNIEnv *env,
                                                             jobject obj,
                                                             jbyteArray out,
                                                             jbyteArray key,
                                                             jbyteArray in) {
  (void)obj;

  CHECK_NULL(out, );
  CHECK_NULL(key, );
  CHECK_NULL(in, );

  ENSURE_ARRAY_LENGTH(out, 32, );
  ENSURE_ARRAY_LENGTH(key, 32, );
  ENSURE_ARRAY_LENGTH(in, 16, );

  jbyte *out_ptr = (*env)->GetByteArrayElements(env, out, NULL);
  jbyte *key_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  jbyte *in_ptr = (*env)->GetByteArrayElements(env, in, NULL);

  crypto_chacha20_h((uint8_t *)out_ptr, (const uint8_t *)key_ptr,
                    (const uint8_t *)in_ptr);

  (*env)->ReleaseByteArrayElements(env, out, out_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, in, in_ptr, JNI_ABORT);
}

JNIEXPORT jlong JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1chacha20_1djb(
    JNIEnv *env,
    jobject obj,
    jobject cipher_text,
    jobject plain_text,
    jlong text_size,
    jobject key,
    jobject nonce,
    jlong ctr) {
  (void)obj;

  CHECK_NULL(cipher_text, 0);
  CHECK_NULL(key, 0);
  CHECK_NULL(nonce, 0);

  INIT_BYTE_BUFFER_CLASS(bbClass);

  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, cipher_text, 0);
  if (plain_text) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, plain_text, 0);
  }
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, key, 0);
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, nonce, 0);

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, key, 32, 0);
  ENSURE_BYTE_BUFFER_LENGTH(bbClass, nonce, 8, 0);

  if (text_size < 0) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "text_size must be non-negative");
    return 0;
  }

  size_t cipher_text_len =
      (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

  if (cipher_text_len != (size_t)text_size) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc,
                     "cipher_text length needs to be the same as text_size");
    return 0;
  }

  if (plain_text) {
    size_t plain_text_len =
        (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

    if (cipher_text_len != plain_text_len) {
      jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
      (*env)->ThrowNew(env, exc,
                       "plain_text needs to be same length as cipher_text");
      return 0;
    }
  }

  jbyte *cipher_text_ptr = (*env)->GetDirectBufferAddress(env, cipher_text);
  jbyte *plain_text_ptr =
      plain_text ? (*env)->GetDirectBufferAddress(env, plain_text) : NULL;
  jbyte *key_ptr = (*env)->GetDirectBufferAddress(env, key);
  jbyte *nonce_ptr = (*env)->GetDirectBufferAddress(env, nonce);

  uint64_t result = crypto_chacha20_djb(
      (uint8_t *)cipher_text_ptr, (const uint8_t *)plain_text_ptr,
      (size_t)text_size, (const uint8_t *)key_ptr, (const uint8_t *)nonce_ptr,
      (uint64_t)ctr);

  return result;
}

JNIEXPORT jlong JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1chacha20_1ietf(
    JNIEnv *env,
    jobject obj,
    jobject cipher_text,
    jobject plain_text,
    jlong text_size,
    jobject key,
    jobject nonce,
    jlong ctr) {
  (void)obj;

  CHECK_NULL(cipher_text, 0);
  CHECK_NULL(key, 0);
  CHECK_NULL(nonce, 0);

  INIT_BYTE_BUFFER_CLASS(bbClass);

  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, cipher_text, 0);
  if (plain_text) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, plain_text, 0);
  }
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, key, 0);
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, nonce, 0);

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, key, 32, 0);
  ENSURE_BYTE_BUFFER_LENGTH(bbClass, nonce, 12, 0);

  if (text_size < 0) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "text_size must be non-negative");
    return 0;
  }

  size_t cipher_text_len =
      (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

  if (cipher_text_len != (size_t)text_size) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc,
                     "cipher_text length needs to be the same as text_size");
    return 0;
  }

  if (plain_text) {
    size_t plain_text_len =
        (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

    if (cipher_text_len != plain_text_len) {
      jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
      (*env)->ThrowNew(env, exc,
                       "plain_text needs to be same length as cipher_text");
      return 0;
    }
  }

  jbyte *cipher_text_ptr = (*env)->GetDirectBufferAddress(env, cipher_text);
  jbyte *plain_text_ptr =
      plain_text ? (*env)->GetDirectBufferAddress(env, plain_text) : NULL;
  jbyte *key_ptr = (*env)->GetDirectBufferAddress(env, key);
  jbyte *nonce_ptr = (*env)->GetDirectBufferAddress(env, nonce);

  uint64_t result = crypto_chacha20_ietf(
      (uint8_t *)cipher_text_ptr, (const uint8_t *)plain_text_ptr,
      (size_t)text_size, (const uint8_t *)key_ptr, (const uint8_t *)nonce_ptr,
      (uint64_t)ctr);

  return result;
}

JNIEXPORT jlong JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1chacha20_1x(
    JNIEnv *env,
    jobject obj,
    jobject cipher_text,
    jobject plain_text,
    jlong text_size,
    jobject key,
    jobject nonce,
    jlong ctr) {
  (void)obj;

  CHECK_NULL(cipher_text, 0);
  CHECK_NULL(key, 0);
  CHECK_NULL(nonce, 0);

  INIT_BYTE_BUFFER_CLASS(bbClass);

  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, cipher_text, 0);
  if (plain_text) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, plain_text, 0);
  }
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, key, 0);
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, nonce, 0);

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, key, 32, 0);
  ENSURE_BYTE_BUFFER_LENGTH(bbClass, nonce, 24, 0);

  if (text_size < 0) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "text_size must be non-negative");
    return 0;
  }

  size_t cipher_text_len =
      (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

  if (cipher_text_len != (size_t)text_size) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc,
                     "cipher_text length needs to be the same as text_size");
    return 0;
  }

  if (plain_text) {
    size_t plain_text_len =
        (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

    if (cipher_text_len != plain_text_len) {
      jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
      (*env)->ThrowNew(env, exc,
                       "plain_text needs to be same length as cipher_text");
      return 0;
    }
  }

  jbyte *cipher_text_ptr = (*env)->GetDirectBufferAddress(env, cipher_text);
  jbyte *plain_text_ptr =
      plain_text ? (*env)->GetDirectBufferAddress(env, plain_text) : NULL;
  jbyte *key_ptr = (*env)->GetDirectBufferAddress(env, key);
  jbyte *nonce_ptr = (*env)->GetDirectBufferAddress(env, nonce);

  uint64_t result = crypto_chacha20_x(
      (uint8_t *)cipher_text_ptr, (const uint8_t *)plain_text_ptr,
      (size_t)text_size, (const uint8_t *)key_ptr, (const uint8_t *)nonce_ptr,
      (uint64_t)ctr);

  return result;
}
