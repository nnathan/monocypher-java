#include <jni.h>
#include <stdbool.h>
#include <stdlib.h>
#include "monocypher.h"
#include "net_lastninja_monocypher_Monocypher.h"

#define CHECK_NULL_WITH_NAME(var, name_str, ret_val)                 \
  do {                                                               \
    if (!(var)) {                                                    \
      jclass npeClass =                                              \
          (*env)->FindClass(env, "java/lang/NullPointerException");  \
      if (npeClass)                                                  \
        (*env)->ThrowNew(env, npeClass, name_str " cannot be null"); \
      return ret_val;                                                \
    }                                                                \
  } while (0)

#define CHECK_NULL(var, ret_val) CHECK_NULL_WITH_NAME(var, #var, ret_val)

#define INIT_BYTE_BUFFER_CLASS(var)                                            \
  jclass var = (*env)->FindClass(env, "java/nio/ByteBuffer");                  \
  jmethodID var##_isDirect = (*env)->GetMethodID(env, var, "isDirect", "()Z"); \
  jmethodID var##_remaining =                                                  \
      (*env)->GetMethodID(env, bbClass, "remaining", "()I");

#define ENSURE_BYTE_BUFFER_IS_DIRECT(class_var, bb_var, ret_val)          \
  do {                                                                    \
    if (!(*env)->CallBooleanMethod(env, bb_var, class_var##_isDirect)) {  \
      jclass exc =                                                        \
          (*env)->FindClass(env, "java/lang/IllegalArgumentException");   \
      (*env)->ThrowNew(env, exc, #bb_var " must be a direct ByteBuffer"); \
      return ret_val;                                                     \
    }                                                                     \
  } while (0)

#define ENSURE_BYTE_BUFFER_LENGTH(class_var, bb_var, len, ret_val)            \
  do {                                                                        \
    if ((*env)->CallIntMethod(env, bb_var, class_var##_remaining) != len) {   \
      jclass exc =                                                            \
          (*env)->FindClass(env, "java/lang/IllegalArgumentException");       \
      (*env)->ThrowNew(env, exc,                                              \
                       #bb_var " must be a buffer of length " #len " bytes"); \
      return ret_val;                                                         \
    }                                                                         \
  } while (0)

#define ENSURE_ARRAY_LENGTH(array_var, len, ret_val)                          \
  do {                                                                        \
    if ((*env)->GetArrayLength(env, array_var) != len) {                      \
      jclass exc =                                                            \
          (*env)->FindClass(env, "java/lang/IllegalArgumentException");       \
      (*env)->ThrowNew(                                                       \
          env, exc, #array_var " must be an array of length " #len " bytes"); \
      return ret_val;                                                         \
    }                                                                         \
  } while (0)

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1verify16(JNIEnv *env,
                                                          jobject obj,
                                                          jbyteArray j_a,
                                                          jbyteArray j_b) {
  (void)obj;

  CHECK_NULL_WITH_NAME(j_a, "a", -1);
  CHECK_NULL_WITH_NAME(j_b, "b", -1);

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
                                   JNI_ABORT);  // no write-back needed
  (*env)->ReleaseByteArrayElements(env, j_b, b, JNI_ABORT);

  return result;
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1verify32(JNIEnv *env,
                                                          jobject obj,
                                                          jbyteArray j_a,
                                                          jbyteArray j_b) {
  (void)obj;

  CHECK_NULL_WITH_NAME(j_a, "a", -1);
  CHECK_NULL_WITH_NAME(j_b, "b", -1);

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
                                   JNI_ABORT);  // no write-back needed
  (*env)->ReleaseByteArrayElements(env, j_b, b, JNI_ABORT);

  return result;
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1verify64(JNIEnv *env,
                                                          jobject obj,
                                                          jbyteArray j_a,
                                                          jbyteArray j_b) {
  (void)obj;

  CHECK_NULL_WITH_NAME(j_a, "a", -1);
  CHECK_NULL_WITH_NAME(j_b, "b", -1);

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
                                   JNI_ABORT);  // no write-back needed
  (*env)->ReleaseByteArrayElements(env, j_b, b, JNI_ABORT);

  return result;
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe___3B(JNIEnv *env,
                                                           jobject obj,
                                                           jbyteArray buf) {
  (void)obj;

  if (buf == NULL) {
    return;
  }

  jsize len = (*env)->GetArrayLength(env, buf);
  jbyte *ptr = (*env)->GetByteArrayElements(env, buf, NULL);
  if (ptr == NULL) {
    return;
  }

  crypto_wipe((void *)ptr, (size_t)len);

  (*env)->ReleaseByteArrayElements(env, buf, ptr, 0);

  return;
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1lock(
    JNIEnv *env,
    jobject obj,
    jobject cipher_text,
    jobject mac,
    jbyteArray key,
    jobject nonce,
    jobject ad,
    jobject plain_text) {
  (void)obj;

  CHECK_NULL(cipher_text, );
  CHECK_NULL(mac, );
  CHECK_NULL(key, );
  CHECK_NULL(nonce, );
  CHECK_NULL(plain_text, );

  INIT_BYTE_BUFFER_CLASS(bbClass);

  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, cipher_text, );
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, mac, );
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, nonce, );
  if (ad) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, ad, );
  };
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, plain_text, );

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, mac, 16, );
  ENSURE_BYTE_BUFFER_LENGTH(bbClass, nonce, 24, );

  ENSURE_ARRAY_LENGTH(key, 32, );

  uint8_t *ct_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, cipher_text);
  uint8_t *mac_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, mac);
  jbyte *jkey_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  const uint8_t *key_ptr = (const uint8_t *)jkey_ptr;
  const uint8_t *nonce_ptr =
      (uint8_t *)(*env)->GetDirectBufferAddress(env, nonce);
  const uint8_t *ad_ptr =
      ad ? (uint8_t *)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len =
      (size_t)(ad ? (*env)->CallIntMethod(env, ad, bbClass_remaining) : 0);
  uint8_t *pt_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, plain_text);
  const size_t pt_len =
      (size_t)(*env)->CallIntMethod(env, plain_text, bbClass_remaining);

  crypto_aead_lock(ct_ptr, mac_ptr, key_ptr, nonce_ptr, ad_ptr, ad_len, pt_ptr,
                   pt_len);

  (*env)->ReleaseByteArrayElements(env, key, jkey_ptr, JNI_ABORT);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1unlock(
    JNIEnv *env,
    jobject obj,
    jobject plain_text,
    jobject mac,
    jbyteArray key,
    jobject nonce,
    jobject ad,
    jobject cipher_text) {
  (void)obj;

  CHECK_NULL(plain_text, -1);
  CHECK_NULL(mac, -1);
  CHECK_NULL(key, -1);
  CHECK_NULL(nonce, -1);
  CHECK_NULL(cipher_text, -1);

  INIT_BYTE_BUFFER_CLASS(bbClass);

  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, plain_text, -1);
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, mac, -1);
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, nonce, -1);
  if (ad) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, ad, -1);
  };
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, cipher_text, -1);

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, mac, 16, -1);
  ENSURE_BYTE_BUFFER_LENGTH(bbClass, nonce, 24, -1);

  ENSURE_ARRAY_LENGTH(key, 32, -1);

  uint8_t *pt_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, plain_text);
  uint8_t *mac_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, mac);
  jbyte *jkey_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  const uint8_t *key_ptr = (const uint8_t *)jkey_ptr;
  const uint8_t *nonce_ptr =
      (uint8_t *)(*env)->GetDirectBufferAddress(env, nonce);
  const uint8_t *ad_ptr =
      ad ? (uint8_t *)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len =
      (size_t)(ad ? (*env)->CallIntMethod(env, ad, bbClass_remaining) : 0);
  uint8_t *ct_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, cipher_text);
  const size_t ct_len =
      (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

  int result = crypto_aead_unlock(pt_ptr, mac_ptr, key_ptr, nonce_ptr, ad_ptr,
                                  ad_len, ct_ptr, ct_len);

  (*env)->ReleaseByteArrayElements(env, key, jkey_ptr, JNI_ABORT);

  return result;
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1init_1x(
    JNIEnv *env,
    jobject obj,
    jobject aead_ctx,
    jbyteArray key,
    jbyteArray nonce) {
  (void)obj;

  CHECK_NULL_WITH_NAME(aead_ctx, "ctx", );
  CHECK_NULL(key, );
  CHECK_NULL(nonce, );

  ENSURE_ARRAY_LENGTH(key, 32, );
  ENSURE_ARRAY_LENGTH(nonce, 24, );

  jbyte *key_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  jbyte *nonce_ptr = (*env)->GetByteArrayElements(env, nonce, NULL);

  jclass ctxClass = (*env)->GetObjectClass(env, aead_ctx);
  jfieldID fidCounter = (*env)->GetFieldID(env, ctxClass, "counter", "J");

  jfieldID fidKey = (*env)->GetFieldID(env, ctxClass, "key", "[B");
  jbyteArray keyArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  crypto_aead_init_x(&ctx, (const uint8_t *)key_ptr,
                     (const uint8_t *)nonce_ptr);

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong)ctx.counter);
  (*env)->SetByteArrayRegion(env, keyArray, 0, 32, (const jbyte *)ctx.key);
  (*env)->SetByteArrayRegion(env, nonceArray, 0, 8, (const jbyte *)ctx.nonce);

  crypto_wipe(&ctx, sizeof(ctx));

  (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, nonce, nonce_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1init_1djb(
    JNIEnv *env,
    jobject obj,
    jobject aead_ctx,
    jbyteArray key,
    jbyteArray nonce) {
  (void)obj;

  CHECK_NULL_WITH_NAME(aead_ctx, "ctx", );
  CHECK_NULL(key, );
  CHECK_NULL(nonce, );

  ENSURE_ARRAY_LENGTH(key, 32, );
  ENSURE_ARRAY_LENGTH(nonce, 8, );

  jbyte *key_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  jbyte *nonce_ptr = (*env)->GetByteArrayElements(env, nonce, NULL);

  jclass ctxClass = (*env)->GetObjectClass(env, aead_ctx);
  jfieldID fidCounter = (*env)->GetFieldID(env, ctxClass, "counter", "J");

  jfieldID fidKey = (*env)->GetFieldID(env, ctxClass, "key", "[B");
  jbyteArray keyArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  crypto_aead_init_djb(&ctx, (const uint8_t *)key_ptr,
                       (const uint8_t *)nonce_ptr);

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong)ctx.counter);
  (*env)->SetByteArrayRegion(env, keyArray, 0, 32, (const jbyte *)ctx.key);
  (*env)->SetByteArrayRegion(env, nonceArray, 0, 8, (const jbyte *)ctx.nonce);

  crypto_wipe(&ctx, sizeof(ctx));

  (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, nonce, nonce_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1init_1ietf(
    JNIEnv *env,
    jobject obj,
    jobject aead_ctx,
    jbyteArray key,
    jbyteArray nonce) {
  (void)obj;

  CHECK_NULL_WITH_NAME(aead_ctx, "ctx", );
  CHECK_NULL(key, );
  CHECK_NULL(nonce, );

  ENSURE_ARRAY_LENGTH(key, 32, );
  ENSURE_ARRAY_LENGTH(nonce, 12, );

  jbyte *key_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  jbyte *nonce_ptr = (*env)->GetByteArrayElements(env, nonce, NULL);

  jclass ctxClass = (*env)->GetObjectClass(env, aead_ctx);
  jfieldID fidCounter = (*env)->GetFieldID(env, ctxClass, "counter", "J");

  jfieldID fidKey = (*env)->GetFieldID(env, ctxClass, "key", "[B");
  jbyteArray keyArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  crypto_aead_init_ietf(&ctx, (const uint8_t *)key_ptr,
                        (const uint8_t *)nonce_ptr);

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong)ctx.counter);
  (*env)->SetByteArrayRegion(env, keyArray, 0, 32, (const jbyte *)ctx.key);
  (*env)->SetByteArrayRegion(env, nonceArray, 0, 8, (const jbyte *)ctx.nonce);

  crypto_wipe(&ctx, sizeof(ctx));

  (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, nonce, nonce_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024AEAD_1ctx_2(
    JNIEnv *env,
    jobject obj,
    jobject aead_ctx) {
  (void)obj;

  if (!aead_ctx) {
    return;
  }

  jclass ctxClass = (*env)->GetObjectClass(env, aead_ctx);
  jfieldID fidCounter = (*env)->GetFieldID(env, ctxClass, "counter", "J");

  jfieldID fidKey = (*env)->GetFieldID(env, ctxClass, "key", "[B");
  jbyteArray keyArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  jbyte key[32] = {0};
  jbyte nonce[8] = {0};

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong)0);
  (*env)->SetByteArrayRegion(env, keyArray, 0, 32, (const jbyte *)key);
  (*env)->SetByteArrayRegion(env, nonceArray, 0, 8, (const jbyte *)nonce);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1write(
    JNIEnv *env,
    jobject obj,
    jobject aead_ctx,
    jobject cipher_text,
    jobject mac,
    jobject ad,
    jobject plain_text) {
  (void)obj;

  CHECK_NULL_WITH_NAME(aead_ctx, "ctx", );
  CHECK_NULL(cipher_text, );
  CHECK_NULL(mac, );
  CHECK_NULL(plain_text, );

  INIT_BYTE_BUFFER_CLASS(bbClass)

  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, cipher_text, );
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, mac, );
  if (ad) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, ad, );
  };
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, plain_text, );

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, mac, 16, );

  jclass ctxClass = (*env)->GetObjectClass(env, aead_ctx);
  jfieldID fidCounter = (*env)->GetFieldID(env, ctxClass, "counter", "J");

  jfieldID fidKey = (*env)->GetFieldID(env, ctxClass, "key", "[B");
  jbyteArray keyArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  ctx.counter = (uint64_t)(*env)->GetLongField(env, aead_ctx, fidCounter);

  jbyte *aead_ctx_key_ptr = (*env)->GetByteArrayElements(env, keyArray, NULL);
  for (int i = 0; i < 32; i++) {
    ctx.key[i] = (uint8_t)aead_ctx_key_ptr[i];
  }

  jbyte *aead_ctx_nonce_ptr =
      (*env)->GetByteArrayElements(env, nonceArray, NULL);
  for (int i = 0; i < 8; i++) {
    ctx.nonce[i] = (uint8_t)aead_ctx_nonce_ptr[i];
  }

  uint8_t *ct_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, cipher_text);
  uint8_t *mac_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, mac);
  const uint8_t *ad_ptr =
      ad ? (uint8_t *)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len =
      (size_t)(ad ? (*env)->CallIntMethod(env, ad, bbClass_remaining) : 0);
  uint8_t *pt_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, plain_text);
  const size_t pt_len =
      (size_t)(*env)->CallIntMethod(env, plain_text, bbClass_remaining);

  crypto_aead_write(&ctx, ct_ptr, mac_ptr, ad_ptr, ad_len, pt_ptr, pt_len);

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong)ctx.counter);

  for (int i = 0; i < 32; i++) {
    aead_ctx_key_ptr[i] = (jbyte)ctx.key[i];
  }
  (*env)->ReleaseByteArrayElements(env, keyArray, aead_ctx_key_ptr, 0);

  for (int i = 0; i < 8; i++) {
    aead_ctx_nonce_ptr[i] = (jbyte)ctx.nonce[i];
  }
  (*env)->ReleaseByteArrayElements(env, nonceArray, aead_ctx_nonce_ptr, 0);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1read(
    JNIEnv *env,
    jobject obj,
    jobject aead_ctx,
    jobject plain_text,
    jobject mac,
    jobject ad,
    jobject cipher_text) {
  (void)obj;

  CHECK_NULL_WITH_NAME(aead_ctx, "ctx", -1);
  CHECK_NULL(plain_text, -1);
  CHECK_NULL(mac, -1);
  CHECK_NULL(cipher_text, -1);

  INIT_BYTE_BUFFER_CLASS(bbClass)

  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, plain_text, -1);
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, mac, -1);
  if (ad) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, ad, -1);
  };
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, cipher_text, -1);

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, mac, 16, -1);

  jclass ctxClass = (*env)->GetObjectClass(env, aead_ctx);
  jfieldID fidCounter = (*env)->GetFieldID(env, ctxClass, "counter", "J");

  jfieldID fidKey = (*env)->GetFieldID(env, ctxClass, "key", "[B");
  jbyteArray keyArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray =
      (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  ctx.counter = (uint64_t)(*env)->GetLongField(env, aead_ctx, fidCounter);

  jbyte *aead_ctx_key_ptr = (*env)->GetByteArrayElements(env, keyArray, NULL);
  for (int i = 0; i < 32; i++) {
    ctx.key[i] = (uint8_t)aead_ctx_key_ptr[i];
  }

  jbyte *aead_ctx_nonce_ptr =
      (*env)->GetByteArrayElements(env, nonceArray, NULL);
  for (int i = 0; i < 8; i++) {
    ctx.nonce[i] = (uint8_t)aead_ctx_nonce_ptr[i];
  }

  uint8_t *pt_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, plain_text);
  uint8_t *mac_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, mac);
  const uint8_t *ad_ptr =
      ad ? (uint8_t *)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len =
      (size_t)(ad ? (*env)->CallIntMethod(env, ad, bbClass_remaining) : 0);
  uint8_t *ct_ptr = (uint8_t *)(*env)->GetDirectBufferAddress(env, cipher_text);
  const size_t ct_len =
      (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

  int result =
      crypto_aead_read(&ctx, pt_ptr, mac_ptr, ad_ptr, ad_len, ct_ptr, ct_len);

  if (result == -1) {
    (*env)->ReleaseByteArrayElements(env, keyArray, aead_ctx_key_ptr,
                                     JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, nonceArray, aead_ctx_nonce_ptr,
                                     JNI_ABORT);
    return result;
  }

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong)ctx.counter);

  for (int i = 0; i < 32; i++) {
    aead_ctx_key_ptr[i] = (jbyte)ctx.key[i];
  }
  (*env)->ReleaseByteArrayElements(env, keyArray, aead_ctx_key_ptr, 0);

  for (int i = 0; i < 8; i++) {
    aead_ctx_nonce_ptr[i] = (jbyte)ctx.nonce[i];
  }
  (*env)->ReleaseByteArrayElements(env, nonceArray, aead_ctx_nonce_ptr, 0);

  return result;
}

#define ENSURE_ARRAY_LENGTH_BETWEEN(array_var, start, end, ret_val)            \
  do {                                                                         \
    jint len = (*env)->GetArrayLength(env, array_var);                         \
    if (len < start || len > end) {                                            \
      jclass exc =                                                             \
          (*env)->FindClass(env, "java/lang/IllegalArgumentException");        \
      (*env)->ThrowNew(                                                        \
          env, exc,                                                            \
          #array_var " must be an array of length between (inclusive) " #start \
                     " and " #end " bytes");                                   \
      return ret_val;                                                          \
    }                                                                          \
  } while (0)

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b(JNIEnv *env,
                                                         jobject obj,
                                                         jbyteArray hash,
                                                         jbyteArray message) {
  (void)obj;

  CHECK_NULL(hash, );

  ENSURE_ARRAY_LENGTH_BETWEEN(hash, 1, 64, );

  jbyte *hash_ptr = (*env)->GetByteArrayElements(env, hash, NULL);
  jint hash_len = (*env)->GetArrayLength(env, hash);

  jint msg_len = 0;
  jbyte *msg_ptr = NULL;

  if (message) {
    msg_len = (*env)->GetArrayLength(env, message);
    msg_ptr = (*env)->GetByteArrayElements(env, message, NULL);
  }

  crypto_blake2b((uint8_t *)hash_ptr, (size_t)hash_len,
                 (const uint8_t *)msg_ptr, (size_t)msg_len);

  (*env)->ReleaseByteArrayElements(env, hash, hash_ptr, 0);
  if (message) {
    (*env)->ReleaseByteArrayElements(env, message, msg_ptr, JNI_ABORT);
  }
}

#define ENSURE_BYTE_BUFFER_LENGTH_BETWEEN(class_var, bb_var, start, end,    \
                                          ret_val)                          \
  do {                                                                      \
    jint len = (*env)->CallIntMethod(env, bb_var, class_var##_remaining);   \
    if (len < start || len > end) {                                         \
      jclass exc =                                                          \
          (*env)->FindClass(env, "java/lang/IllegalArgumentException");     \
      (*env)->ThrowNew(                                                     \
          env, exc,                                                         \
          #bb_var " must be a buffer of length between (inclusive) " #start \
                  " and " #end " bytes");                                   \
      return ret_val;                                                       \
    }                                                                       \
  } while (0)

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b_1keyed(
    JNIEnv *env,
    jobject obj,
    jobject hash,
    jobject key,
    jobject message) {
  (void)obj;

  CHECK_NULL(hash, );

  INIT_BYTE_BUFFER_CLASS(bbClass);

  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, hash, );
  if (key) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, hash, );
  }
  if (message) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, message, );
  }

  ENSURE_BYTE_BUFFER_LENGTH_BETWEEN(bbClass, hash, 1, 64, );
  if (key) {
    ENSURE_BYTE_BUFFER_LENGTH_BETWEEN(bbClass, key, 0, 64, );
  }

  jbyte *hash_ptr = (*env)->GetDirectBufferAddress(env, hash);
  jint hash_len = (*env)->CallIntMethod(env, hash, bbClass_remaining);

  jbyte *key_ptr = NULL;
  jint key_len = 0;

  if (key) {
    key_ptr = (*env)->GetDirectBufferAddress(env, key);
    key_len = (*env)->CallIntMethod(env, key, bbClass_remaining);
  }

  jbyte *msg_ptr = NULL;
  jint msg_len = 0;

  if (message) {
    msg_ptr = (*env)->GetDirectBufferAddress(env, message);
    msg_len = (*env)->CallIntMethod(env, message, bbClass_remaining);
  }

  crypto_blake2b_keyed((uint8_t *)hash_ptr, (size_t)hash_len,
                       (const uint8_t *)key_ptr, (size_t)key_len,
                       (const uint8_t *)msg_ptr, (size_t)msg_len);
}

#define TO_BLAKE2_CTX_CLASS(c_ctx, java_ctx)                                 \
  do {                                                                       \
    jclass ctxClass = (*env)->GetObjectClass(env, java_ctx);                 \
    {                                                                        \
      jfieldID fidHash = (*env)->GetFieldID(env, ctxClass, "hash", "[J");    \
      jlongArray hashArray =                                                 \
          (jlongArray)(*env)->GetObjectField(env, java_ctx, fidHash);        \
      (*env)->SetLongArrayRegion(env, hashArray, 0, 8,                       \
                                 (const jlong *)c_ctx.hash);                 \
    }                                                                        \
    {                                                                        \
      jfieldID fidInputOffset =                                              \
          (*env)->GetFieldID(env, ctxClass, "input_offset", "[J");           \
      jlongArray inputOffsetArray =                                          \
          (jlongArray)(*env)->GetObjectField(env, java_ctx, fidInputOffset); \
      (*env)->SetLongArrayRegion(env, inputOffsetArray, 0, 2,                \
                                 (const jlong *)c_ctx.input_offset);         \
    }                                                                        \
    {                                                                        \
      jfieldID fidInput = (*env)->GetFieldID(env, ctxClass, "input", "[J");  \
      jlongArray inputArray =                                                \
          (jlongArray)(*env)->GetObjectField(env, java_ctx, fidInput);       \
      (*env)->SetLongArrayRegion(env, inputArray, 0, 16,                     \
                                 (const jlong *)c_ctx.input);                \
    }                                                                        \
    {                                                                        \
      jfieldID fidInputIdx =                                                 \
          (*env)->GetFieldID(env, ctxClass, "input_idx", "J");               \
      (*env)->SetLongField(env, java_ctx, fidInputIdx,                       \
                           (jlong)c_ctx.input_idx);                          \
    }                                                                        \
    {                                                                        \
      jfieldID fidHashSize =                                                 \
          (*env)->GetFieldID(env, ctxClass, "hash_size", "J");               \
      (*env)->SetLongField(env, java_ctx, fidHashSize,                       \
                           (jlong)c_ctx.hash_size);                          \
    }                                                                        \
  } while (0)

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b_1init(
    JNIEnv *env,
    jobject obj,
    jobject blake2b_ctx,
    jlong hash_size) {
  (void)obj;

  CHECK_NULL_WITH_NAME(blake2b_ctx, "ctx", );

  if (hash_size < 1 || hash_size > 64) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(
        env, exc,
        "hash_size must be a length between (inclusive) 1 and 64 bytes");
    return;
  }

  crypto_blake2b_ctx ctx;
  crypto_blake2b_init(&ctx, hash_size);

  TO_BLAKE2_CTX_CLASS(ctx, blake2b_ctx);
}

#define FROM_BLAKE2_CTX_CLASS(java_ctx, c_ctx)                               \
  do {                                                                       \
    jclass ctxClass = (*env)->GetObjectClass(env, java_ctx);                 \
    {                                                                        \
      jfieldID fidHash = (*env)->GetFieldID(env, ctxClass, "hash", "[J");    \
      jlongArray hashArray =                                                 \
          (jlongArray)(*env)->GetObjectField(env, java_ctx, fidHash);        \
      jlong *hash = (*env)->GetLongArrayElements(env, hashArray, NULL);      \
      for (int i = 0; i < 8; i++) {                                          \
        c_ctx.hash[i] = (uint64_t)hash[i];                                   \
      }                                                                      \
      (*env)->ReleaseLongArrayElements(env, hashArray, hash, 0);             \
    }                                                                        \
    {                                                                        \
      jfieldID fidInputOffset =                                              \
          (*env)->GetFieldID(env, ctxClass, "input_offset", "[J");           \
      jlongArray inputOffsetArray =                                          \
          (jlongArray)(*env)->GetObjectField(env, java_ctx, fidInputOffset); \
      jlong *input_offset =                                                  \
          (*env)->GetLongArrayElements(env, inputOffsetArray, NULL);         \
      for (int i = 0; i < 2; i++) {                                          \
        c_ctx.input_offset[i] = (uint64_t)input_offset[i];                   \
      }                                                                      \
      (*env)->ReleaseLongArrayElements(env, inputOffsetArray, input_offset,  \
                                       0);                                   \
    }                                                                        \
    {                                                                        \
      jfieldID fidInput = (*env)->GetFieldID(env, ctxClass, "input", "[J");  \
      jlongArray inputArray =                                                \
          (jlongArray)(*env)->GetObjectField(env, java_ctx, fidInput);       \
      jlong *input = (*env)->GetLongArrayElements(env, inputArray, NULL);    \
      for (int i = 0; i < 16; i++) {                                         \
        c_ctx.input[i] = (uint64_t)input[i];                                 \
      }                                                                      \
      (*env)->ReleaseLongArrayElements(env, inputArray, input, 0);           \
    }                                                                        \
    {                                                                        \
      jfieldID fidInputIdx =                                                 \
          (*env)->GetFieldID(env, ctxClass, "input_idx", "J");               \
      ctx.input_idx =                                                        \
          (uint64_t)(*env)->GetLongField(env, java_ctx, fidInputIdx);        \
    }                                                                        \
    {                                                                        \
      jfieldID fidHashSize =                                                 \
          (*env)->GetFieldID(env, ctxClass, "hash_size", "J");               \
      ctx.hash_size =                                                        \
          (uint64_t)(*env)->GetLongField(env, java_ctx, fidHashSize);        \
    }                                                                        \
  } while (0)

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b_1update(
    JNIEnv *env,
    jobject obj,
    jobject blake2b_ctx,
    jbyteArray message) {
  (void)obj;

  CHECK_NULL_WITH_NAME(blake2b_ctx, "ctx", );

  crypto_blake2b_ctx ctx;

  jint msg_len = 0;
  jbyte *msg_ptr = NULL;

  if (message) {
    msg_len = (*env)->GetArrayLength(env, message);
    msg_ptr = (*env)->GetByteArrayElements(env, message, NULL);
  }

  FROM_BLAKE2_CTX_CLASS(blake2b_ctx, ctx);

  crypto_blake2b_update(&ctx, (const uint8_t *)msg_ptr, (size_t)msg_len);

  TO_BLAKE2_CTX_CLASS(ctx, blake2b_ctx);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1blake2b_1final(
    JNIEnv *env,
    jobject obj,
    jobject blake2b_ctx,
    jbyteArray hash) {
  (void)obj;

  CHECK_NULL_WITH_NAME(blake2b_ctx, "ctx", );
  CHECK_NULL(hash, );

  crypto_blake2b_ctx ctx;

  jint hash_len = (*env)->GetArrayLength(env, hash);

  FROM_BLAKE2_CTX_CLASS(blake2b_ctx, ctx);

  if ((size_t)hash_len != ctx.hash_size) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    char buf[64];
    snprintf(buf, sizeof(buf), "hash must be of length %lu bytes",
             ctx.hash_size);
    (*env)->ThrowNew(env, exc, buf);
    return;
  }

  jbyte *hash_ptr = (*env)->GetByteArrayElements(env, hash, NULL);

  crypto_blake2b_final(&ctx, (uint8_t *)hash_ptr);

  (*env)->ReleaseByteArrayElements(env, hash, hash_ptr, 0);

  TO_BLAKE2_CTX_CLASS(ctx, blake2b_ctx);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024Blake2b_1ctx_2(
    JNIEnv *env,
    jobject obj,
    jobject blake2b_ctx) {
  (void)obj;

  if (!blake2b_ctx) {
    return;
  }

  crypto_blake2b_ctx ctx;
  crypto_wipe((void *)&ctx, sizeof(ctx));

  TO_BLAKE2_CTX_CLASS(ctx, blake2b_ctx);
}

#define FROM_ARGON2_CONFIG_CLASS(java_cfg, c_cfg)                     \
  do {                                                                \
    jclass cfgClass = (*env)->GetObjectClass(env, java_cfg);          \
    {                                                                 \
      jfieldID fidAlgorithm =                                         \
          (*env)->GetFieldID(env, cfgClass, "algorithm", "I");        \
      c_cfg.algorithm =                                               \
          (uint32_t)(*env)->GetIntField(env, java_cfg, fidAlgorithm); \
    }                                                                 \
    {                                                                 \
      jfieldID fidNbBlocks =                                          \
          (*env)->GetFieldID(env, cfgClass, "nb_blocks", "I");        \
      c_cfg.nb_blocks =                                               \
          (uint32_t)(*env)->GetIntField(env, java_cfg, fidNbBlocks);  \
    }                                                                 \
    {                                                                 \
      jfieldID fidNbPasses =                                          \
          (*env)->GetFieldID(env, cfgClass, "nb_passes", "I");        \
      c_cfg.nb_passes =                                               \
          (uint32_t)(*env)->GetIntField(env, java_cfg, fidNbPasses);  \
    }                                                                 \
    {                                                                 \
      jfieldID fidNbLanes =                                           \
          (*env)->GetFieldID(env, cfgClass, "nb_lanes", "I");         \
      c_cfg.nb_lanes =                                                \
          (uint32_t)(*env)->GetIntField(env, java_cfg, fidNbLanes);   \
    }                                                                 \
  } while (0)

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1argon2(JNIEnv *env,
                                                        jobject obj,
                                                        jbyteArray hash,
                                                        jobject config,
                                                        jobject inputs,
                                                        jobject extras) {
  (void)obj;

  CHECK_NULL(hash, );
  CHECK_NULL(config, );
  CHECK_NULL(inputs, );

  crypto_argon2_config cfg;

  FROM_ARGON2_CONFIG_CLASS(config, cfg);

  if (cfg.algorithm != CRYPTO_ARGON2_D && cfg.algorithm != CRYPTO_ARGON2_I &&
      cfg.algorithm != CRYPTO_ARGON2_ID) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(
        env, exc,
        "algorithm must be one of Argon2_config.Algorithm_ARGON2_{D,I,ID}");
    return;
  }

  if (cfg.nb_blocks < (8 * cfg.nb_lanes)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "nb_blocks should be at least (8 * nb_lanes)");
    return;
  }

  jclass inputClass = (*env)->GetObjectClass(env, inputs);
  jfieldID fidPass = (*env)->GetFieldID(env, inputClass, "pass", "[B");
  jfieldID fidSalt = (*env)->GetFieldID(env, inputClass, "salt", "[B");
  jbyteArray pass = (jbyteArray)(*env)->GetObjectField(env, inputs, fidPass);
  jbyteArray salt = (jbyteArray)(*env)->GetObjectField(env, inputs, fidSalt);

  if (!salt) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    if (npeClass)
      (*env)->ThrowNew(env, npeClass, "salt cannot be null");
    return;
  }

  jint salt_len = (*env)->GetArrayLength(env, salt);

  if (salt_len < 8) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "salt needs to be at least 8 bytes");
    return;
  }

  jbyte *salt_ptr = (*env)->GetByteArrayElements(env, salt, NULL);

  jbyte *pass_ptr = NULL;
  jint pass_len = 0;

  if (pass) {
    pass_ptr = (*env)->GetByteArrayElements(env, pass, NULL);
    pass_len = (*env)->GetArrayLength(env, pass);
  }

  crypto_argon2_inputs inp = {
      .pass = (const uint8_t *)pass_ptr,
      .pass_size = (uint32_t)pass_len,
      .salt = (const uint8_t *)salt_ptr,
      .salt_size = (uint32_t)salt_len,
  };

  jclass extraClass = (*env)->GetObjectClass(env, extras);
  jfieldID fidKey = (*env)->GetFieldID(env, extraClass, "key", "[B");
  jfieldID fidAd = (*env)->GetFieldID(env, extraClass, "ad", "[B");
  jbyteArray key = (jbyteArray)(*env)->GetObjectField(env, extras, fidKey);
  jbyteArray ad = (jbyteArray)(*env)->GetObjectField(env, extras, fidAd);

  jbyte *key_ptr = NULL;
  jint key_len = 0;

  if (key) {
    key_ptr = (*env)->GetByteArrayElements(env, key, NULL);
    key_len = (*env)->GetArrayLength(env, key);
  }

  jbyte *ad_ptr = NULL;
  jint ad_len = 0;

  if (ad) {
    ad_ptr = (*env)->GetByteArrayElements(env, ad, NULL);
    ad_len = (*env)->GetArrayLength(env, ad);
  }

  crypto_argon2_extras ext = {
      .key = (const uint8_t *)key_ptr,
      .key_size = (uint32_t)key_len,
      .ad = (const uint8_t *)ad_ptr,
      .ad_size = (uint32_t)ad_len,
  };

  jbyte *hash_ptr = (*env)->GetByteArrayElements(env, hash, NULL);
  jint hash_len = (*env)->GetArrayLength(env, hash);

  jbyteArray work_area = (*env)->NewByteArray(env, cfg.nb_blocks * 1024);
  jbyte *work_area_ptr = (*env)->GetByteArrayElements(env, work_area, NULL);

  crypto_argon2((uint8_t *)hash_ptr, (size_t)hash_len, (void *)work_area_ptr,
                cfg, inp, ext);

  (*env)->ReleaseByteArrayElements(env, work_area, work_area_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, hash, hash_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, salt, salt_ptr, JNI_ABORT);
  if (pass) {
    (*env)->ReleaseByteArrayElements(env, pass, pass_ptr, JNI_ABORT);
  }
  if (key) {
    (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
  }
  if (ad) {
    (*env)->ReleaseByteArrayElements(env, ad, ad_ptr, JNI_ABORT);
  }
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024Argon2_1inputs_2(
    JNIEnv *env,
    jobject obj,
    jobject inputs) {
  (void)obj;

  if (!inputs) {
    return;
  }

  jclass inputClass = (*env)->GetObjectClass(env, inputs);
  jfieldID fidPass = (*env)->GetFieldID(env, inputClass, "pass", "[B");
  jfieldID fidSalt = (*env)->GetFieldID(env, inputClass, "salt", "[B");
  jbyteArray pass = (jbyteArray)(*env)->GetObjectField(env, inputs, fidPass);
  jbyteArray salt = (jbyteArray)(*env)->GetObjectField(env, inputs, fidSalt);

  if (salt) {
    jint salt_len = (*env)->GetArrayLength(env, salt);
    jbyte *salt_ptr = (*env)->GetByteArrayElements(env, salt, NULL);

    crypto_wipe((void *)salt_ptr, (size_t)salt_len);

    (*env)->ReleaseByteArrayElements(env, salt, salt_ptr, 0);
  }

  if (pass) {
    jint pass_len = (*env)->GetArrayLength(env, pass);
    jbyte *pass_ptr = (*env)->GetByteArrayElements(env, pass, NULL);

    crypto_wipe((void *)pass_ptr, (size_t)pass_len);

    (*env)->ReleaseByteArrayElements(env, pass, pass_ptr, 0);
  }
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024Argon2_1extras_2(
    JNIEnv *env,
    jobject obj,
    jobject extras) {
  (void)obj;

  if (!extras) {
    return;
  }

  jclass extraClass = (*env)->GetObjectClass(env, extras);
  jfieldID fidKey = (*env)->GetFieldID(env, extraClass, "key", "[B");
  jfieldID fidAd = (*env)->GetFieldID(env, extraClass, "ad", "[B");
  jbyteArray key = (jbyteArray)(*env)->GetObjectField(env, extras, fidKey);
  jbyteArray ad = (jbyteArray)(*env)->GetObjectField(env, extras, fidAd);

  if (key) {
    jint key_len = (*env)->GetArrayLength(env, key);
    jbyte *key_ptr = (*env)->GetByteArrayElements(env, key, NULL);

    crypto_wipe((void *)key_ptr, (size_t)key_len);

    (*env)->ReleaseByteArrayElements(env, key, key_ptr, 0);
  }

  if (ad) {
    jint ad_len = (*env)->GetArrayLength(env, ad);
    jbyte *ad_ptr = (*env)->GetByteArrayElements(env, ad, NULL);

    crypto_wipe((void *)ad_ptr, (size_t)ad_len);

    (*env)->ReleaseByteArrayElements(env, ad, ad_ptr, 0);
  }
}

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

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1poly1305(JNIEnv *env,
                                                          jobject obj,
                                                          jobject mac,
                                                          jobject message,
                                                          jbyteArray key) {
  (void)obj;

  CHECK_NULL(mac, );
  CHECK_NULL(key, );

  ENSURE_ARRAY_LENGTH(key, 32, );

  INIT_BYTE_BUFFER_CLASS(bbClass);

  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, mac, );
  if (message) {
    ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, message, );
  }

  jbyte *mac_ptr = (*env)->GetDirectBufferAddress(env, mac);
  jbyte *message_ptr =
      message ? (*env)->GetDirectBufferAddress(env, message) : NULL;
  jint message_len =
      message ? (*env)->CallIntMethod(env, message, bbClass_remaining) : 0;
  jbyte *key_ptr = (*env)->GetByteArrayElements(env, key, NULL);

  crypto_poly1305((uint8_t *)mac_ptr, (const uint8_t *)message_ptr,
                  (size_t)message_len, (const uint8_t *)key_ptr);

  (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
}

#define TO_POLY1305_CTX_CLASS(c_ctx, java_ctx)                                 \
  do {                                                                         \
    jclass ctxClass = (*env)->GetObjectClass(env, java_ctx);                   \
    {                                                                          \
      jfieldID fidC = (*env)->GetFieldID(env, ctxClass, "c", "[B");            \
      jbyteArray cArray =                                                      \
          (jbyteArray)(*env)->GetObjectField(env, java_ctx, fidC);             \
      (*env)->SetByteArrayRegion(env, cArray, 0, 16, (const jbyte *)c_ctx.c);  \
    }                                                                          \
    {                                                                          \
      jfieldID fidCIdx = (*env)->GetFieldID(env, ctxClass, "c_idx", "J");      \
      (*env)->SetLongField(env, java_ctx, fidCIdx, (jlong)c_ctx.c_idx);        \
    }                                                                          \
    {                                                                          \
      jfieldID fidR = (*env)->GetFieldID(env, ctxClass, "r", "[I");            \
      jintArray rArray =                                                       \
          (jintArray)(*env)->GetObjectField(env, java_ctx, fidR);              \
      (*env)->SetIntArrayRegion(env, rArray, 0, 4, (const jint *)c_ctx.r);     \
    }                                                                          \
    {                                                                          \
      jfieldID fidPad = (*env)->GetFieldID(env, ctxClass, "pad", "[I");        \
      jintArray padArray =                                                     \
          (jintArray)(*env)->GetObjectField(env, java_ctx, fidPad);            \
      (*env)->SetIntArrayRegion(env, padArray, 0, 4, (const jint *)c_ctx.pad); \
    }                                                                          \
    {                                                                          \
      jfieldID fidH = (*env)->GetFieldID(env, ctxClass, "h", "[I");            \
      jintArray hArray =                                                       \
          (jintArray)(*env)->GetObjectField(env, java_ctx, fidH);              \
      (*env)->SetIntArrayRegion(env, hArray, 0, 5, (const jint *)c_ctx.h);     \
    }                                                                          \
  } while (0)

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1poly1305_1init(
    JNIEnv *env,
    jobject obj,
    jobject poly1305_ctx,
    jbyteArray key) {
  (void)obj;

  CHECK_NULL_WITH_NAME(poly1305_ctx, "ctx", );
  CHECK_NULL(key, );

  ENSURE_ARRAY_LENGTH(key, 32, );

  jbyte *key_ptr = (*env)->GetByteArrayElements(env, key, NULL);

  crypto_poly1305_ctx ctx;
  crypto_poly1305_init(&ctx, (const uint8_t *)key_ptr);

  TO_POLY1305_CTX_CLASS(ctx, poly1305_ctx);

  (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
}

#define FROM_POLY1305_CTX_CLASS(java_ctx, c_ctx)                          \
  do {                                                                    \
    jclass ctxClass = (*env)->GetObjectClass(env, java_ctx);              \
    {                                                                     \
      jfieldID fidC = (*env)->GetFieldID(env, ctxClass, "c", "[B");       \
      jbyteArray cArray =                                                 \
          (jbyteArray)(*env)->GetObjectField(env, java_ctx, fidC);        \
      jbyte *c_ptr = (*env)->GetByteArrayElements(env, cArray, NULL);     \
      for (int i = 0; i < 16; i++) {                                      \
        c_ctx.c[i] = (uint8_t)c_ptr[i];                                   \
      }                                                                   \
      (*env)->ReleaseByteArrayElements(env, cArray, c_ptr, JNI_ABORT);    \
    }                                                                     \
    {                                                                     \
      jfieldID fidCIdx = (*env)->GetFieldID(env, ctxClass, "c_idx", "J"); \
      ctx.c_idx = (size_t)(*env)->GetLongField(env, java_ctx, fidCIdx);   \
    }                                                                     \
    {                                                                     \
      jfieldID fidR = (*env)->GetFieldID(env, ctxClass, "r", "[I");       \
      jbyteArray rArray =                                                 \
          (jintArray)(*env)->GetObjectField(env, java_ctx, fidR);         \
      jint *r_ptr = (*env)->GetIntArrayElements(env, rArray, NULL);       \
      for (int i = 0; i < 4; i++) {                                       \
        c_ctx.r[i] = (uint32_t)r_ptr[i];                                  \
      }                                                                   \
      (*env)->ReleaseIntArrayElements(env, rArray, r_ptr, JNI_ABORT);     \
    }                                                                     \
    {                                                                     \
      jfieldID fidPad = (*env)->GetFieldID(env, ctxClass, "pad", "[I");   \
      jbyteArray padArray =                                               \
          (jintArray)(*env)->GetObjectField(env, java_ctx, fidPad);       \
      jint *pad_ptr = (*env)->GetIntArrayElements(env, padArray, NULL);   \
      for (int i = 0; i < 4; i++) {                                       \
        c_ctx.pad[i] = (uint32_t)pad_ptr[i];                              \
      }                                                                   \
      (*env)->ReleaseIntArrayElements(env, padArray, pad_ptr, JNI_ABORT); \
    }                                                                     \
    {                                                                     \
      jfieldID fidH = (*env)->GetFieldID(env, ctxClass, "h", "[I");       \
      jbyteArray hArray =                                                 \
          (jintArray)(*env)->GetObjectField(env, java_ctx, fidH);         \
      jint *h_ptr = (*env)->GetIntArrayElements(env, hArray, NULL);       \
      for (int i = 0; i < 5; i++) {                                       \
        c_ctx.h[i] = (uint32_t)h_ptr[i];                                  \
      }                                                                   \
      (*env)->ReleaseIntArrayElements(env, hArray, h_ptr, JNI_ABORT);     \
    }                                                                     \
  } while (0)

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1poly1305_1update(
    JNIEnv *env,
    jobject obj,
    jobject poly1305_ctx,
    jbyteArray message) {
  (void)obj;

  CHECK_NULL_WITH_NAME(poly1305_ctx, "ctx", );

  jbyte *message_ptr = NULL;
  jint message_len = 0;

  if (message) {
    message_ptr = (*env)->GetByteArrayElements(env, message, NULL);
    message_len = (*env)->GetArrayLength(env, message);
  }

  crypto_poly1305_ctx ctx;
  FROM_POLY1305_CTX_CLASS(poly1305_ctx, ctx);

  crypto_poly1305_update(&ctx, (const uint8_t *)message_ptr,
                         (size_t)message_len);

  TO_POLY1305_CTX_CLASS(ctx, poly1305_ctx);

  crypto_wipe((void *)&ctx, sizeof(ctx));

  if (message) {
    (*env)->ReleaseByteArrayElements(env, message, message_ptr, JNI_ABORT);
  }
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1poly1305_1final(
    JNIEnv *env,
    jobject obj,
    jobject poly1305_ctx,
    jbyteArray mac) {
  (void)obj;

  CHECK_NULL_WITH_NAME(poly1305_ctx, "ctx", );
  CHECK_NULL(mac, );

  ENSURE_ARRAY_LENGTH(mac, 16, );

  crypto_poly1305_ctx ctx;
  FROM_POLY1305_CTX_CLASS(poly1305_ctx, ctx);

  jbyte *mac_ptr = (*env)->GetByteArrayElements(env, mac, NULL);

  crypto_poly1305_final(&ctx, (uint8_t *)mac_ptr);

  TO_POLY1305_CTX_CLASS(ctx, poly1305_ctx);

  crypto_wipe((void *)&ctx, sizeof(ctx));

  (*env)->ReleaseByteArrayElements(env, mac, mac_ptr, 0);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024Poly1305_1ctx_2(
    JNIEnv *env,
    jobject obj,
    jobject poly1305_ctx) {
  (void)obj;

  if (!poly1305_ctx) {
    return;
  }

  crypto_poly1305_ctx ctx;
  crypto_wipe((void *)&ctx, sizeof(ctx));

  TO_POLY1305_CTX_CLASS(ctx, poly1305_ctx);
}

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
