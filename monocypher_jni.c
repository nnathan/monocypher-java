#include "monocypher.h"
#include "net_lastninja_monocypher_Monocypher.h"
#include <jni.h>
#include <stdbool.h>

#define CHECK_NULL_WITH_NAME(var, name_str, ret_val) \
  do { \
    if (!(var)) { \
        jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException"); \
        if (npeClass) (*env)->ThrowNew(env, npeClass, name_str " cannot be null"); \
        return ret_val; \
    } \
  } while (0)

#define CHECK_NULL(var, ret_val) CHECK_NULL_WITH_NAME(var, #var, ret_val)

#define INIT_BYTE_BUFFER_CLASS(var) \
  jclass var = (*env)->FindClass(env, "java/nio/ByteBuffer"); \
  jmethodID var##_isDirect = (*env)->GetMethodID(env, var, "isDirect", "()Z"); \
  jmethodID var##_remaining = (*env)->GetMethodID(env, bbClass, "remaining", "()I");


#define ENSURE_BYTE_BUFFER_IS_DIRECT(class_var, bb_var, ret_val) \
  do { \
    if (!(*env)->CallBooleanMethod(env, bb_var, class_var##_isDirect)) { \
      jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException"); \
      (*env)->ThrowNew(env, exc, #bb_var " must be a direct ByteBuffer"); \
      return ret_val; \
    } \
  } while (0)

#define ENSURE_BYTE_BUFFER_LENGTH(class_var, bb_var, len, ret_val) \
  do { \
    if ((*env)->CallIntMethod(env, bb_var, class_var##_remaining) != len) { \
      jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException"); \
      (*env)->ThrowNew(env, exc, #bb_var " must be a buffer of length " #len " bytes"); \
      return ret_val; \
    } \
  } while (0)

#define ENSURE_ARRAY_LENGTH(array_var, len, ret_val) \
  do { \
    if ((*env)->GetArrayLength(env, array_var) != len) { \
      jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException"); \
      (*env)->ThrowNew(env, exc, #array_var " must be an array of length " #len " bytes"); \
      return ret_val; \
    } \
  } while (0)

JNIEXPORT jint JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1verify16(
  JNIEnv *env,
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
                                   JNI_ABORT); // no write-back needed
  (*env)->ReleaseByteArrayElements(env, j_b, b, JNI_ABORT);

  return result;
}

JNIEXPORT jint JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1verify32(
  JNIEnv *env,
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
                                   JNI_ABORT); // no write-back needed
  (*env)->ReleaseByteArrayElements(env, j_b, b, JNI_ABORT);

  return result;
}

JNIEXPORT jint JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1verify64(
  JNIEnv *env,
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
                                   JNI_ABORT); // no write-back needed
  (*env)->ReleaseByteArrayElements(env, j_b, b, JNI_ABORT);

  return result;
}

JNIEXPORT void JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1wipe___3B(
  JNIEnv *env,
  jobject obj,
  jbyteArray buf) {

  (void)obj;

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
  if (ad) { ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, ad, ); };
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, plain_text, );

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, mac, 16, );
  ENSURE_BYTE_BUFFER_LENGTH(bbClass, nonce, 24, );

  ENSURE_ARRAY_LENGTH(key, 32, );

  uint8_t *ct_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, cipher_text);
  uint8_t *mac_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, mac);
  jbyte *jkey_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  const uint8_t *key_ptr = (const uint8_t *)jkey_ptr;
  const uint8_t *nonce_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, nonce);
  const uint8_t *ad_ptr = ad ? (uint8_t*)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len = (size_t)(ad ? (*env)->CallIntMethod(env, ad, bbClass_remaining) : 0);
  uint8_t *pt_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, plain_text);
  const size_t pt_len = (size_t)(*env)->CallIntMethod(env, plain_text, bbClass_remaining);

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
  if (ad) { ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, ad, -1); };
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, cipher_text, -1);

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, mac, 16, -1);
  ENSURE_BYTE_BUFFER_LENGTH(bbClass, nonce, 24, -1);

  ENSURE_ARRAY_LENGTH(key, 32, -1);

  uint8_t *pt_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, plain_text);
  uint8_t *mac_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, mac);
  jbyte *jkey_ptr = (*env)->GetByteArrayElements(env, key, NULL);
  const uint8_t *key_ptr = (const uint8_t *)jkey_ptr;
  const uint8_t *nonce_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, nonce);
  const uint8_t *ad_ptr = ad ? (uint8_t*)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len = (size_t)(ad ? (*env)->CallIntMethod(env, ad, bbClass_remaining) : 0);
  uint8_t *ct_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, cipher_text);
  const size_t ct_len = (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

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

JNIEXPORT void JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1init_1x(
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
  jbyteArray keyArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  crypto_aead_init_x(&ctx, (const uint8_t *)key_ptr, (const uint8_t *)nonce_ptr);

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong) ctx.counter);
  (*env)->SetByteArrayRegion(env, keyArray, 0, 32, (const jbyte *)ctx.key);
  (*env)->SetByteArrayRegion(env, nonceArray, 0, 8, (const jbyte *)ctx.nonce);

  crypto_wipe(&ctx, sizeof(ctx));

  (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, nonce, nonce_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1init_1djb(
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
  jbyteArray keyArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  crypto_aead_init_djb(&ctx, (const uint8_t *)key_ptr, (const uint8_t *)nonce_ptr);

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong) ctx.counter);
  (*env)->SetByteArrayRegion(env, keyArray, 0, 32, (const jbyte *)ctx.key);
  (*env)->SetByteArrayRegion(env, nonceArray, 0, 8, (const jbyte *)ctx.nonce);

  crypto_wipe(&ctx, sizeof(ctx));

  (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, nonce, nonce_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1init_1ietf(
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
  jbyteArray keyArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  crypto_aead_init_ietf(&ctx, (const uint8_t *)key_ptr, (const uint8_t *)nonce_ptr);

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong) ctx.counter);
  (*env)->SetByteArrayRegion(env, keyArray, 0, 32, (const jbyte *)ctx.key);
  (*env)->SetByteArrayRegion(env, nonceArray, 0, 8, (const jbyte *)ctx.nonce);

  crypto_wipe(&ctx, sizeof(ctx));

  (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, nonce, nonce_ptr, JNI_ABORT);
}

JNIEXPORT void JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024AEAD_1ctx_2(
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
  jbyteArray keyArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  jbyte key[32] = {0};
  jbyte nonce[8] = {0};

  (*env)->SetLongField(env, aead_ctx, fidCounter, (jlong)0);
  (*env)->SetByteArrayRegion(env, keyArray, 0, 32, (const jbyte *)key);
  (*env)->SetByteArrayRegion(env, nonceArray, 0, 8, (const jbyte *)nonce);
}

JNIEXPORT void JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1write(
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
  if (ad) { ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, ad, ); };
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, plain_text, );

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, mac, 16, );

  jclass ctxClass = (*env)->GetObjectClass(env, aead_ctx);
  jfieldID fidCounter = (*env)->GetFieldID(env, ctxClass, "counter", "J");

  jfieldID fidKey = (*env)->GetFieldID(env, ctxClass, "key", "[B");
  jbyteArray keyArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  ctx.counter = (uint64_t)(*env)->GetLongField(env, aead_ctx, fidCounter);

  jbyte *aead_ctx_key_ptr = (*env)->GetByteArrayElements(env, keyArray, NULL);
  for (int i = 0; i < 32; i++) {
    ctx.key[i] = (uint8_t)aead_ctx_key_ptr[i];
  }

  jbyte *aead_ctx_nonce_ptr = (*env)->GetByteArrayElements(env, nonceArray, NULL);
  for (int i = 0; i < 8; i++) {
    ctx.nonce[i] = (uint8_t)aead_ctx_nonce_ptr[i];
  }

  uint8_t *ct_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, cipher_text);
  uint8_t *mac_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, mac);
  const uint8_t *ad_ptr = ad ? (uint8_t*)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len = (size_t)(ad ? (*env)->CallIntMethod(env, ad, bbClass_remaining) : 0);
  uint8_t *pt_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, plain_text);
  const size_t pt_len = (size_t)(*env)->CallIntMethod(env, plain_text, bbClass_remaining);

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

JNIEXPORT jint JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1aead_1read(
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
  if (ad) { ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, ad, -1); };
  ENSURE_BYTE_BUFFER_IS_DIRECT(bbClass, cipher_text, -1);

  ENSURE_BYTE_BUFFER_LENGTH(bbClass, mac, 16, -1);

  jclass ctxClass = (*env)->GetObjectClass(env, aead_ctx);
  jfieldID fidCounter = (*env)->GetFieldID(env, ctxClass, "counter", "J");

  jfieldID fidKey = (*env)->GetFieldID(env, ctxClass, "key", "[B");
  jbyteArray keyArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidKey);

  jfieldID fidNonce = (*env)->GetFieldID(env, ctxClass, "nonce", "[B");
  jbyteArray nonceArray = (jbyteArray)(*env)->GetObjectField(env, aead_ctx, fidNonce);

  crypto_aead_ctx ctx;

  ctx.counter = (uint64_t)(*env)->GetLongField(env, aead_ctx, fidCounter);

  jbyte *aead_ctx_key_ptr = (*env)->GetByteArrayElements(env, keyArray, NULL);
  for (int i = 0; i < 32; i++) {
    ctx.key[i] = (uint8_t)aead_ctx_key_ptr[i];
  }

  jbyte *aead_ctx_nonce_ptr = (*env)->GetByteArrayElements(env, nonceArray, NULL);
  for (int i = 0; i < 8; i++) {
    ctx.nonce[i] = (uint8_t)aead_ctx_nonce_ptr[i];
  }

  uint8_t *pt_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, plain_text);
  uint8_t *mac_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, mac);
  const uint8_t *ad_ptr = ad ? (uint8_t*)(*env)->GetDirectBufferAddress(env, ad) : NULL;
  size_t ad_len = (size_t)(ad ? (*env)->CallIntMethod(env, ad, bbClass_remaining) : 0);
  uint8_t *ct_ptr = (uint8_t*)(*env)->GetDirectBufferAddress(env, cipher_text);
  const size_t ct_len = (size_t)(*env)->CallIntMethod(env, cipher_text, bbClass_remaining);

  int result = crypto_aead_read(&ctx, pt_ptr, mac_ptr, ad_ptr, ad_len, ct_ptr, ct_len);

  if (result == -1) {
    (*env)->ReleaseByteArrayElements(env, keyArray, aead_ctx_key_ptr, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, nonceArray, aead_ctx_nonce_ptr, JNI_ABORT);
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
