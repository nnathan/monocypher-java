#include "jni_util.h"

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
