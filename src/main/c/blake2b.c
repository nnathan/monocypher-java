#include "jni_util.h"

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
