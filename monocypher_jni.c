#include "monocypher.h"
#include "net_lastninja_monocypher_Monocypher.h"
#include <jni.h>

JNIEXPORT jint JNICALL Java_net_lastninja_monocypher_Monocypher_crypto_1verify16(
    JNIEnv *env, jobject obj, jbyteArray j_a, jbyteArray j_b) {

  if ((*env)->GetArrayLength(env, j_a) != 16 ||
      (*env)->GetArrayLength(env, j_b) != 16) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    if (exc != NULL) {
      (*env)->ThrowNew(env, exc, "Both arrays must be 16 bytes long");
    } else {
      // should be unreachable
      return -1;
    }
    return 0;
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
