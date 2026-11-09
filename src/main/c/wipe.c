#include "jni_util.h"

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
