#include "jni_util.h"

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe___3B(JNIEnv *env,
                                                           jclass cls,
                                                           jbyteArray buf) {
  (void)cls;

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
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Ljava_nio_ByteBuffer_2(JNIEnv *env,
                                                                              jclass cls,
                                                                              jobject j_secret) {
  (void)cls;

  if (j_secret == NULL) {
    return;
  }

  mc_buf secret;
  if (!mc_output(env, j_secret, "secret", &secret)) return;

  crypto_wipe(secret.ptr, secret.len);
}
