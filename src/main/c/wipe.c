#include "jni_util.h"

/*
 * The JVM may hand C a copy of the array. The copy is wiped, then written back
 * and freed, so the array ends up zeroed and no unwiped copy is left behind by
 * this call. Copies the garbage collector made earlier are out of reach, which
 * is why direct buffers are preferred for secrets.
 */
JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe___3B(JNIEnv *env,
                                                           jclass cls,
                                                           jbyteArray j_secret) {
  (void)cls;

  if (j_secret == NULL) return;

  jsize len = (*env)->GetArrayLength(env, j_secret);
  jbyte *secret = (*env)->GetByteArrayElements(env, j_secret, NULL);
  if (secret == NULL) return;

  crypto_wipe(secret, (size_t)len);
  (*env)->ReleaseByteArrayElements(env, j_secret, secret, 0);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Ljava_nio_ByteBuffer_2(JNIEnv *env,
                                                                              jclass cls,
                                                                              jobject j_secret) {
  (void)cls;

  if (j_secret == NULL) return;

  mc_buf secret;
  if (!mc_output(env, j_secret, "secret", &secret)) return;

  crypto_wipe(secret.ptr, secret.len);
}
