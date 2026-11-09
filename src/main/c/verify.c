#include "jni_util.h"

static bool verify_args(JNIEnv *env, jobject j_a, jobject j_b, size_t len, mc_buf *a, mc_buf *b) {
  return mc_input(env, j_a, "a", a) && mc_input(env, j_b, "b", b) &&
         mc_require_len(env, a, "a", len) && mc_require_len(env, b, "b", len);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1verify16(JNIEnv *env,
                                                          jclass cls,
                                                          jobject j_a,
                                                          jobject j_b) {
  (void)cls;

  mc_buf a, b;
  if (!verify_args(env, j_a, j_b, 16, &a, &b)) return -1;

  return crypto_verify16(a.ptr, b.ptr);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1verify32(JNIEnv *env,
                                                          jclass cls,
                                                          jobject j_a,
                                                          jobject j_b) {
  (void)cls;

  mc_buf a, b;
  if (!verify_args(env, j_a, j_b, 32, &a, &b)) return -1;

  return crypto_verify32(a.ptr, b.ptr);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1verify64(JNIEnv *env,
                                                          jclass cls,
                                                          jobject j_a,
                                                          jobject j_b) {
  (void)cls;

  mc_buf a, b;
  if (!verify_args(env, j_a, j_b, 64, &a, &b)) return -1;

  return crypto_verify64(a.ptr, b.ptr);
}
