#include "jni_util.h"
#include "net_lastninja_monocypher_Hazmat.h"

/*
 * Dangerous low-level EdDSA building blocks, bound to the Hazmat class so
 * that using them takes a deliberate import.
 *
 * No overlap checks: the manual and upstream tests allow overlapping buffers.
 */

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Hazmat_crypto_1eddsa_1trim_1scalar(JNIEnv *env,
                                                                 jclass cls,
                                                                 jobject j_out,
                                                                 jobject j_in) {
  (void)cls;

  mc_buf out, in;
  if (!mc_output_len(env, j_out, "out", 32, &out)) return;
  if (!mc_input_len(env, j_in, "in", 32, &in)) return;

  crypto_eddsa_trim_scalar(out.ptr, in.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Hazmat_crypto_1eddsa_1reduce(JNIEnv *env,
                                                           jclass cls,
                                                           jobject j_reduced,
                                                           jobject j_expanded) {
  (void)cls;

  mc_buf reduced, expanded;
  if (!mc_output_len(env, j_reduced, "reduced", 32, &reduced)) return;
  if (!mc_input_len(env, j_expanded, "expanded", 64, &expanded)) return;

  crypto_eddsa_reduce(reduced.ptr, expanded.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Hazmat_crypto_1eddsa_1mul_1add(JNIEnv *env,
                                                             jclass cls,
                                                             jobject j_r,
                                                             jobject j_a,
                                                             jobject j_b,
                                                             jobject j_c) {
  (void)cls;

  mc_buf r, a, b, c;
  if (!mc_output_len(env, j_r, "r", 32, &r)) return;
  if (!mc_input_len(env, j_a, "a", 32, &a)) return;
  if (!mc_input_len(env, j_b, "b", 32, &b)) return;
  if (!mc_input_len(env, j_c, "c", 32, &c)) return;

  crypto_eddsa_mul_add(r.ptr, a.ptr, b.ptr, c.ptr);
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Hazmat_crypto_1eddsa_1scalarbase(JNIEnv *env,
                                                               jclass cls,
                                                               jobject j_point,
                                                               jobject j_scalar) {
  (void)cls;

  mc_buf point, scalar;
  if (!mc_output_len(env, j_point, "point", 32, &point)) return;
  if (!mc_input_len(env, j_scalar, "scalar", 32, &scalar)) return;

  crypto_eddsa_scalarbase(point.ptr, scalar.ptr);
}

JNIEXPORT jint JNICALL
Java_net_lastninja_monocypher_Hazmat_crypto_1eddsa_1check_1equation(JNIEnv *env,
                                                                    jclass cls,
                                                                    jobject j_signature,
                                                                    jobject j_public_key,
                                                                    jobject j_h_ram) {
  (void)cls;

  mc_buf signature, public_key, h_ram;
  if (!mc_input_len(env, j_signature, "signature", 64, &signature)) return -1;
  if (!mc_input_len(env, j_public_key, "public_key", 32, &public_key)) return -1;
  if (!mc_input_len(env, j_h_ram, "h_ram", 32, &h_ram)) return -1;

  return crypto_eddsa_check_equation(signature.ptr, public_key.ptr, h_ram.ptr);
}
