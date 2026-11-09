#ifndef MONOCYPHER_JNI_UTIL_H
#define MONOCYPHER_JNI_UTIL_H

#include <jni.h>
#include <stdbool.h>
#include <stdlib.h>
#include "monocypher.h"
#include "net_lastninja_monocypher_Monocypher.h"

/*
 * Argument validation for JNI functions.
 *
 * Every function below returns true on success. On failure it leaves a Java
 * exception pending and returns false, and the caller must return to Java
 * immediately, because a pending exception does not stop C from running:
 *
 *   mc_buf key;
 *   if (!mc_input(env, j_key, "key", &key)) return;
 *
 * `name` is the argument name used in exception messages.
 */

/* A view of a direct ByteBuffer's bytes, from its position to its limit. */
typedef struct {
  uint8_t *ptr;
  size_t len;
} mc_buf;

/* Throws NullPointerException if obj is null. For non-buffer arguments. */
bool mc_require_object(JNIEnv *env, jobject obj, const char *name);

/*
 * Gets a required input from a direct ByteBuffer. Does not change the buffer's
 * position.
 *
 * Throws NullPointerException if bb is null, and IllegalArgumentException if
 * it is not direct.
 */
bool mc_input(JNIEnv *env, jobject bb, const char *name, mc_buf *out);

/*
 * Like mc_input, for an optional input: a null bb succeeds and gives
 * {NULL, 0}, which is how Monocypher expresses "no data".
 */
bool mc_input_opt(JNIEnv *env, jobject bb, const char *name, mc_buf *out);

/*
 * Like mc_input, for a buffer that will be written to. Also throws
 * IllegalArgumentException if bb is read-only, as C could otherwise write
 * through a read-only view.
 */
bool mc_output(JNIEnv *env, jobject bb, const char *name, mc_buf *out);

/* mc_input followed by mc_require_len, for fixed-size arguments. */
bool mc_input_len(JNIEnv *env, jobject bb, const char *name, size_t len, mc_buf *out);

/* mc_output followed by mc_require_len, for fixed-size arguments. */
bool mc_output_len(JNIEnv *env, jobject bb, const char *name, size_t len, mc_buf *out);

/* Throws IllegalArgumentException with "<name> <problem>". Always returns false. */
bool mc_throw_iae(JNIEnv *env, const char *name, const char *problem);

/* Throws IllegalArgumentException unless b has exactly len bytes. */
bool mc_require_len(JNIEnv *env, const mc_buf *b, const char *name, size_t len);

/* Throws IllegalArgumentException unless a and b have the same length. */
bool mc_require_same_len(JNIEnv *env, const mc_buf *a, const char *a_name,
                         const mc_buf *b, const char *b_name);

/*
 * For arguments that may be used in place, such as cipher_text and plain_text.
 * Allows exactly the same memory (same start and length) or no overlap, and
 * throws IllegalArgumentException for a partial overlap.
 */
bool mc_check_overlap(JNIEnv *env, const mc_buf *a, const char *a_name,
                      const mc_buf *b, const char *b_name);

/*
 * For arguments that must never share memory, such as mac and cipher_text.
 * Throws IllegalArgumentException for any overlap, including exact aliases.
 */
bool mc_check_disjoint(JNIEnv *env, const mc_buf *a, const char *a_name,
                       const mc_buf *b, const char *b_name);

/*
 * Contexts are Java Ctx objects holding one off-heap block, which C uses in
 * place so that no copy of the secret state ever exists elsewhere. The block
 * is a struct aligned to 8 bytes, followed by one byte recording whether it
 * has been initialised.
 */

/* The number of bytes Java must allocate for a context struct of this size. */
jint mc_ctx_alloc_size(size_t size);

/*
 * Gets the struct inside a Java Ctx, whatever its state. For init and wipe.
 * Throws NullPointerException if j_ctx is null.
 */
bool mc_ctx_get(JNIEnv *env, jobject j_ctx, size_t size, void **ctx);

/*
 * Like mc_ctx_get, and also throws IllegalStateException unless the context
 * has been initialised and not wiped since.
 */
bool mc_ctx_ready(JNIEnv *env, jobject j_ctx, size_t size, void **ctx);

/* Records whether the context is usable. */
void mc_ctx_mark(void *ctx, size_t size, bool ready);

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

#endif
