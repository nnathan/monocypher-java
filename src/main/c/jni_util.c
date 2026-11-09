#include <stdint.h>
#include <stdio.h>
#include "jni_util.h"

static jclass illegal_argument;
static jclass null_pointer;
static jmethodID bb_is_direct;
static jmethodID bb_is_read_only;
static jmethodID bb_position;
static jmethodID bb_remaining;

static jclass global_class(JNIEnv *env, const char *name) {
  jclass local = (*env)->FindClass(env, name);
  if (local == NULL) return NULL;
  return (*env)->NewGlobalRef(env, local);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)reserved;

  JNIEnv *env;
  if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

  illegal_argument = global_class(env, "java/lang/IllegalArgumentException");
  null_pointer = global_class(env, "java/lang/NullPointerException");
  jclass bb = (*env)->FindClass(env, "java/nio/ByteBuffer");
  if (illegal_argument == NULL || null_pointer == NULL || bb == NULL) return JNI_ERR;

  bb_is_direct = (*env)->GetMethodID(env, bb, "isDirect", "()Z");
  bb_is_read_only = (*env)->GetMethodID(env, bb, "isReadOnly", "()Z");
  bb_position = (*env)->GetMethodID(env, bb, "position", "()I");
  bb_remaining = (*env)->GetMethodID(env, bb, "remaining", "()I");
  if (bb_is_direct == NULL || bb_is_read_only == NULL || bb_position == NULL ||
      bb_remaining == NULL) {
    return JNI_ERR;
  }

  return JNI_VERSION_1_6;
}

static bool throw_iae(JNIEnv *env, const char *name, const char *problem) {
  char msg[128];
  snprintf(msg, sizeof(msg), "%s %s", name, problem);
  (*env)->ThrowNew(env, illegal_argument, msg);
  return false;
}

bool mc_input(JNIEnv *env, jobject bb, const char *name, mc_buf *out) {
  if (bb == NULL) {
    char msg[128];
    snprintf(msg, sizeof(msg), "%s cannot be null", name);
    (*env)->ThrowNew(env, null_pointer, msg);
    return false;
  }
  if (!(*env)->CallBooleanMethod(env, bb, bb_is_direct)) {
    return throw_iae(env, name, "must be a direct ByteBuffer");
  }

  uint8_t *base = (*env)->GetDirectBufferAddress(env, bb);
  jint position = (*env)->CallIntMethod(env, bb, bb_position);
  jint remaining = (*env)->CallIntMethod(env, bb, bb_remaining);
  if (base == NULL && remaining > 0) {
    return throw_iae(env, name, "has no accessible address");
  }

  out->ptr = base == NULL ? NULL : base + position;
  out->len = (size_t)remaining;
  return true;
}

bool mc_input_opt(JNIEnv *env, jobject bb, const char *name, mc_buf *out) {
  if (bb == NULL) {
    out->ptr = NULL;
    out->len = 0;
    return true;
  }
  return mc_input(env, bb, name, out);
}

bool mc_output(JNIEnv *env, jobject bb, const char *name, mc_buf *out) {
  if (!mc_input(env, bb, name, out)) return false;
  if ((*env)->CallBooleanMethod(env, bb, bb_is_read_only)) {
    return throw_iae(env, name, "must not be read-only");
  }
  return true;
}

bool mc_require_len(JNIEnv *env, const mc_buf *b, const char *name, size_t len) {
  if (b->len == len) return true;

  char problem[64];
  snprintf(problem, sizeof(problem), "must have exactly %lu bytes remaining",
           (unsigned long)len);
  return throw_iae(env, name, problem);
}

bool mc_require_same_len(JNIEnv *env, const mc_buf *a, const char *a_name,
                         const mc_buf *b, const char *b_name) {
  if (a->len == b->len) return true;

  char problem[64];
  snprintf(problem, sizeof(problem), "must have the same length as %s", b_name);
  return throw_iae(env, a_name, problem);
}

static bool overlaps(const mc_buf *a, const mc_buf *b) {
  if (a->len == 0 || b->len == 0) return false;

  uintptr_t a_start = (uintptr_t)a->ptr;
  uintptr_t b_start = (uintptr_t)b->ptr;
  return a_start < b_start + b->len && b_start < a_start + a->len;
}

bool mc_check_overlap(JNIEnv *env, const mc_buf *a, const char *a_name,
                      const mc_buf *b, const char *b_name) {
  if (!overlaps(a, b)) return true;
  if (a->ptr == b->ptr && a->len == b->len) return true;

  char problem[64];
  snprintf(problem, sizeof(problem), "must be the same memory as %s or not overlap it", b_name);
  return throw_iae(env, a_name, problem);
}

bool mc_check_disjoint(JNIEnv *env, const mc_buf *a, const char *a_name,
                       const mc_buf *b, const char *b_name) {
  if (!overlaps(a, b)) return true;

  char problem[64];
  snprintf(problem, sizeof(problem), "must not overlap %s", b_name);
  return throw_iae(env, a_name, problem);
}
