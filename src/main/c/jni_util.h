#ifndef MONOCYPHER_JNI_UTIL_H
#define MONOCYPHER_JNI_UTIL_H

#include <jni.h>
#include <stdbool.h>
#include <stdlib.h>
#include "monocypher.h"
#include "net_lastninja_monocypher_Monocypher.h"

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
