#include "jni_util.h"

#define FROM_ARGON2_CONFIG_CLASS(java_cfg, c_cfg)                     \
  do {                                                                \
    jclass cfgClass = (*env)->GetObjectClass(env, java_cfg);          \
    {                                                                 \
      jfieldID fidAlgorithm =                                         \
          (*env)->GetFieldID(env, cfgClass, "algorithm", "I");        \
      c_cfg.algorithm =                                               \
          (uint32_t)(*env)->GetIntField(env, java_cfg, fidAlgorithm); \
    }                                                                 \
    {                                                                 \
      jfieldID fidNbBlocks =                                          \
          (*env)->GetFieldID(env, cfgClass, "nb_blocks", "I");        \
      c_cfg.nb_blocks =                                               \
          (uint32_t)(*env)->GetIntField(env, java_cfg, fidNbBlocks);  \
    }                                                                 \
    {                                                                 \
      jfieldID fidNbPasses =                                          \
          (*env)->GetFieldID(env, cfgClass, "nb_passes", "I");        \
      c_cfg.nb_passes =                                               \
          (uint32_t)(*env)->GetIntField(env, java_cfg, fidNbPasses);  \
    }                                                                 \
    {                                                                 \
      jfieldID fidNbLanes =                                           \
          (*env)->GetFieldID(env, cfgClass, "nb_lanes", "I");         \
      c_cfg.nb_lanes =                                                \
          (uint32_t)(*env)->GetIntField(env, java_cfg, fidNbLanes);   \
    }                                                                 \
  } while (0)

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1argon2(JNIEnv *env,
                                                        jobject obj,
                                                        jbyteArray hash,
                                                        jobject config,
                                                        jobject inputs,
                                                        jobject extras) {
  (void)obj;

  CHECK_NULL(hash, );
  CHECK_NULL(config, );
  CHECK_NULL(inputs, );

  crypto_argon2_config cfg;

  FROM_ARGON2_CONFIG_CLASS(config, cfg);

  if (cfg.algorithm != CRYPTO_ARGON2_D && cfg.algorithm != CRYPTO_ARGON2_I &&
      cfg.algorithm != CRYPTO_ARGON2_ID) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(
        env, exc,
        "algorithm must be one of Argon2_config.Algorithm_ARGON2_{D,I,ID}");
    return;
  }

  if (cfg.nb_blocks < (8 * cfg.nb_lanes)) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "nb_blocks should be at least (8 * nb_lanes)");
    return;
  }

  jclass inputClass = (*env)->GetObjectClass(env, inputs);
  jfieldID fidPass = (*env)->GetFieldID(env, inputClass, "pass", "[B");
  jfieldID fidSalt = (*env)->GetFieldID(env, inputClass, "salt", "[B");
  jbyteArray pass = (jbyteArray)(*env)->GetObjectField(env, inputs, fidPass);
  jbyteArray salt = (jbyteArray)(*env)->GetObjectField(env, inputs, fidSalt);

  if (!salt) {
    jclass npeClass = (*env)->FindClass(env, "java/lang/NullPointerException");
    if (npeClass)
      (*env)->ThrowNew(env, npeClass, "salt cannot be null");
    return;
  }

  jint salt_len = (*env)->GetArrayLength(env, salt);

  if (salt_len < 8) {
    jclass exc = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    (*env)->ThrowNew(env, exc, "salt needs to be at least 8 bytes");
    return;
  }

  jbyte *salt_ptr = (*env)->GetByteArrayElements(env, salt, NULL);

  jbyte *pass_ptr = NULL;
  jint pass_len = 0;

  if (pass) {
    pass_ptr = (*env)->GetByteArrayElements(env, pass, NULL);
    pass_len = (*env)->GetArrayLength(env, pass);
  }

  crypto_argon2_inputs inp = {
      .pass = (const uint8_t *)pass_ptr,
      .pass_size = (uint32_t)pass_len,
      .salt = (const uint8_t *)salt_ptr,
      .salt_size = (uint32_t)salt_len,
  };

  jclass extraClass = (*env)->GetObjectClass(env, extras);
  jfieldID fidKey = (*env)->GetFieldID(env, extraClass, "key", "[B");
  jfieldID fidAd = (*env)->GetFieldID(env, extraClass, "ad", "[B");
  jbyteArray key = (jbyteArray)(*env)->GetObjectField(env, extras, fidKey);
  jbyteArray ad = (jbyteArray)(*env)->GetObjectField(env, extras, fidAd);

  jbyte *key_ptr = NULL;
  jint key_len = 0;

  if (key) {
    key_ptr = (*env)->GetByteArrayElements(env, key, NULL);
    key_len = (*env)->GetArrayLength(env, key);
  }

  jbyte *ad_ptr = NULL;
  jint ad_len = 0;

  if (ad) {
    ad_ptr = (*env)->GetByteArrayElements(env, ad, NULL);
    ad_len = (*env)->GetArrayLength(env, ad);
  }

  crypto_argon2_extras ext = {
      .key = (const uint8_t *)key_ptr,
      .key_size = (uint32_t)key_len,
      .ad = (const uint8_t *)ad_ptr,
      .ad_size = (uint32_t)ad_len,
  };

  jbyte *hash_ptr = (*env)->GetByteArrayElements(env, hash, NULL);
  jint hash_len = (*env)->GetArrayLength(env, hash);

  jbyteArray work_area = (*env)->NewByteArray(env, cfg.nb_blocks * 1024);
  jbyte *work_area_ptr = (*env)->GetByteArrayElements(env, work_area, NULL);

  crypto_argon2((uint8_t *)hash_ptr, (size_t)hash_len, (void *)work_area_ptr,
                cfg, inp, ext);

  (*env)->ReleaseByteArrayElements(env, work_area, work_area_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, hash, hash_ptr, 0);
  (*env)->ReleaseByteArrayElements(env, salt, salt_ptr, JNI_ABORT);
  if (pass) {
    (*env)->ReleaseByteArrayElements(env, pass, pass_ptr, JNI_ABORT);
  }
  if (key) {
    (*env)->ReleaseByteArrayElements(env, key, key_ptr, JNI_ABORT);
  }
  if (ad) {
    (*env)->ReleaseByteArrayElements(env, ad, ad_ptr, JNI_ABORT);
  }
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024Argon2_1inputs_2(
    JNIEnv *env,
    jobject obj,
    jobject inputs) {
  (void)obj;

  if (!inputs) {
    return;
  }

  jclass inputClass = (*env)->GetObjectClass(env, inputs);
  jfieldID fidPass = (*env)->GetFieldID(env, inputClass, "pass", "[B");
  jfieldID fidSalt = (*env)->GetFieldID(env, inputClass, "salt", "[B");
  jbyteArray pass = (jbyteArray)(*env)->GetObjectField(env, inputs, fidPass);
  jbyteArray salt = (jbyteArray)(*env)->GetObjectField(env, inputs, fidSalt);

  if (salt) {
    jint salt_len = (*env)->GetArrayLength(env, salt);
    jbyte *salt_ptr = (*env)->GetByteArrayElements(env, salt, NULL);

    crypto_wipe((void *)salt_ptr, (size_t)salt_len);

    (*env)->ReleaseByteArrayElements(env, salt, salt_ptr, 0);
  }

  if (pass) {
    jint pass_len = (*env)->GetArrayLength(env, pass);
    jbyte *pass_ptr = (*env)->GetByteArrayElements(env, pass, NULL);

    crypto_wipe((void *)pass_ptr, (size_t)pass_len);

    (*env)->ReleaseByteArrayElements(env, pass, pass_ptr, 0);
  }
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1wipe__Lnet_lastninja_monocypher_Monocypher_00024Argon2_1extras_2(
    JNIEnv *env,
    jobject obj,
    jobject extras) {
  (void)obj;

  if (!extras) {
    return;
  }

  jclass extraClass = (*env)->GetObjectClass(env, extras);
  jfieldID fidKey = (*env)->GetFieldID(env, extraClass, "key", "[B");
  jfieldID fidAd = (*env)->GetFieldID(env, extraClass, "ad", "[B");
  jbyteArray key = (jbyteArray)(*env)->GetObjectField(env, extras, fidKey);
  jbyteArray ad = (jbyteArray)(*env)->GetObjectField(env, extras, fidAd);

  if (key) {
    jint key_len = (*env)->GetArrayLength(env, key);
    jbyte *key_ptr = (*env)->GetByteArrayElements(env, key, NULL);

    crypto_wipe((void *)key_ptr, (size_t)key_len);

    (*env)->ReleaseByteArrayElements(env, key, key_ptr, 0);
  }

  if (ad) {
    jint ad_len = (*env)->GetArrayLength(env, ad);
    jbyte *ad_ptr = (*env)->GetByteArrayElements(env, ad, NULL);

    crypto_wipe((void *)ad_ptr, (size_t)ad_len);

    (*env)->ReleaseByteArrayElements(env, ad, ad_ptr, 0);
  }
}
