#include "jni_util.h"

static jobject buffer_field(JNIEnv *env, jobject obj, const char *name) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jfieldID field = (*env)->GetFieldID(env, cls, name, "Ljava/nio/ByteBuffer;");
  return (*env)->GetObjectField(env, obj, field);
}

static jint int_field(JNIEnv *env, jobject obj, const char *name) {
  jclass cls = (*env)->GetObjectClass(env, obj);
  jfieldID field = (*env)->GetFieldID(env, cls, name, "I");
  return (*env)->GetIntField(env, obj, field);
}

/* Argon2_config validates in its constructor; this repeats it as a backstop. */
static bool get_config(JNIEnv *env, jobject j_config, crypto_argon2_config *cfg) {
  jint algorithm = int_field(env, j_config, "algorithm");
  jint nb_blocks = int_field(env, j_config, "nb_blocks");
  jint nb_passes = int_field(env, j_config, "nb_passes");
  jint nb_lanes = int_field(env, j_config, "nb_lanes");

  if (algorithm != CRYPTO_ARGON2_D && algorithm != CRYPTO_ARGON2_I &&
      algorithm != CRYPTO_ARGON2_ID) {
    return mc_throw_iae(env, "algorithm", "is not a known Argon2 algorithm");
  }
  if (nb_passes < 1) return mc_throw_iae(env, "nb_passes", "must be at least 1");
  if (nb_lanes < 1) return mc_throw_iae(env, "nb_lanes", "must be at least 1");
  if ((int64_t)nb_blocks < 8 * (int64_t)nb_lanes) {
    return mc_throw_iae(env, "nb_blocks", "must be at least 8 * nb_lanes");
  }

  cfg->algorithm = (uint32_t)algorithm;
  cfg->nb_blocks = (uint32_t)nb_blocks;
  cfg->nb_passes = (uint32_t)nb_passes;
  cfg->nb_lanes = (uint32_t)nb_lanes;
  return true;
}

JNIEXPORT void JNICALL
Java_net_lastninja_monocypher_Monocypher_crypto_1argon2(JNIEnv *env,
                                                        jclass cls,
                                                        jobject j_hash,
                                                        jobject j_work_area,
                                                        jobject j_config,
                                                        jobject j_inputs,
                                                        jobject j_extras) {
  (void)cls;

  if (!mc_require_object(env, j_config, "config")) return;
  if (!mc_require_object(env, j_inputs, "inputs")) return;
  if (!mc_require_object(env, j_extras, "extras")) return;

  crypto_argon2_config cfg = {0};
  if (!get_config(env, j_config, &cfg)) return;

  mc_buf hash, work_area, pass, salt, key, ad;
  if (!mc_output(env, j_hash, "hash", &hash)) return;
  if (!mc_output(env, j_work_area, "work_area", &work_area)) return;
  if (!mc_input_opt(env, buffer_field(env, j_inputs, "pass"), "pass", &pass)) return;
  if (!mc_input(env, buffer_field(env, j_inputs, "salt"), "salt", &salt)) return;
  if (!mc_input_opt(env, buffer_field(env, j_extras, "key"), "key", &key)) return;
  if (!mc_input_opt(env, buffer_field(env, j_extras, "ad"), "ad", &ad)) return;

  if (salt.len < 8) {
    mc_throw_iae(env, "salt", "must have at least 8 bytes remaining");
    return;
  }
  /* uint64_t because nb_blocks * 1024 overflows 32 bits for large configs. */
  if ((uint64_t)work_area.len != (uint64_t)cfg.nb_blocks * 1024) {
    mc_throw_iae(env, "work_area", "must have exactly nb_blocks * 1024 bytes remaining");
    return;
  }
  if ((uintptr_t)work_area.ptr % 8 != 0) {
    mc_throw_iae(env, "work_area", "must be 8-byte aligned");
    return;
  }

  if (!mc_check_disjoint(env, &hash, "hash", &work_area, "work_area") ||
      !mc_check_disjoint(env, &hash, "hash", &pass, "pass") ||
      !mc_check_disjoint(env, &hash, "hash", &salt, "salt") ||
      !mc_check_disjoint(env, &hash, "hash", &key, "key") ||
      !mc_check_disjoint(env, &hash, "hash", &ad, "ad") ||
      !mc_check_disjoint(env, &work_area, "work_area", &pass, "pass") ||
      !mc_check_disjoint(env, &work_area, "work_area", &salt, "salt") ||
      !mc_check_disjoint(env, &work_area, "work_area", &key, "key") ||
      !mc_check_disjoint(env, &work_area, "work_area", &ad, "ad")) {
    return;
  }

  crypto_argon2_inputs inputs = {
      .pass = pass.ptr,
      .salt = salt.ptr,
      .pass_size = (uint32_t)pass.len,
      .salt_size = (uint32_t)salt.len,
  };
  crypto_argon2_extras extras = {
      .key = key.ptr,
      .ad = ad.ptr,
      .key_size = (uint32_t)key.len,
      .ad_size = (uint32_t)ad.len,
  };

  /* Monocypher wipes work_area itself before returning. */
  crypto_argon2(hash.ptr, (uint32_t)hash.len, work_area.ptr, cfg, inputs, extras);
}
