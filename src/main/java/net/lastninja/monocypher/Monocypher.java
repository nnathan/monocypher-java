package net.lastninja.monocypher;

import java.nio.ByteBuffer;

public class Monocypher {
  static {
    NativeLoader.load();
  }

  public static native int crypto_verify16(ByteBuffer a, ByteBuffer b);

  public static native int crypto_verify32(ByteBuffer a, ByteBuffer b);

  public static native int crypto_verify64(ByteBuffer a, ByteBuffer b);

  public static native void crypto_wipe(byte[] secret);

  public static native void crypto_wipe(ByteBuffer secret);

  public static native void crypto_aead_lock(
      ByteBuffer cipher_text,
      ByteBuffer mac,
      ByteBuffer key,
      ByteBuffer nonce,
      ByteBuffer ad,
      ByteBuffer plain_text);

  public static native int crypto_aead_unlock(
      ByteBuffer plain_text,
      ByteBuffer mac,
      ByteBuffer key,
      ByteBuffer nonce,
      ByteBuffer ad,
      ByteBuffer cipher_text);

  /** An off-heap context, used in place by C. Holds secrets until wiped or closed. */
  abstract static class Ctx {
    final ByteBuffer mem;

    Ctx(int size) {
      mem = ByteBuffer.allocateDirect(size);
    }
  }

  private static native int sizeof_aead_ctx();

  public static final class AEAD_ctx extends Ctx implements AutoCloseable {
    public AEAD_ctx() {
      super(sizeof_aead_ctx());
    }

    @Override
    public void close() {
      crypto_wipe(this);
    }
  }

  public static native void crypto_aead_init_x(AEAD_ctx ctx, ByteBuffer key, ByteBuffer nonce);

  public static native void crypto_aead_init_djb(AEAD_ctx ctx, ByteBuffer key, ByteBuffer nonce);

  public static native void crypto_aead_init_ietf(AEAD_ctx ctx, ByteBuffer key, ByteBuffer nonce);

  public static native void crypto_wipe(AEAD_ctx ctx);

  public static native void crypto_aead_write(
      AEAD_ctx ctx, ByteBuffer cipher_text, ByteBuffer mac, ByteBuffer ad, ByteBuffer plain_text);

  public static native int crypto_aead_read(
      AEAD_ctx ctx, ByteBuffer plain_text, ByteBuffer mac, ByteBuffer ad, ByteBuffer cipher_text);

  public static native void crypto_blake2b(ByteBuffer hash, ByteBuffer message);

  public static native void crypto_blake2b_keyed(ByteBuffer hash, ByteBuffer key, ByteBuffer message);

  private static native int sizeof_blake2b_ctx();

  public static final class Blake2b_ctx extends Ctx implements AutoCloseable {
    public Blake2b_ctx() {
      super(sizeof_blake2b_ctx());
    }

    @Override
    public void close() {
      crypto_wipe(this);
    }
  }

  public static native void crypto_blake2b_init(Blake2b_ctx ctx, int hash_size);

  public static native void crypto_blake2b_keyed_init(
      Blake2b_ctx ctx, int hash_size, ByteBuffer key);

  public static native void crypto_blake2b_update(Blake2b_ctx ctx, ByteBuffer message);

  /** Monocypher wipes ctx, so it must be initialised again before reuse. */
  public static native void crypto_blake2b_final(Blake2b_ctx ctx, ByteBuffer hash);

  public static native void crypto_wipe(Blake2b_ctx ctx);

  public enum crypto_argon2_algorithm {
    CRYPTO_ARGON2_D(0),
    CRYPTO_ARGON2_I(1),
    CRYPTO_ARGON2_ID(2);

    final int value;

    crypto_argon2_algorithm(int value) {
      this.value = value;
    }
  }

  public static final crypto_argon2_algorithm CRYPTO_ARGON2_D = crypto_argon2_algorithm.CRYPTO_ARGON2_D;
  public static final crypto_argon2_algorithm CRYPTO_ARGON2_I = crypto_argon2_algorithm.CRYPTO_ARGON2_I;
  public static final crypto_argon2_algorithm CRYPTO_ARGON2_ID = crypto_argon2_algorithm.CRYPTO_ARGON2_ID;

  /** The largest nb_blocks whose work area fits in one ByteBuffer. */
  private static final int ARGON2_MAX_BLOCKS = Integer.MAX_VALUE / 1024;

  public static final class Argon2_config {
    final int algorithm;
    final int nb_blocks;
    final int nb_passes;
    final int nb_lanes;

    public Argon2_config(
        crypto_argon2_algorithm algorithm, int nb_blocks, int nb_passes, int nb_lanes) {
      if (algorithm == null) throw new NullPointerException("algorithm cannot be null");
      if (nb_passes < 1) throw new IllegalArgumentException("nb_passes must be at least 1");
      if (nb_lanes < 1) throw new IllegalArgumentException("nb_lanes must be at least 1");
      if (nb_blocks < 8L * nb_lanes) {
        throw new IllegalArgumentException("nb_blocks must be at least 8 * nb_lanes");
      }
      if (nb_blocks > ARGON2_MAX_BLOCKS) {
        throw new IllegalArgumentException("nb_blocks must be at most " + ARGON2_MAX_BLOCKS);
      }

      this.algorithm = algorithm.value;
      this.nb_blocks = nb_blocks;
      this.nb_passes = nb_passes;
      this.nb_lanes = nb_lanes;
    }
  }

  public static final class Argon2_inputs {
    final ByteBuffer pass;
    final ByteBuffer salt;

    /** A null pass is an empty password. */
    public Argon2_inputs(ByteBuffer pass, ByteBuffer salt) {
      this.pass = pass;
      this.salt = salt;
    }
  }

  public static final class Argon2_extras {
    final ByteBuffer key;
    final ByteBuffer ad;

    /** Either may be null, meaning none. */
    public Argon2_extras(ByteBuffer key, ByteBuffer ad) {
      this.key = key;
      this.ad = ad;
    }
  }

  public static final Argon2_extras crypto_argon2_no_extras = new Argon2_extras(null, null);

  /** work_area must be exactly nb_blocks * 1024 bytes and 8-byte aligned. Argon2 wipes it. */
  public static native void crypto_argon2(
      ByteBuffer hash,
      ByteBuffer work_area,
      Argon2_config config,
      Argon2_inputs inputs,
      Argon2_extras extras);

  public static native void crypto_x25519_public_key(ByteBuffer public_key, ByteBuffer secret_key);

  public static native void crypto_x25519(
      ByteBuffer raw_shared_secret, ByteBuffer your_secret_key, ByteBuffer their_public_key);

  public static native void crypto_x25519_to_eddsa(ByteBuffer eddsa, ByteBuffer x25519);

  public static native void crypto_x25519_inverse(
      ByteBuffer blind_salt, ByteBuffer private_key, ByteBuffer curve_point);

  public static native void crypto_x25519_dirty_small(ByteBuffer pk, ByteBuffer sk);

  public static native void crypto_x25519_dirty_fast(ByteBuffer pk, ByteBuffer sk);

  /** Monocypher wipes the seed, so it must be writable. */
  public static native void crypto_eddsa_key_pair(
      ByteBuffer secret_key, ByteBuffer public_key, ByteBuffer seed);

  public static native void crypto_eddsa_sign(
      ByteBuffer signature, ByteBuffer secret_key, ByteBuffer message);

  /** Returns 0 if the signature is valid, -1 otherwise. */
  public static native int crypto_eddsa_check(
      ByteBuffer signature, ByteBuffer public_key, ByteBuffer message);

  public static native void crypto_eddsa_to_x25519(ByteBuffer x25519, ByteBuffer eddsa);

  public static native void crypto_chacha20_h(ByteBuffer out, ByteBuffer key, ByteBuffer in);

  public static native long crypto_chacha20_djb(
      ByteBuffer cipher_text, ByteBuffer plain_text, ByteBuffer key, ByteBuffer nonce, long ctr);

  public static native long crypto_chacha20_ietf(
      ByteBuffer cipher_text, ByteBuffer plain_text, ByteBuffer key, ByteBuffer nonce, long ctr);

  public static native long crypto_chacha20_x(
      ByteBuffer cipher_text, ByteBuffer plain_text, ByteBuffer key, ByteBuffer nonce, long ctr);

  public static native void crypto_poly1305(ByteBuffer mac, ByteBuffer message, ByteBuffer key);

  private static native int sizeof_poly1305_ctx();

  public static final class Poly1305_ctx extends Ctx implements AutoCloseable {
    public Poly1305_ctx() {
      super(sizeof_poly1305_ctx());
    }

    @Override
    public void close() {
      crypto_wipe(this);
    }
  }

  public static native void crypto_poly1305_init(Poly1305_ctx ctx, ByteBuffer key);

  public static native void crypto_poly1305_update(Poly1305_ctx ctx, ByteBuffer message);

  /** Wipes ctx, so it must be initialised again before reuse. */
  public static native void crypto_poly1305_final(Poly1305_ctx ctx, ByteBuffer mac);

  public static native void crypto_wipe(Poly1305_ctx ctx);

  /** Monocypher wipes the seed, so it must be writable. */
  public static native void crypto_elligator_key_pair(
      ByteBuffer hidden, ByteBuffer secret_key, ByteBuffer seed);

  /** tweak must be between 0 and 255. Returns 0 on success, -1 if curve cannot be hidden. */
  public static native int crypto_elligator_rev(ByteBuffer hidden, ByteBuffer curve, int tweak);

  public static native void crypto_elligator_map(ByteBuffer curve, ByteBuffer hidden);
}
