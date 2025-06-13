package net.lastninja.monocypher;

import com.sun.jna.Platform;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class Monocypher {
  static {
    try {
      String lib = "";
      String suffix = "";

      if (Platform.isMac()) {
        if (Platform.isARM()) {
          suffix = ".dylib";
          lib = "/native/mac_arm/libmonocypher_jni.dylib";
        }
      }

      InputStream in = Monocypher.class.getResourceAsStream(lib);
      if (in == null) throw new UnsatisfiedLinkError("Native lib not found: " + lib);

      File temp = File.createTempFile("libmonocypher_jni", suffix);
      temp.deleteOnExit();

      try (OutputStream out = new FileOutputStream(temp)) {
        byte[] buf = new byte[4096];
        int len;
        while ((len = in.read(buf)) != -1) out.write(buf, 0, len);
      }

      System.load(temp.getAbsolutePath());
    } catch (IOException e) {
      throw new RuntimeException("Failed to load native library", e);
    }
  }

  public native int crypto_verify16(byte[] a, byte[] b);

  public native int crypto_verify32(byte[] a, byte[] b);

  public native int crypto_verify64(byte[] a, byte[] b);

  public native void crypto_wipe(byte[] buf);

  public native void crypto_aead_lock(
      ByteBuffer cipher_text,
      ByteBuffer mac,
      byte[] key,
      ByteBuffer nonce,
      ByteBuffer ad,
      ByteBuffer plain_text);

  public native int crypto_aead_unlock(
      ByteBuffer plain_text,
      ByteBuffer mac,
      byte[] key,
      ByteBuffer nonce,
      ByteBuffer ad,
      ByteBuffer cipher_text);

  @SuppressWarnings("unused")
  public class AEAD_ctx {
    private long counter;
    private byte[] key = new byte[32];
    private byte[] nonce = new byte[8];
  }

  public native void crypto_aead_init_x(AEAD_ctx ctx, byte[] key, byte[] nonce);

  public native void crypto_aead_init_djb(AEAD_ctx ctx, byte[] key, byte[] nonce);

  public native void crypto_aead_init_ietf(AEAD_ctx ctx, byte[] key, byte[] nonce);

  public native void crypto_wipe(AEAD_ctx ctx);

  public native void crypto_aead_write(
      AEAD_ctx ctx, ByteBuffer cipher_text, ByteBuffer mac, ByteBuffer ad, ByteBuffer plain_text);

  public native int crypto_aead_read(
      AEAD_ctx ctx, ByteBuffer plain_text, ByteBuffer mac, ByteBuffer ad, ByteBuffer cipher_text);

  public native void crypto_blake2b(byte[] hash, byte[] message);

  public native void crypto_blake2b_keyed(ByteBuffer hash, ByteBuffer key, ByteBuffer message);

  @SuppressWarnings("unused")
  public class Blake2b_ctx {
    private long hash[] = new long[8];
    private long input_offset[] = new long[2];
    private long input[] = new long[16];
    private long input_idx;
    private long hash_size;
  }

  public native void crypto_blake2b_init(Blake2b_ctx ctx, long hash_size);

  public native void crypto_blake2b_update(Blake2b_ctx ctx, byte[] message);

  public native void crypto_blake2b_final(Blake2b_ctx ctx, byte[] hash);

  public native void crypto_wipe(Blake2b_ctx ctx);

  @SuppressWarnings("unused")
  public class Argon2_config {
    public static final int Algorithm_ARGON2_D = 0;
    public static final int Algorithm_ARGON2_I = 1;
    public static final int Algorithm_ARGON2_DI = 2;

    private int algorithm;
    private int nb_blocks;
    private int nb_passes;
    private int nb_lanes;

    public Argon2_config(int algorithm, int nb_blocks, int nb_passes, int nb_lanes) {
      this.algorithm = algorithm;
      this.nb_blocks = nb_blocks;
      this.nb_passes = nb_passes;
      this.nb_lanes = nb_lanes;
    }
  }

  @SuppressWarnings("unused")
  public class Argon2_inputs {
    private byte[] pass;
    private byte[] salt;

    public Argon2_inputs(byte[] pass, byte[] salt) {
      this.pass = pass;
      this.salt = salt;
    }
  }

  @SuppressWarnings("unused")
  public class Argon2_extras {
    private byte[] key;
    private byte[] ad;

    public Argon2_extras(byte[] key, byte[] ad) {
      this.key = key;
      this.ad = ad;
    }
  }

  public native void crypto_argon2(
      byte[] hash, Argon2_config config, Argon2_inputs inputs, Argon2_extras extras);

  public native void crypto_wipe(Argon2_inputs inputs);

  public native void crypto_wipe(Argon2_extras extras);

  public native void crypto_x25519_public_key(byte[] public_key, byte[] secret_key);

  public native void crypto_x25519(
      byte[] raw_shared_secret, byte[] your_secret_key, byte[] their_public_key);

  public native void crypto_x25519_to_eddsa(byte[] eddsa, byte[] x25519);

  public native void crypto_x25519_inverse(
      byte[] blind_salt, byte[] private_key, byte[] curve_point);

  public native void crypto_x25519_dirty_small(byte[] pk, byte[] sk);

  public native void crypto_x25519_dirty_fast(byte[] pk, byte[] sk);

  public native void crypto_eddsa_key_pair(byte[] secret_key, byte[] public_key, byte[] seed);

  public native void crypto_eddsa_sign(byte[] signature, byte[] secret_key, byte[] message);

  public native int crypto_eddsa_check(byte[] signature, byte[] public_key, byte[] message);

  public native void crypto_eddsa_to_x25519(byte[] x25519, byte[] eddsa);

  public native void crypto_eddsa_trim_scalar(byte[] out, byte[] in);

  public native void crypto_eddsa_reduce(byte[] reduced, byte[] expanded);

  public native void crypto_eddsa_mul_add(byte r[], byte[] a, byte[] b, byte[] c);

  public native void crypto_eddsa_scalarbase(byte[] point, byte[] scalar);

  public native void crypto_chacha20_h(byte[] out, byte[] key, byte[] in);

  public native long crypto_chacha20_djb(
      ByteBuffer cipher_text,
      ByteBuffer plain_text,
      long text_size,
      ByteBuffer key,
      ByteBuffer nonce,
      long ctr);

  public native long crypto_chacha20_ietf(
      ByteBuffer cipher_text,
      ByteBuffer plain_text,
      long text_size,
      ByteBuffer key,
      ByteBuffer nonce,
      long ctr);

  public native long crypto_chacha20_x(
      ByteBuffer cipher_text,
      ByteBuffer plain_text,
      long text_size,
      ByteBuffer key,
      ByteBuffer nonce,
      long ctr);

  public native void crypto_poly1305(ByteBuffer mac, ByteBuffer message, byte[] key);

  public class Poly1305_ctx {
    byte[] c = new byte[16];
    long c_idx;
    int[] r = new int[4];
    int[] pad = new int[4];
    int[] h = new int[5];
  }

  public native void crypto_poly1305_init(Poly1305_ctx ctx, byte[] key);
}
