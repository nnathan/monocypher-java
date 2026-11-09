package net.lastninja.monocypher;

import java.nio.ByteBuffer;

/**
 * JNI bindings for <a href="https://monocypher.org/">Monocypher</a> 4.0.3, including the optional
 * SHA-512 and Ed25519 functions.
 *
 * <p>Functions keep their C names and argument order, so the <a
 * href="https://monocypher.org/manual/">Monocypher manual</a> applies directly. Read it for the
 * cryptographic rules, such as never reusing a nonce, which these bindings cannot check at compile
 * time.
 *
 * <p>The bindings differ from C in these ways:
 *
 * <ul>
 *   <li>Every byte argument is a direct {@link ByteBuffer}, used from its position to its limit. A
 *       pointer and its size become one buffer. Calls never move the position of any buffer.
 *   <li>Fixed sizes, such as a 32-byte key, are checked, and a buffer with the wrong number of
 *       bytes remaining throws {@link IllegalArgumentException}. So does a heap buffer, or a
 *       read-only buffer where C writes.
 *   <li>A {@code null} buffer throws {@link NullPointerException}, except where C allows {@code
 *       NULL}, such as additional data. There {@code null} is the same as an empty buffer.
 *   <li>Integers narrower than the Java type, such as a 32-bit counter passed as a {@code long},
 *       are checked rather than truncated.
 *   <li>Buffers may overlap only as the manual and upstream tests allow. Where in-place operation
 *       is allowed, the input and output must be the exact same bytes or not overlap at all.
 *       Overlap that is not allowed throws {@link IllegalArgumentException}.
 *   <li>Functions that return an {@code int} status return 0 on success and -1 on failure, as in C.
 *   <li>Contexts are objects, such as {@link Blake2b_ctx}, whose state lives off the Java heap.
 *       Using one before it is initialised, or after it is finalised or wiped, throws {@link
 *       IllegalStateException}. They are {@link AutoCloseable}, and closing one wipes it.
 *   <li>The Argon2 parameters are typed objects, and the algorithm is an enum usable by the same
 *       names as in C.
 *   <li>The low-level EdDSA building blocks are in {@link Hazmat}.
 * </ul>
 *
 * <p>Arguments that Monocypher wipes, such as key pair seeds, count as outputs and must be
 * writable.
 *
 * <p>The examples use zeroed buffers to stay short. Fill keys, nonces, seeds and salts with random
 * bytes, for example like this, which also wipes the temporary array:
 *
 * <pre>{@code
 * static ByteBuffer random(int size) {
 *   byte[] bytes = new byte[size];
 *   new SecureRandom().nextBytes(bytes);
 *   ByteBuffer buffer = ByteBuffer.allocateDirect(size);
 *   buffer.put(bytes).flip();
 *   crypto_wipe(bytes);
 *   return buffer;
 * }
 * }</pre>
 */
public class Monocypher {
  static {
    NativeLoader.load();
  }

  /**
   * Compares two 16-byte buffers in constant time, for comparing MACs.
   *
   * <pre>{@code
   * ByteBuffer mac = ByteBuffer.allocateDirect(16);
   * ByteBuffer expected = ByteBuffer.allocateDirect(16);
   *
   * if (crypto_verify16(mac, expected) != 0) {
   *   throw new IllegalStateException("MAC mismatch");
   * }
   * }</pre>
   *
   * @return 0 if they are equal, -1 otherwise
   * @see <a href="https://monocypher.org/manual/verify">verify in the Monocypher manual</a>
   */
  public static native int crypto_verify16(ByteBuffer a, ByteBuffer b);

  /**
   * Compares two 32-byte buffers in constant time, for comparing hashes or shared secrets.
   *
   * <pre>{@code
   * ByteBuffer hash = ByteBuffer.allocateDirect(32);
   * ByteBuffer expected = ByteBuffer.allocateDirect(32);
   *
   * if (crypto_verify32(hash, expected) != 0) {
   *   throw new IllegalStateException("hash mismatch");
   * }
   * }</pre>
   *
   * @return 0 if they are equal, -1 otherwise
   * @see <a href="https://monocypher.org/manual/verify">verify in the Monocypher manual</a>
   */
  public static native int crypto_verify32(ByteBuffer a, ByteBuffer b);

  /**
   * Compares two 64-byte buffers in constant time, for comparing hashes.
   *
   * <pre>{@code
   * ByteBuffer hash = ByteBuffer.allocateDirect(64);
   * ByteBuffer expected = ByteBuffer.allocateDirect(64);
   *
   * if (crypto_verify64(hash, expected) != 0) {
   *   throw new IllegalStateException("hash mismatch");
   * }
   * }</pre>
   *
   * @return 0 if they are equal, -1 otherwise
   * @see <a href="https://monocypher.org/manual/verify">verify in the Monocypher manual</a>
   */
  public static native int crypto_verify64(ByteBuffer a, ByteBuffer b);

  /**
   * Zeroes a byte array that held secrets. A {@code null} array is ignored.
   *
   * <p>The JVM may give C a copy of the array. That copy is wiped and written back, so the array
   * ends up zeroed and this call leaves no unwiped copy behind. Copies the garbage collector made
   * earlier when it moved the array are out of reach. Prefer direct buffers for secrets.
   *
   * <pre>{@code
   * byte[] secret = new byte[32];
   * // ... use the secret ...
   * crypto_wipe(secret);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/wipe">wipe in the Monocypher manual</a>
   */
  public static native void crypto_wipe(byte[] secret);

  /**
   * Zeroes the bytes of a direct buffer that held secrets, from its position to its limit. A
   * {@code null} buffer is ignored. The buffer must be writable.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32);
   * // ... use the key ...
   * crypto_wipe(key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/wipe">wipe in the Monocypher manual</a>
   */
  public static native void crypto_wipe(ByteBuffer secret);

  /**
   * Encrypts and authenticates {@code plain_text} into {@code cipher_text} and a 16-byte {@code
   * mac}, using a 32-byte {@code key} and a 24-byte {@code nonce}. The result can be decrypted by
   * {@link #crypto_aead_unlock crypto_aead_unlock}.
   *
   * <p>A nonce must never be reused with the same key. The nonce is large enough to be chosen at
   * random. {@code ad} is optional additional data, which is authenticated but not encrypted, and
   * may be {@code null}.
   *
   * <p>{@code cipher_text} and {@code plain_text} must be the same length. They may be the exact
   * same bytes, for encryption in place, or must not overlap. {@code mac} must not overlap the text
   * or {@code ad}, and {@code key} and {@code nonce} must not overlap anything written.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32);   // random
   * ByteBuffer nonce = ByteBuffer.allocateDirect(24); // random, never reused with this key
   * ByteBuffer plain_text = ByteBuffer.allocateDirect(11);
   * ByteBuffer cipher_text = ByteBuffer.allocateDirect(11);
   * ByteBuffer mac = ByteBuffer.allocateDirect(16);
   *
   * crypto_aead_lock(cipher_text, mac, key, nonce, null, plain_text);
   *
   * ByteBuffer decrypted = ByteBuffer.allocateDirect(11);
   * if (crypto_aead_unlock(decrypted, mac, key, nonce, null, cipher_text) != 0) {
   *   throw new IllegalStateException("corrupted message");
   * }
   *
   * crypto_wipe(key);
   * crypto_wipe(plain_text);
   * crypto_wipe(decrypted);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/aead">aead in the Monocypher manual</a>
   */
  public static native void crypto_aead_lock(
      ByteBuffer cipher_text,
      ByteBuffer mac,
      ByteBuffer key,
      ByteBuffer nonce,
      ByteBuffer ad,
      ByteBuffer plain_text);

  /**
   * Checks and decrypts what {@link #crypto_aead_lock crypto_aead_lock} produced. {@code ad} must be the same as
   * when locking, and may be {@code null}.
   *
   * <p>If the MAC is wrong, nothing is written to {@code plain_text}. The same length and overlap
   * rules as {@link #crypto_aead_lock crypto_aead_lock} apply. See {@link #crypto_aead_lock crypto_aead_lock} for an example.
   *
   * @return 0 if the message is authentic and was decrypted, -1 otherwise
   * @see <a href="https://monocypher.org/manual/aead">aead in the Monocypher manual</a>
   */
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

  /**
   * The state of an incremental AEAD stream, {@code crypto_aead_ctx} in C. Initialise it with
   * {@link #crypto_aead_init_x crypto_aead_init_x}, {@link #crypto_aead_init_djb crypto_aead_init_djb} or {@link #crypto_aead_init_ietf crypto_aead_init_ietf}.
   *
   * <p>It holds key material until wiped. Close it, or call {@link #crypto_wipe(AEAD_ctx) crypto_wipe}, once
   * the stream is done. See {@link #crypto_aead_write crypto_aead_write} for an example.
   *
   * @see <a href="https://monocypher.org/manual/aead">aead in the Monocypher manual</a>
   */
  public static final class AEAD_ctx extends Ctx implements AutoCloseable {
    public AEAD_ctx() {
      super(sizeof_aead_ctx());
    }

    /** Wipes the context. */
    @Override
    public void close() {
      crypto_wipe(this);
    }
  }

  /**
   * Starts an AEAD stream with a 32-byte {@code key} and a 24-byte {@code nonce}, large enough to
   * be chosen at random. A nonce must never be reused with the same key. See {@link
   * #crypto_aead_write crypto_aead_write} for an example.
   *
   * @see <a href="https://monocypher.org/manual/aead">aead in the Monocypher manual</a>
   */
  public static native void crypto_aead_init_x(AEAD_ctx ctx, ByteBuffer key, ByteBuffer nonce);

  /**
   * Starts an AEAD stream with a 32-byte {@code key} and an 8-byte {@code nonce}, too small to be
   * chosen at random. A nonce must never be reused with the same key. See {@link
   * #crypto_aead_write crypto_aead_write} for an example.
   *
   * @see <a href="https://monocypher.org/manual/aead">aead in the Monocypher manual</a>
   */
  public static native void crypto_aead_init_djb(AEAD_ctx ctx, ByteBuffer key, ByteBuffer nonce);

  /**
   * Starts an AEAD stream with a 32-byte {@code key} and a 12-byte {@code nonce}, too small to be
   * chosen at random. A nonce must never be reused with the same key. See {@link
   * #crypto_aead_write crypto_aead_write} for an example.
   *
   * @see <a href="https://monocypher.org/manual/aead">aead in the Monocypher manual</a>
   */
  public static native void crypto_aead_init_ietf(AEAD_ctx ctx, ByteBuffer key, ByteBuffer nonce);

  /**
   * Wipes an AEAD context, which must be initialised again before reuse. {@code null} is ignored.
   *
   * @see <a href="https://monocypher.org/manual/wipe">wipe in the Monocypher manual</a>
   */
  public static native void crypto_wipe(AEAD_ctx ctx);

  /**
   * Encrypts and authenticates one chunk of a stream, writing {@code cipher_text} and a 16-byte
   * {@code mac}. Chunks must be read by {@link #crypto_aead_read crypto_aead_read} in the order written.
   *
   * <p>Reordered chunks are detected, but a truncated stream is not. Mark the last chunk yourself,
   * for example with different {@code ad}. The length and overlap rules of {@link
   * #crypto_aead_lock crypto_aead_lock} apply.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32);   // random
   * ByteBuffer nonce = ByteBuffer.allocateDirect(24); // random, never reused with this key
   * ByteBuffer plain_text = ByteBuffer.allocateDirect(11);
   * ByteBuffer cipher_text = ByteBuffer.allocateDirect(11);
   * ByteBuffer mac = ByteBuffer.allocateDirect(16);
   * ByteBuffer decrypted = ByteBuffer.allocateDirect(11);
   *
   * try (AEAD_ctx writer = new AEAD_ctx(); AEAD_ctx reader = new AEAD_ctx()) {
   *   crypto_aead_init_x(writer, key, nonce);
   *   crypto_aead_init_x(reader, key, nonce);
   *
   *   for (int chunk = 0; chunk < 3; chunk++) {
   *     crypto_aead_write(writer, cipher_text, mac, null, plain_text);
   *     if (crypto_aead_read(reader, decrypted, mac, null, cipher_text) != 0) {
   *       throw new IllegalStateException("corrupted chunk");
   *     }
   *   }
   * }
   *
   * crypto_wipe(key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/aead">aead in the Monocypher manual</a>
   */
  public static native void crypto_aead_write(
      AEAD_ctx ctx, ByteBuffer cipher_text, ByteBuffer mac, ByteBuffer ad, ByteBuffer plain_text);

  /**
   * Checks and decrypts one chunk written by {@link #crypto_aead_write crypto_aead_write}. If the MAC is wrong,
   * nothing is written to {@code plain_text} and {@code ctx} is unchanged. See {@link
   * #crypto_aead_write crypto_aead_write} for an example.
   *
   * @return 0 if the chunk is authentic and was decrypted, -1 otherwise
   * @see <a href="https://monocypher.org/manual/aead">aead in the Monocypher manual</a>
   */
  public static native int crypto_aead_read(
      AEAD_ctx ctx, ByteBuffer plain_text, ByteBuffer mac, ByteBuffer ad, ByteBuffer cipher_text);

  /**
   * Hashes {@code message} with BLAKE2b. The hash is as long as {@code hash}, between 1 and 64
   * bytes. {@code message} may be {@code null}. Any of the buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer message = ByteBuffer.allocateDirect(11);
   * ByteBuffer hash = ByteBuffer.allocateDirect(64);
   *
   * crypto_blake2b(hash, message);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/blake2b">blake2b in the Monocypher manual</a>
   */
  public static native void crypto_blake2b(ByteBuffer hash, ByteBuffer message);

  /**
   * Like {@link #crypto_blake2b crypto_blake2b}, keyed with up to 64 bytes for use as a MAC or for key
   * derivation. {@code key} may be {@code null} or empty, which is the same as unkeyed.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer message = ByteBuffer.allocateDirect(11);
   * ByteBuffer mac = ByteBuffer.allocateDirect(64);
   *
   * crypto_blake2b_keyed(mac, key, message);
   * crypto_wipe(key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/blake2b">blake2b in the Monocypher manual</a>
   */
  public static native void crypto_blake2b_keyed(ByteBuffer hash, ByteBuffer key, ByteBuffer message);

  private static native int sizeof_blake2b_ctx();

  /**
   * The state of an incremental BLAKE2b hash, {@code crypto_blake2b_ctx} in C. Initialise it with
   * {@link #crypto_blake2b_init crypto_blake2b_init} or {@link #crypto_blake2b_keyed_init crypto_blake2b_keyed_init}, which have examples.
   *
   * @see <a href="https://monocypher.org/manual/blake2b">blake2b in the Monocypher manual</a>
   */
  public static final class Blake2b_ctx extends Ctx implements AutoCloseable {
    public Blake2b_ctx() {
      super(sizeof_blake2b_ctx());
    }

    /** Wipes the context. */
    @Override
    public void close() {
      crypto_wipe(this);
    }
  }

  /**
   * Starts an incremental BLAKE2b hash. {@code hash_size} must be between 1 and 64.
   *
   * <pre>{@code
   * ByteBuffer part1 = ByteBuffer.allocateDirect(5);
   * ByteBuffer part2 = ByteBuffer.allocateDirect(6);
   * ByteBuffer hash = ByteBuffer.allocateDirect(64);
   *
   * try (Blake2b_ctx ctx = new Blake2b_ctx()) {
   *   crypto_blake2b_init(ctx, 64);
   *   crypto_blake2b_update(ctx, part1);
   *   crypto_blake2b_update(ctx, part2);
   *   crypto_blake2b_final(ctx, hash);
   * }
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/blake2b">blake2b in the Monocypher manual</a>
   */
  public static native void crypto_blake2b_init(Blake2b_ctx ctx, int hash_size);

  /**
   * Starts an incremental keyed BLAKE2b hash. {@code hash_size} must be between 1 and 64, and
   * {@code key} may be {@code null} or up to 64 bytes.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer part1 = ByteBuffer.allocateDirect(5);
   * ByteBuffer part2 = ByteBuffer.allocateDirect(6);
   * ByteBuffer mac = ByteBuffer.allocateDirect(32);
   *
   * try (Blake2b_ctx ctx = new Blake2b_ctx()) {
   *   crypto_blake2b_keyed_init(ctx, 32, key);
   *   crypto_blake2b_update(ctx, part1);
   *   crypto_blake2b_update(ctx, part2);
   *   crypto_blake2b_final(ctx, mac);
   * }
   * crypto_wipe(key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/blake2b">blake2b in the Monocypher manual</a>
   */
  public static native void crypto_blake2b_keyed_init(
      Blake2b_ctx ctx, int hash_size, ByteBuffer key);

  /**
   * Adds {@code message}, which may be {@code null}, to an incremental BLAKE2b hash. See {@link
   * #crypto_blake2b_init crypto_blake2b_init} for an example.
   *
   * @see <a href="https://monocypher.org/manual/blake2b">blake2b in the Monocypher manual</a>
   */
  public static native void crypto_blake2b_update(Blake2b_ctx ctx, ByteBuffer message);

  /**
   * Finishes an incremental BLAKE2b hash. {@code hash} must have exactly the {@code hash_size}
   * given at initialisation. Monocypher wipes ctx, so it must be initialised again before reuse.
   * See {@link #crypto_blake2b_init crypto_blake2b_init} for an example.
   *
   * @see <a href="https://monocypher.org/manual/blake2b">blake2b in the Monocypher manual</a>
   */
  public static native void crypto_blake2b_final(Blake2b_ctx ctx, ByteBuffer hash);

  /**
   * Wipes a BLAKE2b context, which must be initialised again before reuse. {@code null} is ignored.
   *
   * @see <a href="https://monocypher.org/manual/wipe">wipe in the Monocypher manual</a>
   */
  public static native void crypto_wipe(Blake2b_ctx ctx);

  /**
   * The Argon2 variant, {@code CRYPTO_ARGON2_D}, {@code _I} or {@code _ID} in C.
   *
   * @see <a href="https://monocypher.org/manual/argon2">argon2 in the Monocypher manual</a>
   */
  public enum crypto_argon2_algorithm {
    /** Argon2d. */
    CRYPTO_ARGON2_D(0),
    /** Argon2i. */
    CRYPTO_ARGON2_I(1),
    /** Argon2id. */
    CRYPTO_ARGON2_ID(2);

    final int value;

    crypto_argon2_algorithm(int value) {
      this.value = value;
    }
  }

  /** Argon2d, usable by the same name as in C. */
  public static final crypto_argon2_algorithm CRYPTO_ARGON2_D = crypto_argon2_algorithm.CRYPTO_ARGON2_D;
  /** Argon2i, usable by the same name as in C. */
  public static final crypto_argon2_algorithm CRYPTO_ARGON2_I = crypto_argon2_algorithm.CRYPTO_ARGON2_I;
  /** Argon2id, usable by the same name as in C. */
  public static final crypto_argon2_algorithm CRYPTO_ARGON2_ID = crypto_argon2_algorithm.CRYPTO_ARGON2_ID;

  /** The largest nb_blocks whose work area fits in one ByteBuffer. */
  private static final int ARGON2_MAX_BLOCKS = Integer.MAX_VALUE / 1024;

  /**
   * The cost parameters of {@link #crypto_argon2 crypto_argon2}, {@code crypto_argon2_config} in C. They are
   * checked when constructed. See {@link #crypto_argon2 crypto_argon2} for an example.
   *
   * @see <a href="https://monocypher.org/manual/argon2">argon2 in the Monocypher manual</a>
   */
  public static final class Argon2_config {
    final int algorithm;
    final int nb_blocks;
    final int nb_passes;
    final int nb_lanes;

    /**
     * @param algorithm the Argon2 variant
     * @param nb_blocks the number of 1 KiB blocks in the work area. At least {@code 8 * nb_lanes},
     *     and at most 2097151 because the work area must fit in one ByteBuffer. The manual
     *     suggests 100000 as a starting point.
     * @param nb_passes the number of passes, at least 1. The manual strongly recommends 3 for
     *     Argon2i.
     * @param nb_lanes the level of parallelism, at least 1. Monocypher does not use threads, so
     *     this adds no parallelism, and the manual strongly recommends 1.
     * @throws NullPointerException if algorithm is null
     * @throws IllegalArgumentException if a parameter is out of range
     */
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

  /**
   * The password and salt for {@link #crypto_argon2 crypto_argon2}, {@code crypto_argon2_inputs} in C. The
   * buffers are not copied, so they are read when the hash is computed.
   *
   * @see <a href="https://monocypher.org/manual/argon2">argon2 in the Monocypher manual</a>
   */
  public static final class Argon2_inputs {
    final ByteBuffer pass;
    final ByteBuffer salt;

    /**
     * A null pass is an empty password. salt must have at least 8 bytes remaining when hashed, and
     * 16 random bytes are recommended.
     */
    public Argon2_inputs(ByteBuffer pass, ByteBuffer salt) {
      this.pass = pass;
      this.salt = salt;
    }
  }

  /**
   * The rarely needed key and additional data for {@link #crypto_argon2 crypto_argon2}, {@code
   * crypto_argon2_extras} in C.
   *
   * @see <a href="https://monocypher.org/manual/argon2">argon2 in the Monocypher manual</a>
   */
  public static final class Argon2_extras {
    final ByteBuffer key;
    final ByteBuffer ad;

    /** Either may be null, meaning none. */
    public Argon2_extras(ByteBuffer key, ByteBuffer ad) {
      this.key = key;
      this.ad = ad;
    }
  }

  /** No key and no additional data, {@code crypto_argon2_no_extras} in C. */
  public static final Argon2_extras crypto_argon2_no_extras = new Argon2_extras(null, null);

  /**
   * Hashes a password with Argon2, for password storage or key derivation. The hash is as long as
   * {@code hash}. 32 or 64 bytes are recommended, to compare hashes with {@link #crypto_verify32 crypto_verify32}
   * or {@link #crypto_verify64 crypto_verify64}.
   *
   * <p>{@code work_area} must be exactly {@code nb_blocks * 1024} bytes and 8-byte aligned. A
   * fresh {@link ByteBuffer#allocateDirect ByteBuffer.allocateDirect} buffer is aligned in practice. Argon2 wipes it.
   *
   * <p>The password, salt, key and additional data may overlap each other, as the manual allows.
   * Neither {@code hash} nor {@code work_area} may overlap anything. Monocypher's own tests also
   * overlap the work area with the inputs, which these bindings reject.
   *
   * <p>Wipe the password with {@link #crypto_wipe(ByteBuffer) crypto_wipe} once it has been hashed.
   *
   * <pre>{@code
   * ByteBuffer password = ByteBuffer.allocateDirect(8);
   * ByteBuffer salt = ByteBuffer.allocateDirect(16); // random
   * ByteBuffer hash = ByteBuffer.allocateDirect(32);
   *
   * Argon2_config config = new Argon2_config(CRYPTO_ARGON2_ID, 100000, 3, 1);
   * ByteBuffer work_area = ByteBuffer.allocateDirect(100000 * 1024);
   *
   * crypto_argon2(
   *     hash, work_area, config, new Argon2_inputs(password, salt), crypto_argon2_no_extras);
   * crypto_wipe(password);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/argon2">argon2 in the Monocypher manual</a>
   */
  public static native void crypto_argon2(
      ByteBuffer hash,
      ByteBuffer work_area,
      Argon2_config config,
      Argon2_inputs inputs,
      Argon2_extras extras);

  /**
   * Computes the 32-byte public key for a 32-byte X25519 secret key. Any of the buffers may
   * overlap.
   *
   * <pre>{@code
   * ByteBuffer secret_key = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer public_key = ByteBuffer.allocateDirect(32);
   *
   * crypto_x25519_public_key(public_key, secret_key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/x25519">x25519 in the Monocypher manual</a>
   */
  public static native void crypto_x25519_public_key(ByteBuffer public_key, ByteBuffer secret_key);

  /**
   * Computes a 32-byte shared secret between your secret key and their public key. The result is
   * not uniformly random, so hash it before using it as a key, as the manual explains. Any of the
   * buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer your_secret_key = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer your_public_key = ByteBuffer.allocateDirect(32);
   * ByteBuffer their_public_key = ByteBuffer.allocateDirect(32); // received from them
   * crypto_x25519_public_key(your_public_key, your_secret_key);
   *
   * ByteBuffer shared_secret = ByteBuffer.allocateDirect(32);
   * crypto_x25519(shared_secret, your_secret_key, their_public_key);
   *
   * // Hash the shared secret with both public keys to get the shared key.
   * ByteBuffer shared_key = ByteBuffer.allocateDirect(32);
   * try (Blake2b_ctx ctx = new Blake2b_ctx()) {
   *   crypto_blake2b_init(ctx, 32);
   *   crypto_blake2b_update(ctx, shared_secret);
   *   crypto_blake2b_update(ctx, your_public_key);
   *   crypto_blake2b_update(ctx, their_public_key);
   *   crypto_blake2b_final(ctx, shared_key);
   * }
   *
   * crypto_wipe(your_secret_key);
   * crypto_wipe(shared_secret);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/x25519">x25519 in the Monocypher manual</a>
   */
  public static native void crypto_x25519(
      ByteBuffer raw_shared_secret, ByteBuffer your_secret_key, ByteBuffer their_public_key);

  /**
   * Converts a 32-byte X25519 public key to an EdDSA public key.
   *
   * <pre>{@code
   * ByteBuffer x25519 = ByteBuffer.allocateDirect(32);
   * ByteBuffer eddsa = ByteBuffer.allocateDirect(32);
   *
   * crypto_x25519_to_eddsa(eddsa, x25519);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/x25519">x25519 in the Monocypher manual</a>
   */
  public static native void crypto_x25519_to_eddsa(ByteBuffer eddsa, ByteBuffer x25519);

  /**
   * Multiplies a 32-byte curve point by the inverse of a 32-byte private key, for exponential
   * blinding. Any of the buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer private_key = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer curve_point = ByteBuffer.allocateDirect(32);
   * ByteBuffer blind_salt = ByteBuffer.allocateDirect(32);
   *
   * crypto_x25519_inverse(blind_salt, private_key, curve_point);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/x25519">x25519 in the Monocypher manual</a>
   */
  public static native void crypto_x25519_inverse(
      ByteBuffer blind_salt, ByteBuffer private_key, ByteBuffer curve_point);

  /**
   * Computes a public key that may lie anywhere on the curve, for use with Elligator. Smaller code
   * than {@link #crypto_x25519_dirty_fast crypto_x25519_dirty_fast}, with the same result.
   *
   * <pre>{@code
   * ByteBuffer sk = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer pk = ByteBuffer.allocateDirect(32);
   *
   * crypto_x25519_dirty_small(pk, sk);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/x25519">x25519 in the Monocypher manual</a>
   */
  public static native void crypto_x25519_dirty_small(ByteBuffer pk, ByteBuffer sk);

  /**
   * Computes a public key that may lie anywhere on the curve, for use with Elligator. Faster than
   * {@link #crypto_x25519_dirty_small crypto_x25519_dirty_small}, with the same result.
   *
   * <pre>{@code
   * ByteBuffer sk = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer pk = ByteBuffer.allocateDirect(32);
   *
   * crypto_x25519_dirty_fast(pk, sk);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/x25519">x25519 in the Monocypher manual</a>
   */
  public static native void crypto_x25519_dirty_fast(ByteBuffer pk, ByteBuffer sk);

  /**
   * Makes an EdDSA key pair, a 64-byte secret key and a 32-byte public key, from a 32-byte random
   * {@code seed}. The secret key holds the seed and the public key. Monocypher wipes the seed, so
   * it must be writable. See {@link #crypto_eddsa_sign crypto_eddsa_sign} for an example.
   *
   * @see <a href="https://monocypher.org/manual/eddsa">eddsa in the Monocypher manual</a>
   */
  public static native void crypto_eddsa_key_pair(
      ByteBuffer secret_key, ByteBuffer public_key, ByteBuffer seed);

  /**
   * Signs {@code message}, which may be {@code null}, with a 64-byte secret key, writing a 64-byte
   * signature. Any of the buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer seed = ByteBuffer.allocateDirect(32); // random, wiped by crypto_eddsa_key_pair
   * ByteBuffer secret_key = ByteBuffer.allocateDirect(64);
   * ByteBuffer public_key = ByteBuffer.allocateDirect(32);
   * crypto_eddsa_key_pair(secret_key, public_key, seed);
   *
   * ByteBuffer message = ByteBuffer.allocateDirect(11);
   * ByteBuffer signature = ByteBuffer.allocateDirect(64);
   * crypto_eddsa_sign(signature, secret_key, message);
   *
   * if (crypto_eddsa_check(signature, public_key, message) != 0) {
   *   throw new IllegalStateException("forged signature");
   * }
   *
   * crypto_wipe(secret_key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/eddsa">eddsa in the Monocypher manual</a>
   */
  public static native void crypto_eddsa_sign(
      ByteBuffer signature, ByteBuffer secret_key, ByteBuffer message);

  /**
   * Checks a 64-byte signature of {@code message}, which may be {@code null}, against a 32-byte
   * public key. See {@link #crypto_eddsa_sign crypto_eddsa_sign} for an example.
   *
   * @return 0 if the signature is valid, -1 otherwise
   * @see <a href="https://monocypher.org/manual/eddsa">eddsa in the Monocypher manual</a>
   */
  public static native int crypto_eddsa_check(
      ByteBuffer signature, ByteBuffer public_key, ByteBuffer message);

  /**
   * Converts a 32-byte EdDSA public key to an X25519 public key.
   *
   * <pre>{@code
   * ByteBuffer eddsa = ByteBuffer.allocateDirect(32);
   * ByteBuffer x25519 = ByteBuffer.allocateDirect(32);
   *
   * crypto_eddsa_to_x25519(x25519, eddsa);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/eddsa">eddsa in the Monocypher manual</a>
   */
  public static native void crypto_eddsa_to_x25519(ByteBuffer x25519, ByteBuffer eddsa);

  /**
   * HChaCha20: derives 32 bytes from a 32-byte {@code key} and 16 bytes {@code in}, for example to
   * hash an X25519 shared secret. Any of the buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32);
   * ByteBuffer in = ByteBuffer.allocateDirect(16);
   * ByteBuffer out = ByteBuffer.allocateDirect(32);
   *
   * crypto_chacha20_h(out, key, in);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/chacha20">chacha20 in the Monocypher manual</a>
   */
  public static native void crypto_chacha20_h(ByteBuffer out, ByteBuffer key, ByteBuffer in);

  /**
   * Encrypts or decrypts with ChaCha20, using a 32-byte {@code key}, an 8-byte {@code nonce} and a
   * block counter {@code ctr}. An 8-byte nonce is too small to be chosen at random, so prefer
   * {@link #crypto_chacha20_x crypto_chacha20_x}.
   *
   * <p>A {@code null} plain_text stands for all zeroes, so {@code cipher_text} receives the raw key
   * stream. Otherwise it must be the same length as {@code cipher_text}, and the two may be the
   * exact same bytes or must not overlap. {@code key} and {@code nonce} must not overlap {@code
   * cipher_text}.
   *
   * <p>{@code ctr} is the unsigned 64-bit counter from C, passed through unchanged, so it works
   * exactly as in C. Values above {@code Long.MAX_VALUE} only look negative in Java.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32);  // random
   * ByteBuffer nonce = ByteBuffer.allocateDirect(8); // a counter, never reused with this key
   * ByteBuffer plain_text = ByteBuffer.allocateDirect(100);
   * ByteBuffer cipher_text = ByteBuffer.allocateDirect(100);
   *
   * long ctr = crypto_chacha20_djb(cipher_text, plain_text, key, nonce, 0);
   * // ctr is now 2, ready to continue the same stream
   * }</pre>
   *
   * @return the counter to pass as {@code ctr} to continue where this call stopped
   * @see <a href="https://monocypher.org/manual/chacha20">chacha20 in the Monocypher manual</a>
   */
  public static native long crypto_chacha20_djb(
      ByteBuffer cipher_text, ByteBuffer plain_text, ByteBuffer key, ByteBuffer nonce, long ctr);

  /**
   * Like {@link #crypto_chacha20_djb crypto_chacha20_djb} with a 12-byte {@code nonce}, as in RFC 8439. The nonce is
   * too small to be chosen at random. {@code ctr} must be between 0 and 4294967295, as the C
   * counter is 32 bits and truncating it would reuse key stream.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32);   // random
   * ByteBuffer nonce = ByteBuffer.allocateDirect(12); // a counter, never reused with this key
   * ByteBuffer plain_text = ByteBuffer.allocateDirect(100);
   * ByteBuffer cipher_text = ByteBuffer.allocateDirect(100);
   *
   * long ctr = crypto_chacha20_ietf(cipher_text, plain_text, key, nonce, 0);
   * // ctr is now 2, ready to continue the same stream
   * }</pre>
   *
   * @return the counter to pass as {@code ctr} to continue where this call stopped
   * @see <a href="https://monocypher.org/manual/chacha20">chacha20 in the Monocypher manual</a>
   */
  public static native long crypto_chacha20_ietf(
      ByteBuffer cipher_text, ByteBuffer plain_text, ByteBuffer key, ByteBuffer nonce, long ctr);

  /**
   * Like {@link #crypto_chacha20_djb crypto_chacha20_djb} with a 24-byte {@code nonce}, which is large enough to be
   * chosen at random.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32);   // random
   * ByteBuffer nonce = ByteBuffer.allocateDirect(24); // random, never reused with this key
   * ByteBuffer plain_text = ByteBuffer.allocateDirect(100);
   * ByteBuffer cipher_text = ByteBuffer.allocateDirect(100);
   *
   * long ctr = crypto_chacha20_x(cipher_text, plain_text, key, nonce, 0);
   * // ctr is now 2, ready to continue the same stream
   * }</pre>
   *
   * @return the counter to pass as {@code ctr} to continue where this call stopped
   * @see <a href="https://monocypher.org/manual/chacha20">chacha20 in the Monocypher manual</a>
   */
  public static native long crypto_chacha20_x(
      ByteBuffer cipher_text, ByteBuffer plain_text, ByteBuffer key, ByteBuffer nonce, long ctr);

  /**
   * Computes a 16-byte Poly1305 MAC of {@code message}, which may be {@code null}, with a 32-byte
   * one-time {@code key}. A key must never authenticate two messages. Any of the buffers may
   * overlap.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32); // random, for this message only
   * ByteBuffer message = ByteBuffer.allocateDirect(11);
   * ByteBuffer mac = ByteBuffer.allocateDirect(16);
   *
   * crypto_poly1305(mac, message, key);
   * crypto_wipe(key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/poly1305">poly1305 in the Monocypher manual</a>
   */
  public static native void crypto_poly1305(ByteBuffer mac, ByteBuffer message, ByteBuffer key);

  private static native int sizeof_poly1305_ctx();

  /**
   * The state of an incremental Poly1305 MAC, {@code crypto_poly1305_ctx} in C. Initialise it with
   * {@link #crypto_poly1305_init crypto_poly1305_init}, which has an example.
   *
   * @see <a href="https://monocypher.org/manual/poly1305">poly1305 in the Monocypher manual</a>
   */
  public static final class Poly1305_ctx extends Ctx implements AutoCloseable {
    public Poly1305_ctx() {
      super(sizeof_poly1305_ctx());
    }

    /** Wipes the context. */
    @Override
    public void close() {
      crypto_wipe(this);
    }
  }

  /**
   * Starts an incremental Poly1305 MAC with a 32-byte one-time {@code key}.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32); // random, for this message only
   * ByteBuffer part1 = ByteBuffer.allocateDirect(5);
   * ByteBuffer part2 = ByteBuffer.allocateDirect(6);
   * ByteBuffer mac = ByteBuffer.allocateDirect(16);
   *
   * try (Poly1305_ctx ctx = new Poly1305_ctx()) {
   *   crypto_poly1305_init(ctx, key);
   *   crypto_poly1305_update(ctx, part1);
   *   crypto_poly1305_update(ctx, part2);
   *   crypto_poly1305_final(ctx, mac);
   * }
   * crypto_wipe(key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/poly1305">poly1305 in the Monocypher manual</a>
   */
  public static native void crypto_poly1305_init(Poly1305_ctx ctx, ByteBuffer key);

  /**
   * Adds {@code message}, which may be {@code null}, to an incremental Poly1305 MAC. See {@link
   * #crypto_poly1305_init crypto_poly1305_init} for an example.
   *
   * @see <a href="https://monocypher.org/manual/poly1305">poly1305 in the Monocypher manual</a>
   */
  public static native void crypto_poly1305_update(Poly1305_ctx ctx, ByteBuffer message);

  /**
   * Finishes an incremental Poly1305 MAC into a 16-byte {@code mac}. Wipes ctx, so it must be
   * initialised again before reuse. See {@link #crypto_poly1305_init crypto_poly1305_init} for an example.
   *
   * @see <a href="https://monocypher.org/manual/poly1305">poly1305 in the Monocypher manual</a>
   */
  public static native void crypto_poly1305_final(Poly1305_ctx ctx, ByteBuffer mac);

  /**
   * Wipes a Poly1305 context, which must be initialised again before reuse. {@code null} is ignored.
   *
   * @see <a href="https://monocypher.org/manual/wipe">wipe in the Monocypher manual</a>
   */
  public static native void crypto_wipe(Poly1305_ctx ctx);

  /**
   * Makes an X25519 key pair whose public key can be hidden as random noise: a 32-byte {@code
   * hidden} representative and a 32-byte {@code secret_key}, from a 32-byte random {@code seed}.
   * Monocypher wipes the seed, so it must be writable. Any of the buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer seed = ByteBuffer.allocateDirect(32); // random, wiped by this call
   * ByteBuffer hidden = ByteBuffer.allocateDirect(32);
   * ByteBuffer secret_key = ByteBuffer.allocateDirect(32);
   *
   * crypto_elligator_key_pair(hidden, secret_key, seed);
   * // send hidden, which is indistinguishable from random bytes
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/elligator">elligator in the Monocypher manual</a>
   */
  public static native void crypto_elligator_key_pair(
      ByteBuffer hidden, ByteBuffer secret_key, ByteBuffer seed);

  /**
   * Hides a 32-byte {@code curve} point as a 32-byte representative indistinguishable from random.
   * {@code tweak} must be between 0 and 255, and should be random. Any of the buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer secret_key = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer public_key = ByteBuffer.allocateDirect(32);
   * ByteBuffer hidden = ByteBuffer.allocateDirect(32);
   * int tweak = 0x5a; // a random byte
   *
   * crypto_x25519_dirty_fast(public_key, secret_key);
   * if (crypto_elligator_rev(hidden, public_key, tweak) != 0) {
   *   // this key cannot be hidden: make another and try again
   * }
   * }</pre>
   *
   * @return 0 on success, -1 if this point cannot be hidden, in which case try another key pair
   * @see <a href="https://monocypher.org/manual/elligator">elligator in the Monocypher manual</a>
   */
  public static native int crypto_elligator_rev(ByteBuffer hidden, ByteBuffer curve, int tweak);

  /**
   * Recovers the 32-byte curve point from a 32-byte representative made by {@link
   * #crypto_elligator_rev crypto_elligator_rev} or {@link #crypto_elligator_key_pair crypto_elligator_key_pair}. Any of the buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer hidden = ByteBuffer.allocateDirect(32); // received from them
   * ByteBuffer their_public_key = ByteBuffer.allocateDirect(32);
   *
   * crypto_elligator_map(their_public_key, hidden);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/elligator">elligator in the Monocypher manual</a>
   */
  public static native void crypto_elligator_map(ByteBuffer curve, ByteBuffer hidden);

  /**
   * Hashes {@code message}, which may be {@code null}, with SHA-512 into a 64-byte {@code hash}.
   * Prefer {@link #crypto_blake2b crypto_blake2b} unless SHA-512 is required. Any of the buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer message = ByteBuffer.allocateDirect(11);
   * ByteBuffer hash = ByteBuffer.allocateDirect(64);
   *
   * crypto_sha512(hash, message);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512(ByteBuffer hash, ByteBuffer message);

  private static native int sizeof_sha512_ctx();

  /**
   * The state of an incremental SHA-512 hash, {@code crypto_sha512_ctx} in C. Initialise it with
   * {@link #crypto_sha512_init crypto_sha512_init}, which has an example.
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static final class SHA512_ctx extends Ctx implements AutoCloseable {
    public SHA512_ctx() {
      super(sizeof_sha512_ctx());
    }

    /** Wipes the context. */
    @Override
    public void close() {
      crypto_wipe(this);
    }
  }

  /**
   * Starts an incremental SHA-512 hash.
   *
   * <pre>{@code
   * ByteBuffer part1 = ByteBuffer.allocateDirect(5);
   * ByteBuffer part2 = ByteBuffer.allocateDirect(6);
   * ByteBuffer hash = ByteBuffer.allocateDirect(64);
   *
   * try (SHA512_ctx ctx = new SHA512_ctx()) {
   *   crypto_sha512_init(ctx);
   *   crypto_sha512_update(ctx, part1);
   *   crypto_sha512_update(ctx, part2);
   *   crypto_sha512_final(ctx, hash);
   * }
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512_init(SHA512_ctx ctx);

  /**
   * Adds {@code message}, which may be {@code null}, to an incremental SHA-512 hash. See {@link
   * #crypto_sha512_init crypto_sha512_init} for an example.
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512_update(SHA512_ctx ctx, ByteBuffer message);

  /**
   * Finishes an incremental SHA-512 hash into a 64-byte {@code hash}. Wipes ctx, so it must be
   * initialised again before reuse. See {@link #crypto_sha512_init crypto_sha512_init} for an example.
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512_final(SHA512_ctx ctx, ByteBuffer hash);

  /**
   * Wipes a SHA-512 context, which must be initialised again before reuse. {@code null} is ignored.
   *
   * @see <a href="https://monocypher.org/manual/wipe">wipe in the Monocypher manual</a>
   */
  public static native void crypto_wipe(SHA512_ctx ctx);

  /**
   * Computes a 64-byte HMAC-SHA-512 of {@code message}, which may be {@code null}. {@code key} may
   * be empty but not {@code null}, and keys longer than 128 bytes are hashed first. Prefer {@link
   * #crypto_blake2b_keyed crypto_blake2b_keyed} unless HMAC is required. Any of the buffers may overlap.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer message = ByteBuffer.allocateDirect(11);
   * ByteBuffer hmac = ByteBuffer.allocateDirect(64);
   *
   * crypto_sha512_hmac(hmac, key, message);
   * crypto_wipe(key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512_hmac(ByteBuffer hmac, ByteBuffer key, ByteBuffer message);

  private static native int sizeof_sha512_hmac_ctx();

  /**
   * The state of an incremental HMAC-SHA-512, {@code crypto_sha512_hmac_ctx} in C. Initialise it
   * with {@link #crypto_sha512_hmac_init crypto_sha512_hmac_init}, which has an example. It holds key material until wiped.
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static final class SHA512_HMAC_ctx extends Ctx implements AutoCloseable {
    public SHA512_HMAC_ctx() {
      super(sizeof_sha512_hmac_ctx());
    }

    /** Wipes the context. */
    @Override
    public void close() {
      crypto_wipe(this);
    }
  }

  /**
   * Starts an incremental HMAC-SHA-512. {@code key} may be empty but not {@code null}.
   *
   * <pre>{@code
   * ByteBuffer key = ByteBuffer.allocateDirect(32); // random
   * ByteBuffer part1 = ByteBuffer.allocateDirect(5);
   * ByteBuffer part2 = ByteBuffer.allocateDirect(6);
   * ByteBuffer hmac = ByteBuffer.allocateDirect(64);
   *
   * try (SHA512_HMAC_ctx ctx = new SHA512_HMAC_ctx()) {
   *   crypto_sha512_hmac_init(ctx, key);
   *   crypto_sha512_hmac_update(ctx, part1);
   *   crypto_sha512_hmac_update(ctx, part2);
   *   crypto_sha512_hmac_final(ctx, hmac);
   * }
   * crypto_wipe(key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512_hmac_init(SHA512_HMAC_ctx ctx, ByteBuffer key);

  /**
   * Adds {@code message}, which may be {@code null}, to an incremental HMAC-SHA-512. See {@link
   * #crypto_sha512_hmac_init crypto_sha512_hmac_init} for an example.
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512_hmac_update(SHA512_HMAC_ctx ctx, ByteBuffer message);

  /**
   * Finishes an incremental HMAC-SHA-512 into a 64-byte {@code hmac}. Wipes ctx, so it must be
   * initialised again before reuse. See {@link #crypto_sha512_hmac_init crypto_sha512_hmac_init} for an example.
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512_hmac_final(SHA512_HMAC_ctx ctx, ByteBuffer hmac);

  /**
   * Wipes an HMAC-SHA-512 context, which must be initialised again before reuse. {@code null} is ignored.
   *
   * @see <a href="https://monocypher.org/manual/wipe">wipe in the Monocypher manual</a>
   */
  public static native void crypto_wipe(SHA512_HMAC_ctx ctx);

  /**
   * The expand step of HKDF-SHA-512: derives {@code okm} from a pseudo-random key {@code prk} and
   * optional domain separation {@code info}, which may be {@code null}. {@code okm} must have at
   * most 16320 bytes remaining, and must not overlap prk or info, as the manual requires.
   *
   * <pre>{@code
   * ByteBuffer prk = ByteBuffer.allocateDirect(64); // uniformly random
   * ByteBuffer okm = ByteBuffer.allocateDirect(80);
   *
   * crypto_sha512_hkdf_expand(okm, prk, null);
   * crypto_wipe(prk);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512_hkdf_expand(ByteBuffer okm, ByteBuffer prk, ByteBuffer info);

  /**
   * HKDF-SHA-512: derives {@code okm} from input key material {@code ikm}. {@code salt} and {@code
   * info} may be {@code null}, and a salt should have at least 16 bytes when used. {@code okm} must
   * have at most 16320 bytes remaining, and must not overlap ikm, salt or info, as the manual
   * requires.
   *
   * <pre>{@code
   * ByteBuffer ikm = ByteBuffer.allocateDirect(32);  // a shared secret, for example
   * ByteBuffer salt = ByteBuffer.allocateDirect(16); // random
   * ByteBuffer okm = ByteBuffer.allocateDirect(64);
   *
   * crypto_sha512_hkdf(okm, ikm, salt, null);
   * crypto_wipe(ikm);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/sha512">sha512 in the Monocypher manual</a>
   */
  public static native void crypto_sha512_hkdf(
      ByteBuffer okm, ByteBuffer ikm, ByteBuffer salt, ByteBuffer info);

  /**
   * Makes an Ed25519 key pair, a 64-byte secret key and a 32-byte public key, from a 32-byte random
   * {@code seed}. These are RFC 8032 keys, not interchangeable with {@link #crypto_eddsa_key_pair crypto_eddsa_key_pair},
   * which uses BLAKE2b. Monocypher wipes the seed, so it must be writable. See {@link
   * #crypto_ed25519_sign crypto_ed25519_sign} for an example.
   *
   * @see <a href="https://monocypher.org/manual/ed25519">ed25519 in the Monocypher manual</a>
   */
  public static native void crypto_ed25519_key_pair(
      ByteBuffer secret_key, ByteBuffer public_key, ByteBuffer seed);

  /**
   * Signs {@code message}, which may be {@code null}, with a 64-byte Ed25519 secret key, writing a
   * 64-byte signature. There are no overlap checks, as for {@link #crypto_eddsa_sign crypto_eddsa_sign}, whose
   * signing code this shares.
   *
   * <pre>{@code
   * ByteBuffer seed = ByteBuffer.allocateDirect(32); // random, wiped by crypto_ed25519_key_pair
   * ByteBuffer secret_key = ByteBuffer.allocateDirect(64);
   * ByteBuffer public_key = ByteBuffer.allocateDirect(32);
   * crypto_ed25519_key_pair(secret_key, public_key, seed);
   *
   * ByteBuffer message = ByteBuffer.allocateDirect(11);
   * ByteBuffer signature = ByteBuffer.allocateDirect(64);
   * crypto_ed25519_sign(signature, secret_key, message);
   *
   * if (crypto_ed25519_check(signature, public_key, message) != 0) {
   *   throw new IllegalStateException("forged signature");
   * }
   *
   * crypto_wipe(secret_key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/ed25519">ed25519 in the Monocypher manual</a>
   */
  public static native void crypto_ed25519_sign(
      ByteBuffer signature, ByteBuffer secret_key, ByteBuffer message);

  /**
   * Checks a 64-byte Ed25519 signature of {@code message}, which may be {@code null}, against a
   * 32-byte public key. See {@link #crypto_ed25519_sign crypto_ed25519_sign} for an example.
   *
   * @return 0 if the signature is valid, -1 otherwise
   * @see <a href="https://monocypher.org/manual/ed25519">ed25519 in the Monocypher manual</a>
   */
  public static native int crypto_ed25519_check(
      ByteBuffer signature, ByteBuffer public_key, ByteBuffer message);

  /**
   * Ed25519ph: signs the 64-byte SHA-512 {@code message_hash} of a message, writing a 64-byte
   * signature. Use only where Ed25519ph is required.
   *
   * <pre>{@code
   * ByteBuffer seed = ByteBuffer.allocateDirect(32); // random, wiped by crypto_ed25519_key_pair
   * ByteBuffer secret_key = ByteBuffer.allocateDirect(64);
   * ByteBuffer public_key = ByteBuffer.allocateDirect(32);
   * crypto_ed25519_key_pair(secret_key, public_key, seed);
   *
   * ByteBuffer message = ByteBuffer.allocateDirect(11);
   * ByteBuffer message_hash = ByteBuffer.allocateDirect(64);
   * crypto_sha512(message_hash, message);
   *
   * ByteBuffer signature = ByteBuffer.allocateDirect(64);
   * crypto_ed25519_ph_sign(signature, secret_key, message_hash);
   *
   * if (crypto_ed25519_ph_check(signature, public_key, message_hash) != 0) {
   *   throw new IllegalStateException("forged signature");
   * }
   *
   * crypto_wipe(secret_key);
   * }</pre>
   *
   * @see <a href="https://monocypher.org/manual/ed25519">ed25519 in the Monocypher manual</a>
   */
  public static native void crypto_ed25519_ph_sign(
      ByteBuffer signature, ByteBuffer secret_key, ByteBuffer message_hash);

  /**
   * Checks an Ed25519ph signature against a 32-byte public key and the 64-byte SHA-512 {@code
   * message_hash} of the message. See {@link #crypto_ed25519_ph_sign crypto_ed25519_ph_sign} for an example.
   *
   * @return 0 if the signature is valid, -1 otherwise
   * @see <a href="https://monocypher.org/manual/ed25519">ed25519 in the Monocypher manual</a>
   */
  public static native int crypto_ed25519_ph_check(
      ByteBuffer signature, ByteBuffer public_key, ByteBuffer message_hash);
}
