package net.lastninja.monocypher;

import java.nio.ByteBuffer;

/**
 * Dangerous low-level EdDSA building blocks ("hazardous materials").
 *
 * <p>These are memory safe, but using them directly allows many kinds of catastrophic misuse. Most
 * users want {@link Monocypher#crypto_eddsa_sign crypto_eddsa_sign} and {@link Monocypher#crypto_eddsa_check crypto_eddsa_check}
 * instead.
 */
public final class Hazmat {
  static {
    NativeLoader.load();
  }

  private Hazmat() {}

  /**
   * <b>Warning:</b> this is a dangerous low-level building block. Using it directly allows many
   * kinds of catastrophic misuse, including leaking the secret key.
   *
   * @see <a href="https://monocypher.org/manual/eddsa">eddsa in the Monocypher manual</a>
   */
  public static native void crypto_eddsa_trim_scalar(ByteBuffer out, ByteBuffer in);

  /**
   * <b>Warning:</b> this is a dangerous low-level building block. Using it directly allows many
   * kinds of catastrophic misuse, including leaking the secret key.
   *
   * @see <a href="https://monocypher.org/manual/eddsa">eddsa in the Monocypher manual</a>
   */
  public static native void crypto_eddsa_reduce(ByteBuffer reduced, ByteBuffer expanded);

  /**
   * <b>Warning:</b> this is a dangerous low-level building block. Using it directly allows many
   * kinds of catastrophic misuse, including leaking the secret key.
   *
   * @see <a href="https://monocypher.org/manual/eddsa">eddsa in the Monocypher manual</a>
   */
  public static native void crypto_eddsa_mul_add(
      ByteBuffer r, ByteBuffer a, ByteBuffer b, ByteBuffer c);

  /**
   * <b>Warning:</b> this is a dangerous low-level building block. Using it directly allows many
   * kinds of catastrophic misuse, including leaking the secret key.
   *
   * @see <a href="https://monocypher.org/manual/eddsa">eddsa in the Monocypher manual</a>
   */
  public static native void crypto_eddsa_scalarbase(ByteBuffer point, ByteBuffer scalar);

  /**
   * <b>Warning:</b> this is a dangerous low-level building block. Using it directly allows many
   * kinds of catastrophic misuse, including leaking the secret key.
   *
   * @return 0 if the signature is valid, -1 otherwise
   * @see <a href="https://monocypher.org/manual/eddsa">eddsa in the Monocypher manual</a>
   */
  public static native int crypto_eddsa_check_equation(
      ByteBuffer signature, ByteBuffer public_key, ByteBuffer h_ram);
}
