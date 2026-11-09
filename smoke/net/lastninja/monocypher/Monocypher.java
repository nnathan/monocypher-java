package net.lastninja.monocypher;

import java.util.Arrays;

/**
 * Stands in for the real class so the JNI symbols resolve without its loader.
 * Takes the path of the library to test. Removed once the loader handles every
 * target.
 */
public class Monocypher {
  public native int crypto_verify16(byte[] a, byte[] b);

  public native void crypto_blake2b(byte[] hash, byte[] message);

  // BLAKE2b-512 of "abc", from RFC 7693 appendix A.
  private static final int[] ABC_HASH = {
    0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d, 0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
    0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7, 0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
    0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d, 0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
    0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a, 0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23
  };

  public static void main(String[] args) {
    System.load(args[0]);
    Monocypher m = new Monocypher();

    byte[] expected = new byte[ABC_HASH.length];
    for (int i = 0; i < expected.length; i++) expected[i] = (byte) ABC_HASH[i];

    byte[] hash = new byte[64];
    m.crypto_blake2b(hash, new byte[] {'a', 'b', 'c'});
    if (!Arrays.equals(hash, expected)) throw new AssertionError("blake2b mismatch");

    byte[] a = new byte[16];
    byte[] b = new byte[16];
    if (m.crypto_verify16(a, b) != 0) throw new AssertionError("verify16 equal");
    b[15] = 1;
    if (m.crypto_verify16(a, b) != -1) throw new AssertionError("verify16 differ");

    System.out.println(
        "OK java "
            + System.getProperty("java.version")
            + " "
            + System.getProperty("os.name")
            + " "
            + System.getProperty("os.arch"));
  }
}
