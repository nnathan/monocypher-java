
package net.lastninja.monocypher;

import java.nio.ByteBuffer;

public final class TestUtil {
  private TestUtil() {}

  public static String toHex(ByteBuffer buffer) {
    StringBuilder sb = new StringBuilder();
    int pos = buffer.position();
    int lim = buffer.limit();
    for (int i = pos; i < lim; i++) {
      sb.append(String.format("%02x", buffer.get(i)));
    }
    return sb.toString();
  }

  public static ByteBuffer fromHexToByteBuffer(String hex) {
    int len = hex.length();
    if (len % 2 != 0) {
      throw new IllegalArgumentException("Hex string must have even length");
    }

    ByteBuffer buffer = ByteBuffer.allocateDirect(len / 2);
    for (int i = 0; i < len; i += 2) {
      byte b = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
      buffer.put(b);
    }

    buffer.flip(); // Reset position to 0 for reading
    return buffer;
  }

  public static byte[] fromHexToByteArray(String hex) {
    int len = hex.length();
    if (len % 2 != 0) {
      throw new IllegalArgumentException("Hex string must have even length");
    }

    byte[] result = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }

    return result;
  }

  public static long fromHexLEToLong(String hex) {
    if (hex.length() != 16) {
      throw new IllegalArgumentException("Hex string must be exactly 16 characters for 8 bytes");
    }

    long result = 0;
    for (int i = 0; i < 8; i++) {
      int byteIndex = i * 2;
      int value = Integer.parseInt(hex.substring(byteIndex, byteIndex + 2), 16);
      result |= ((long) value & 0xFF) << (8 * i); // little-endian shift
    }

    return result;
  }

  public static String toHex(byte[] buffer) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < buffer.length; i++) {
      sb.append(String.format("%02x", buffer[i]));
    }
    return sb.toString();
  }

  public static int fromHexLEToInt(String hex) {
    if (hex.length() != 8) {
      throw new IllegalArgumentException("Hex string must be exactly 8 characters for 4 bytes");
    }

    int result = 0;
    for (int i = 0; i < 4; i++) {
      int byteIndex = i * 2;
      int value = Integer.parseInt(hex.substring(byteIndex, byteIndex + 2), 16);
      result |= (value & 0xFF) << (8 * i); // little-endian shift
    }

    return result;
  }

  public static ByteBuffer direct(byte[] bytes) {
    ByteBuffer buffer = ByteBuffer.allocateDirect(bytes.length);
    buffer.put(bytes);
    buffer.flip();
    return buffer;
  }

  /** Whether a context's off-heap memory contains these exact bytes, wherever it was aligned. */
  public static boolean ctxContains(Object ctx, byte[] expected) {
    ByteBuffer mem = ((Monocypher.Ctx) ctx).mem;
    for (int start = 0; start + expected.length <= mem.capacity(); start++) {
      boolean match = true;
      for (int i = 0; match && i < expected.length; i++) {
        match = mem.get(start + i) == expected[i];
      }
      if (match) return true;
    }
    return false;
  }

  /** Whether every byte of a context's memory, including its state, is zero. */
  public static boolean ctxIsZero(Object ctx) {
    ByteBuffer mem = ((Monocypher.Ctx) ctx).mem;
    for (int i = 0; i < mem.capacity(); i++) {
      if (mem.get(i) != 0) return false;
    }
    return true;
  }

  /** The number of bytes in the context struct itself, without alignment padding or state. */
  public static int ctxStructSize(Object ctx) {
    return ((Monocypher.Ctx) ctx).mem.capacity() - 8;
  }

  /** Overwrites a context's whole memory, including its state, as if it held garbage. */
  public static void ctxFill(Object ctx, byte value) {
    ByteBuffer mem = ((Monocypher.Ctx) ctx).mem;
    for (int i = 0; i < mem.capacity(); i++) {
      mem.put(i, value);
    }
  }

  /**
   * Whether two contexts hold the same struct. The struct's offset in each buffer depends on
   * alignment, so every possible window of a is searched for in b.
   */
  public static boolean ctxSameStruct(Object a, Object b) {
    ByteBuffer mem = ((Monocypher.Ctx) a).mem;
    byte[] window = new byte[ctxStructSize(a)];
    for (int start = 0; start + window.length <= mem.capacity(); start++) {
      for (int i = 0; i < window.length; i++) {
        window[i] = mem.get(start + i);
      }
      if (ctxContains(b, window)) return true;
    }
    return false;
  }
}
