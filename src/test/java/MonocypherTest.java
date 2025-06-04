import static org.junit.Assert.*;

import net.lastninja.monocypher.Monocypher;
import org.junit.Test;

public class MonocypherTest {

  private final Monocypher mc = new Monocypher();

  @Test
  public void test_crypto_verify16_Pass() {
    byte[] a = new byte[16];
    byte[] b = new byte[16];
    for (int i = 0; i < 16; i++) a[i] = b[i] = (byte) i;

    int result = mc.crypto_verify16(a, b);
    assertEquals("Equal arrays should return 0", 0, result);
  }

  @Test
  public void test_crypto_verify16_Fail() {
    byte[] a = new byte[16];
    byte[] b = new byte[16];
    for (int i = 0; i < 16; i++) {
      a[i] = (byte) i;
      b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
    }

    int result = mc.crypto_verify16(a, b);
    assertEquals("Different arrays should return -1", -1, result);
  }

  @Test
  public void test_crypto_verify16_LengthMismatch() {
    byte[] a = new byte[15];
    byte[] b = new byte[16];
    try {
      mc.crypto_verify16(a, b);
      fail("Expected IllegalArgumentException was not thrown");
    } catch (IllegalArgumentException e) {
      assertEquals("Both arrays must be 16 bytes long", e.getMessage());
    }
  }

  @Test
  public void test_crypto_verify32_Pass() {
    byte[] a = new byte[32];
    byte[] b = new byte[32];
    for (int i = 0; i < 32; i++) a[i] = b[i] = (byte) i;

    int result = mc.crypto_verify32(a, b);
    assertEquals("Equal arrays should return 0", 0, result);
  }

  @Test
  public void test_crypto_verify32_Fail() {
    byte[] a = new byte[32];
    byte[] b = new byte[32];
    for (int i = 0; i < 32; i++) {
      a[i] = (byte) i;
      b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
    }

    int result = mc.crypto_verify32(a, b);
    assertEquals("Different arrays should return -1", -1, result);
  }

  @Test
  public void test_crypto_verify32_LengthMismatch() {
    byte[] a = new byte[15];
    byte[] b = new byte[32];
    try {
      mc.crypto_verify32(a, b);
      fail("Expected IllegalArgumentException was not thrown");
    } catch (IllegalArgumentException e) {
      assertEquals("Both arrays must be 32 bytes long", e.getMessage());
    }
  }

  @Test
  public void test_crypto_verify64_Pass() {
    byte[] a = new byte[64];
    byte[] b = new byte[64];
    for (int i = 0; i < 64; i++) a[i] = b[i] = (byte) i;

    int result = mc.crypto_verify64(a, b);
    assertEquals("Equal arrays should return 0", 0, result);
  }

  @Test
  public void test_crypto_verify64_Fail() {
    byte[] a = new byte[64];
    byte[] b = new byte[64];
    for (int i = 0; i < 64; i++) {
      a[i] = (byte) i;
      b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
    }

    int result = mc.crypto_verify64(a, b);
    assertEquals("Different arrays should return -1", -1, result);
  }

  @Test
  public void test_crypto_verify64_LengthMismatch() {
    byte[] a = new byte[15];
    byte[] b = new byte[64];
    try {
      mc.crypto_verify64(a, b);
      fail("Expected IllegalArgumentException was not thrown");
    } catch (IllegalArgumentException e) {
      assertEquals("Both arrays must be 64 bytes long", e.getMessage());
    }
  }
}
