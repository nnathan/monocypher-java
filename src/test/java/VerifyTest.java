import static org.junit.jupiter.api.Assertions.*;
import static net.lastninja.monocypher.TestUtil.*;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import net.lastninja.monocypher.Monocypher;
import net.lastninja.monocypher.Monocypher.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class VerifyTest {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(1)
  public void test_crypto_verify16() {
    {
      byte[] a = new byte[16];
      byte[] b = new byte[16];
      for (int i = 0; i < 16; i++) a[i] = b[i] = (byte) i;

      int result = mc.crypto_verify16(a, b);
      assertEquals(0, result, "Equal arrays should return 0");
    }

    {
      byte[] a = new byte[16];
      byte[] b = new byte[16];
      for (int i = 0; i < 16; i++) {
        a[i] = (byte) i;
        b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
      }

      int result = mc.crypto_verify16(a, b);
      assertEquals(-1, result, "Different arrays should return -1");
    }

    {
      byte[] a = new byte[15];
      byte[] b = new byte[16];
      try {
        mc.crypto_verify16(a, b);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("Both arrays must be 16 bytes long", e.getMessage());
      }
    }
  }

  @Test
  @Order(2)
  public void test_crypto_verify32() {
    {
      byte[] a = new byte[32];
      byte[] b = new byte[32];
      for (int i = 0; i < 32; i++) a[i] = b[i] = (byte) i;

      int result = mc.crypto_verify32(a, b);
      assertEquals(0, result, "Equal arrays should return 0");
    }

    {
      byte[] a = new byte[32];
      byte[] b = new byte[32];
      for (int i = 0; i < 32; i++) {
        a[i] = (byte) i;
        b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
      }

      int result = mc.crypto_verify32(a, b);
      assertEquals(-1, result, "Different arrays should return -1");
    }

    {
      byte[] a = new byte[15];
      byte[] b = new byte[32];
      try {
        mc.crypto_verify32(a, b);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("Both arrays must be 32 bytes long", e.getMessage());
      }
    }
  }

  @Test
  @Order(3)
  public void test_crypto_verify64() {
    {
      byte[] a = new byte[64];
      byte[] b = new byte[64];
      for (int i = 0; i < 64; i++) a[i] = b[i] = (byte) i;

      int result = mc.crypto_verify64(a, b);
      assertEquals(0, result, "Equal arrays should return 0");
    }

    {
      byte[] a = new byte[64];
      byte[] b = new byte[64];
      for (int i = 0; i < 64; i++) {
        a[i] = (byte) i;
        b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
      }

      int result = mc.crypto_verify64(a, b);
      assertEquals(-1, result, "Different arrays should return -1");
    }

    {
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
}
