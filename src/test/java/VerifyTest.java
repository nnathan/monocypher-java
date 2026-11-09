import static net.lastninja.monocypher.Monocypher.*;
import static net.lastninja.monocypher.TestUtil.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class VerifyTest {

  private interface Verify {
    int call(ByteBuffer a, ByteBuffer b);
  }

  private static byte[] counting(int len) {
    byte[] bytes = new byte[len];
    for (int i = 0; i < len; i++) bytes[i] = (byte) i;
    return bytes;
  }

  private static void check(Verify verify, int len) {
    assertEquals(0, verify.call(direct(counting(len)), direct(counting(len))));

    byte[] different = counting(len);
    different[8] = (byte) 0xff;
    assertEquals(-1, verify.call(direct(counting(len)), direct(different)));

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> verify.call(ByteBuffer.allocateDirect(15), direct(counting(len))));
    assertEquals("a must have exactly " + len + " bytes remaining", e.getMessage());

    e =
        assertThrows(
            IllegalArgumentException.class,
            () -> verify.call(direct(counting(len)), ByteBuffer.allocateDirect(len + 1)));
    assertEquals("b must have exactly " + len + " bytes remaining", e.getMessage());
  }

  @Test
  @Order(1)
  public void test_crypto_verify16() {
    check((a, b) -> crypto_verify16(a, b), 16);
  }

  @Test
  @Order(2)
  public void test_crypto_verify32() {
    check((a, b) -> crypto_verify32(a, b), 32);
  }

  @Test
  @Order(3)
  public void test_crypto_verify64() {
    check((a, b) -> crypto_verify64(a, b), 64);
  }

  @Test
  @Order(4)
  public void test_crypto_verify_rejects_null_and_heap_buffers() {
    ByteBuffer good = ByteBuffer.allocateDirect(16);

    NullPointerException npe =
        assertThrows(NullPointerException.class, () -> crypto_verify16(null, good));
    assertEquals("a cannot be null", npe.getMessage());

    IllegalArgumentException iae =
        assertThrows(
            IllegalArgumentException.class,
            () -> crypto_verify16(good, ByteBuffer.allocate(16)));
    assertEquals("b must be a direct ByteBuffer", iae.getMessage());
  }

  @Test
  @Order(5)
  public void test_crypto_verify_uses_position_and_limit() {
    byte[] backing = new byte[32];
    System.arraycopy(counting(16), 0, backing, 8, 16);
    backing[0] = (byte) 0xff; // only outside the compared window

    ByteBuffer a = direct(backing);
    a.position(8).limit(24);
    assertEquals(0, crypto_verify16(a, direct(counting(16))));
  }

  @Test
  @Order(6)
  public void test_crypto_verify_leaves_position_alone() {
    ByteBuffer a = direct(counting(16));
    ByteBuffer b = direct(counting(16));
    crypto_verify16(a, b);
    assertEquals(0, a.position());
    assertEquals(0, b.position());
  }

  @Test
  @Order(7)
  public void test_crypto_verify_accepts_read_only_buffers() {
    assertEquals(
        0,
        crypto_verify16(
            direct(counting(16)).asReadOnlyBuffer(), direct(counting(16)).asReadOnlyBuffer()));
  }
}
