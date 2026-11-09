import static net.lastninja.monocypher.Monocypher.*;
import static net.lastninja.monocypher.TestUtil.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class WipeTest {

  @Test
  @Order(1)
  public void test_crypto_wipe_array() {
    byte[] actual = new byte[] {(byte) 0xaa, (byte) 0xbb};
    crypto_wipe(actual);
    assertArrayEquals(new byte[2], actual);

    crypto_wipe((byte[]) null);
  }

  @Test
  @Order(2)
  public void test_crypto_wipe_buffer() {
    ByteBuffer secret = direct(new byte[] {1, 2, 3, 4});
    crypto_wipe(secret);
    assertEquals(0, secret.position());
    for (int i = 0; i < 4; i++) assertEquals(0, secret.get(i));

    crypto_wipe((ByteBuffer) null);
  }

  @Test
  @Order(3)
  public void test_crypto_wipe_only_touches_position_to_limit() {
    ByteBuffer secret = direct(new byte[] {1, 2, 3, 4});
    secret.position(1).limit(3);
    crypto_wipe(secret);
    secret.clear();
    assertEquals(1, secret.get(0));
    assertEquals(0, secret.get(1));
    assertEquals(0, secret.get(2));
    assertEquals(4, secret.get(3));
  }

  @Test
  @Order(4)
  public void test_crypto_wipe_rejects_read_only_and_heap_buffers() {
    ByteBuffer secret = direct(new byte[] {1, 2});

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class, () -> crypto_wipe(secret.asReadOnlyBuffer()));
    assertEquals("secret must not be read-only", e.getMessage());
    assertEquals(1, secret.get(0));

    e = assertThrows(IllegalArgumentException.class, () -> crypto_wipe(ByteBuffer.allocate(2)));
    assertEquals("secret must be a direct ByteBuffer", e.getMessage());
  }
}
