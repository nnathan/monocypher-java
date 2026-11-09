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
public class WipeTest {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(4)
  public void test_crypto_wipe() {
    {
      byte[] actual = new byte[] {(byte) 0xaa, (byte) 0xbb};
      byte[] expected = new byte[] {(byte) 0x00, (byte) 0x00};

      mc.crypto_wipe(actual);
      assertArrayEquals(expected, actual);
    }

    {
      byte[] actual = null;

      mc.crypto_wipe(actual);
    }
  }
}
