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
public class ElligatorTest {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(44)
  public void test_crypto_elligator_key_pair() {
    // crypto_elligator_key_pair happy path
    {
      byte[] seed =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] hidden = new byte[32];
      byte[] secret = new byte[32];

      mc.crypto_elligator_key_pair(hidden, secret, seed);

      String hidden_expected = "f7e4a52e7996ca06d6d6cb8f4d11f2a89e30ca7df2a30cdadce51e5c84cb009d";
      String hidden_actual = toHex(hidden);

      assertEquals(hidden_expected, hidden_actual, "hidden mismatch");

      String secret_expected = "9cacebfbb286731920ea82342050641ed065ea6431e85e1f3926028214e52507";
      String secret_actual = toHex(secret);

      assertEquals(secret_expected, secret_actual, "secret mismatch");

      String seed_expected = "0000000000000000000000000000000000000000000000000000000000000000";
      String seed_actual = toHex(seed);

      assertEquals(seed_expected, seed_actual, "seed mismatch");
    }
  }

  @Test
  @Order(45)
  public void test_crypto_elligator_rev() {
    // crypto_elligator_rev happy path
    {
      byte[] secret =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] hidden = new byte[32];
      byte tweak = 0x00;

      {
        mc.crypto_x25519_dirty_small(hidden, secret);
        int result = mc.crypto_elligator_rev(hidden, hidden, tweak);
        int expected = -1;
        assertEquals(expected, result, "crypto_elligator_rev mismatch");
      }

      secret[0]++;

      {
        mc.crypto_x25519_dirty_small(hidden, secret);
        int result = mc.crypto_elligator_rev(hidden, hidden, tweak);
        int expected = 0;
        assertEquals(expected, result, "crypto_elligator_rev mismatch");

        String hidden_expected = "9e5a7fa6532ba0750540700e7d0420fc0ba61f0fc126c9732d5569636c683f24";
        String hidden_actual = toHex(hidden);
        assertEquals(hidden_expected, hidden_actual, "hidden mismatch");
      }
    }
  }

  @Test
  @Order(46)
  public void test_crypto_elligator_map() {
    // crypto_elligator_map happy path
    {
      byte[] hidden =
          fromHexToByteArray("9e5a7fa6532ba0750540700e7d0420fc0ba61f0fc126c9732d5569636c683f24");
      byte[] curve = new byte[32];

      mc.crypto_elligator_map(curve, hidden);

      String expected = "4bccf87523680f38820e85a5956f1dba2bd9564dc8a92bf395b8996f41ce724a";

      String actual = toHex(curve);

      assertEquals(expected, actual, "curve mismatch");
    }
  }
}
