import static org.junit.jupiter.api.Assertions.*;
import static net.lastninja.monocypher.Monocypher.*;
import static net.lastninja.monocypher.TestUtil.*;

import java.nio.ByteBuffer;
import net.lastninja.monocypher.Monocypher;
import net.lastninja.monocypher.Monocypher.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ElligatorTest {

  @Test
  @Order(44)
  public void test_crypto_elligator_key_pair() {
    // crypto_elligator_key_pair happy path
    {
      ByteBuffer seed =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer hidden = ByteBuffer.allocateDirect(32);
      ByteBuffer secret = ByteBuffer.allocateDirect(32);

      crypto_elligator_key_pair(hidden, secret, seed);

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
      ByteBuffer secret =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer hidden = ByteBuffer.allocateDirect(32);
      byte tweak = 0x00;

      {
        crypto_x25519_dirty_small(hidden, secret);
        int result = crypto_elligator_rev(hidden, hidden, tweak);
        int expected = -1;
        assertEquals(expected, result, "crypto_elligator_rev mismatch");
      }

      secret.put(0, (byte) (secret.get(0) + 1));

      {
        crypto_x25519_dirty_small(hidden, secret);
        int result = crypto_elligator_rev(hidden, hidden, tweak);
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
      ByteBuffer hidden =
          fromHexToByteBuffer("9e5a7fa6532ba0750540700e7d0420fc0ba61f0fc126c9732d5569636c683f24");
      ByteBuffer curve = ByteBuffer.allocateDirect(32);

      crypto_elligator_map(curve, hidden);

      String expected = "4bccf87523680f38820e85a5956f1dba2bd9564dc8a92bf395b8996f41ce724a";

      String actual = toHex(curve);

      assertEquals(expected, actual, "curve mismatch");
    }
  }

  private static ByteBuffer buf(int len) {
    return ByteBuffer.allocateDirect(len);
  }

  private static ByteBuffer counting(int len, int start) {
    ByteBuffer b = buf(len);
    for (int i = 0; i < len; i++) b.put(i, (byte) (start + i));
    return b;
  }

  @Test
  @Order(100)
  public void test_rev_tweak_range() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class, () -> crypto_elligator_rev(buf(32), buf(32), 256));
    assertEquals("tweak must be between 0 and 255", e.getMessage());
    assertThrows(IllegalArgumentException.class, () -> crypto_elligator_rev(buf(32), buf(32), -1));
    crypto_elligator_rev(buf(32), buf(32), 255);
  }

  @Test
  @Order(101)
  public void test_key_pair_round_trips_through_map() {
    ByteBuffer hidden = buf(32);
    ByteBuffer sk = buf(32);
    ByteBuffer seed = counting(32, 5);
    crypto_elligator_key_pair(hidden, sk, seed);
    for (int i = 0; i < 32; i++) assertEquals(0, seed.get(i));

    // Elligator key pairs use dirty public keys, which differ from crypto_x25519_public_key.
    ByteBuffer pk = buf(32);
    crypto_x25519_dirty_small(pk, sk);
    ByteBuffer curve = buf(32);
    crypto_elligator_map(curve, hidden);
    assertEquals(toHex(pk), toHex(curve));

    assertThrows(
        IllegalArgumentException.class,
        () -> crypto_elligator_key_pair(buf(32), buf(32), counting(32, 5).asReadOnlyBuffer()));
  }
}
