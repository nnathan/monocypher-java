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
public class EddsaTest {

  @Test
  @Order(27)
  public void test_crypto_eddsa_key_pair() {
    // crypto_eddsa_key_pair happy path
    {
      ByteBuffer secret_key = ByteBuffer.allocateDirect(64);
      ByteBuffer public_key = ByteBuffer.allocateDirect(32);
      ByteBuffer seed =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      crypto_eddsa_key_pair(secret_key, public_key, seed);

      String expected, actual;

      expected =
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
              + "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b";
      actual = toHex(secret_key);

      assertEquals(expected, actual, "secret_key mismatch");

      expected = "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b";
      actual = toHex(public_key);

      assertEquals(expected, actual, "public_key mismatch");

      expected = "0000000000000000000000000000000000000000000000000000000000000000";
      actual = toHex(seed);

      assertEquals(expected, actual, "seed mismatch");
    }
  }

  @Test
  @Order(28)
  public void test_crypto_eddsa_sign() {
    // crypto_eddsa_sign happy path
    {
      ByteBuffer secret_key =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      ByteBuffer signature = ByteBuffer.allocateDirect(64);
      ByteBuffer message = null;

      crypto_eddsa_sign(signature, secret_key, message);

      String expected, actual;

      expected =
          "d137e35f4da1beb4e6628c3af3eeeb335ea769c7ed8489e7aecfdd4fcd4b6207"
              + "5816f7bb8ae0687e6ce8cf4ae6af52ee5db55981d4ae664101fa32596c281f0d";
      actual = toHex(signature);

      assertEquals(expected, actual, "signature mismatch");
    }

    // crypto_eddsa_sign happy path
    {
      ByteBuffer secret_key =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      ByteBuffer signature = ByteBuffer.allocateDirect(64);
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      crypto_eddsa_sign(signature, secret_key, message);

      String expected, actual;

      expected =
          "655434d6865d08dff59d21e4623e03fac0023e456b9110a01a1befddc6a4ab0e"
              + "b689e628815958b1ef75086c7d56575636b1eb5b58eb83c9e4fa6443f08ccc07";
      actual = toHex(signature);

      assertEquals(expected, actual, "signature mismatch");
    }
  }

  @Test
  @Order(29)
  public void test_crypto_eddsa_check() {
    // crypto_eddsa_check happy path
    {
      ByteBuffer public_key =
          fromHexToByteBuffer("f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      ByteBuffer signature =
          fromHexToByteBuffer(
              "d137e35f4da1beb4e6628c3af3eeeb335ea769c7ed8489e7aecfdd4fcd4b6207"
                  + "5816f7bb8ae0687e6ce8cf4ae6af52ee5db55981d4ae664101fa32596c281f0d");

      ByteBuffer message = null;

      int result = crypto_eddsa_check(signature, public_key, message);

      int expected = 0;

      assertEquals(expected, result, "signature verification failed");
    }

    // crypto_eddsa_check happy path
    {
      ByteBuffer public_key =
          fromHexToByteBuffer("f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      ByteBuffer signature =
          fromHexToByteBuffer(
              "655434d6865d08dff59d21e4623e03fac0023e456b9110a01a1befddc6a4ab0e"
                  + "b689e628815958b1ef75086c7d56575636b1eb5b58eb83c9e4fa6443f08ccc07");

      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      int result = crypto_eddsa_check(signature, public_key, message);

      int expected = 0;

      assertEquals(expected, result, "signature verification failed");
    }

    // crypto_eddsa_check happy path
    {
      ByteBuffer public_key =
          fromHexToByteBuffer("f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      ByteBuffer signature =
          fromHexToByteBuffer(
              "0000000000000000000000000000000000000000000000000000000000000000"
                  + "0000000000000000000000000000000000000000000000000000000000000000");

      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      int result = crypto_eddsa_check(signature, public_key, message);

      int expected = -1;

      assertEquals(expected, result, "signature verification should fail");
    }
  }

  @Test
  @Order(30)
  public void test_crypto_eddsa_to_x25519() {
    // crypto_eddsa_to_x25519 happy path
    {
      ByteBuffer eddsa =
          fromHexToByteBuffer("752f61d0e2d2e7577f2aafa6a92298b86bb32521d6d7f109dcd834fc41f2a72a");
      ByteBuffer x25519 = ByteBuffer.allocateDirect(32);

      crypto_eddsa_to_x25519(x25519, eddsa);

      String expected = "df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64";
      String actual = toHex(x25519);

      assertEquals(expected, actual, "x25519 mismatch");
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
  public void test_sign_and_check_round_trip() {
    ByteBuffer sk = buf(64);
    ByteBuffer pk = buf(32);
    crypto_eddsa_key_pair(sk, pk, counting(32, 3));

    ByteBuffer message = counting(40, 0);
    message.position(8);
    ByteBuffer signature = buf(64);
    crypto_eddsa_sign(signature, sk, message);
    assertEquals(8, message.position());
    assertEquals(0, crypto_eddsa_check(signature, pk, message));

    message.put(10, (byte) (message.get(10) ^ 1));
    assertEquals(-1, crypto_eddsa_check(signature, pk, message));

    ByteBuffer empty = buf(64);
    crypto_eddsa_sign(empty, sk, null);
    assertEquals(0, crypto_eddsa_check(empty, pk, null));
  }

  @Test
  @Order(101)
  public void test_key_pair_wipes_seed_and_needs_it_writable() {
    ByteBuffer seed = counting(32, 3);
    crypto_eddsa_key_pair(buf(64), buf(32), seed);
    for (int i = 0; i < 32; i++) assertEquals(0, seed.get(i));

    ByteBuffer readOnly = counting(32, 3).asReadOnlyBuffer();
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class, () -> crypto_eddsa_key_pair(buf(64), buf(32), readOnly));
    assertEquals("seed must not be read-only", e.getMessage());
  }

  @Test
  @Order(102)
  public void test_eddsa_rejects_bad_sizes() {
    assertThrows(
        IllegalArgumentException.class, () -> crypto_eddsa_key_pair(buf(32), buf(32), buf(32)));
    assertThrows(IllegalArgumentException.class, () -> crypto_eddsa_sign(buf(63), buf(64), null));
    assertThrows(IllegalArgumentException.class, () -> crypto_eddsa_check(buf(64), buf(31), null));
    assertThrows(IllegalArgumentException.class, () -> crypto_eddsa_to_x25519(buf(32), buf(64)));
  }
}
