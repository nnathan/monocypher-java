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
public class EddsaTest {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(27)
  public void test_crypto_eddsa_key_pair() {
    // crypto_eddsa_key_pair happy path
    {
      byte[] secret_key = new byte[64];
      byte[] public_key = new byte[32];
      byte[] seed =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      mc.crypto_eddsa_key_pair(secret_key, public_key, seed);

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
      byte[] secret_key =
          fromHexToByteArray(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature = new byte[64];
      byte[] message = null;

      mc.crypto_eddsa_sign(signature, secret_key, message);

      String expected, actual;

      expected =
          "d137e35f4da1beb4e6628c3af3eeeb335ea769c7ed8489e7aecfdd4fcd4b6207"
              + "5816f7bb8ae0687e6ce8cf4ae6af52ee5db55981d4ae664101fa32596c281f0d";
      actual = toHex(signature);

      assertEquals(expected, actual, "signature mismatch");
    }

    // crypto_eddsa_sign happy path
    {
      byte[] secret_key =
          fromHexToByteArray(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature = new byte[64];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_eddsa_sign(signature, secret_key, message);

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
      byte[] public_key =
          fromHexToByteArray("f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature =
          fromHexToByteArray(
              "d137e35f4da1beb4e6628c3af3eeeb335ea769c7ed8489e7aecfdd4fcd4b6207"
                  + "5816f7bb8ae0687e6ce8cf4ae6af52ee5db55981d4ae664101fa32596c281f0d");

      byte[] message = null;

      int result = mc.crypto_eddsa_check(signature, public_key, message);

      int expected = 0;

      assertEquals(expected, result, "signature verification failed");
    }

    // crypto_eddsa_check happy path
    {
      byte[] public_key =
          fromHexToByteArray("f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature =
          fromHexToByteArray(
              "655434d6865d08dff59d21e4623e03fac0023e456b9110a01a1befddc6a4ab0e"
                  + "b689e628815958b1ef75086c7d56575636b1eb5b58eb83c9e4fa6443f08ccc07");

      byte[] message = fromHexToByteArray("0001020304050607");

      int result = mc.crypto_eddsa_check(signature, public_key, message);

      int expected = 0;

      assertEquals(expected, result, "signature verification failed");
    }

    // crypto_eddsa_check happy path
    {
      byte[] public_key =
          fromHexToByteArray("f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature =
          fromHexToByteArray(
              "0000000000000000000000000000000000000000000000000000000000000000"
                  + "0000000000000000000000000000000000000000000000000000000000000000");

      byte[] message = fromHexToByteArray("0001020304050607");

      int result = mc.crypto_eddsa_check(signature, public_key, message);

      int expected = -1;

      assertEquals(expected, result, "signature verification should fail");
    }
  }

  @Test
  @Order(30)
  public void test_crypto_eddsa_to_x25519() {
    // crypto_eddsa_to_x25519 happy path
    {
      byte[] eddsa =
          fromHexToByteArray("752f61d0e2d2e7577f2aafa6a92298b86bb32521d6d7f109dcd834fc41f2a72a");
      byte[] x25519 = new byte[32];

      mc.crypto_eddsa_to_x25519(x25519, eddsa);

      String expected = "df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64";
      String actual = toHex(x25519);

      assertEquals(expected, actual, "x25519 mismatch");
    }
  }

  @Test
  @Order(30)
  public void test_crypto_trim_scalar() {
    // crypto_trim_scalar happy path
    {
      byte[] in =
          fromHexToByteArray("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
      byte[] out = new byte[32];

      mc.crypto_eddsa_trim_scalar(out, in);

      String expected = "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
      String actual = toHex(out);

      assertEquals(expected, actual, "out mismatch");
    }
  }

  @Test
  @Order(31)
  public void test_crypto_eddsa_reduce() {
    // crypto_eddsa_reduce happy path
    {
      byte[] expanded =
          fromHexToByteArray(
              "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                  + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
      byte[] reduced = new byte[32];
      ;

      mc.crypto_eddsa_reduce(reduced, expanded);

      String expected = "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903";
      String actual = toHex(reduced);

      assertEquals(expected, actual, "reduced mismatch");
    }
  }

  @Test
  @Order(32)
  public void test_crypto_eddsa_mul_add() {
    // crypto_eddsa_mul_add happy path
    {
      byte[] a =
          fromHexToByteArray("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
      byte[] b =
          fromHexToByteArray("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
      byte[] c =
          fromHexToByteArray("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
      byte[] r = new byte[32];

      mc.crypto_eddsa_mul_add(r, a, b, c);

      String expected = "2a05f60b2d496b1b6c6223f3c345190ee88483d888cca6371eacab86796f7802";
      String actual = toHex(r);

      assertEquals(expected, actual, "r mismatch");
    }
  }

  @Test
  @Order(33)
  public void test_crypto_eddsa_scalarbase() {
    // crypto_eddsa_scalarbase happy path
    {
      byte[] scalar =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] point = new byte[32];

      mc.crypto_eddsa_scalarbase(point, scalar);

      String expected = "ca4a448c3fc4d04945da9fdf920976c05e9bbe3d8cebb1858ea44d587c5e63c3";
      String actual = toHex(point);

      assertEquals(expected, actual, "point mismatch");
    }
  }
}
