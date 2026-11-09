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
public class X25519Test {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(22)
  public void test_crypto_x25519_public_key() {
    // crypto_x25519_public_key happy path
    {
      byte[] secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] public_key = new byte[32];

      mc.crypto_x25519_public_key(public_key, secret_key);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(public_key);

      assertEquals(expected, actual, "public_key mismatch");
    }

    // crypto_x25519_public_key sad path null secret key
    {
      byte[] secret_key = null;
      byte[] public_key = new byte[32];

      try {
        mc.crypto_x25519_public_key(public_key, secret_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("secret_key cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_public_key sad path null public key
    {
      byte[] secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] public_key = null;

      try {
        mc.crypto_x25519_public_key(public_key, secret_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("public_key cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_public_key secret_key invalid length
    {
      byte[] secret_key = fromHexToByteArray("00");
      byte[] public_key = new byte[32];

      try {
        mc.crypto_x25519_public_key(public_key, secret_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("secret_key must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519_public_key public_key invalid length
    {
      byte[] secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] public_key = new byte[1];

      try {
        mc.crypto_x25519_public_key(public_key, secret_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("public_key must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(23)
  public void test_crypto_x25519() {
    // crypto_x25519 happy path
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = new byte[32];

      mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);

      String expected = "df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64";
      String actual = toHex(raw_shared_secret);

      assertEquals(expected, actual, "raw_shared_secret mismatch");
    }

    // crypto_x25519 sad path null secret key
    {
      byte[] your_secret_key = null;
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = new byte[32];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("your_secret_key cannot be null", e.getMessage());
      }
    }

    // crypto_x25519 sad path null public key
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key = null;
      byte[] raw_shared_secret = new byte[32];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("their_public_key cannot be null", e.getMessage());
      }
    }
    //
    // crypto_x25519 sad path raw shared secret
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = null;

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("raw_shared_secret cannot be null", e.getMessage());
      }
    }

    // crypto_x25519 secret_key invalid length
    {
      byte[] your_secret_key = fromHexToByteArray("00");
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = new byte[32];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("your_secret_key must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519 public_key invalid length
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key = fromHexToByteArray("8f");
      byte[] raw_shared_secret = new byte[32];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("their_public_key must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519 public_key invalid length
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = new byte[1];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("raw_shared_secret must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(24)
  public void test_crypto_x25519_to_eddsa() {
    // crypto_x25519_to_eddsa happy path
    {
      byte[] x25519 =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] eddsa = new byte[32];

      mc.crypto_x25519_to_eddsa(eddsa, x25519);

      String expected = "752f61d0e2d2e7577f2aafa6a92298b86bb32521d6d7f109dcd834fc41f2a72a";
      String actual = toHex(eddsa);

      assertEquals(expected, actual, "raw_shared_secret mismatch");
    }

    // crypto_x25519_to_eddsa sad path null x25519
    {
      byte[] x25519 = null;
      byte[] eddsa = new byte[32];

      try {
        mc.crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("x25519 cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_to_eddsa sad path null eddsa
    {
      byte[] x25519 =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] eddsa = null;

      try {
        mc.crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("eddsa cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_to_eddsa sad path small x25519
    {
      byte[] x25519 = fromHexToByteArray("df");
      byte[] eddsa = new byte[32];

      try {
        mc.crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("x25519 must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519_to_eddsa sad path small eddsa
    {
      byte[] x25519 =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] eddsa = new byte[1];

      try {
        mc.crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("eddsa must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(25)
  public void test_crypto_x25519_inverse() {
    // crypto_x25519_inverse happy path
    {
      byte[] curve_point =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] private_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] blind_salt = new byte[32];

      mc.crypto_x25519_inverse(blind_salt, private_key, curve_point);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(blind_salt);

      assertEquals(expected, actual, "blind_salt mismatch");
    }

    // crypto_x25519_inverse sad path null blind_salt
    {
      byte[] curve_point =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] private_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] blind_salt = null;

      try {
        mc.crypto_x25519_inverse(blind_salt, private_key, curve_point);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("blind_salt cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_inverse sad path blind_salt invalid length
    {
      byte[] curve_point =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] private_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] blind_salt = new byte[1];

      try {
        mc.crypto_x25519_inverse(blind_salt, private_key, curve_point);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("blind_salt must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(26)
  public void test_crypto_x25519_dirty_small() {
    // crypto_x25519_dirty_small happy path
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = new byte[32];

      mc.crypto_x25519_dirty_small(pk, sk);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(pk);

      assertEquals(expected, actual, "pk mismatch");
    }

    // crypto_x25519_dirty_small sad path null secret key
    {
      byte[] sk = null;
      byte[] pk = new byte[32];

      try {
        mc.crypto_x25519_dirty_small(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("sk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_small sad path null public key
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = null;

      try {
        mc.crypto_x25519_dirty_small(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("pk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_small sk invalid length
    {
      byte[] sk = fromHexToByteArray("00");
      byte[] pk = new byte[32];

      try {
        mc.crypto_x25519_dirty_small(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("sk must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519_dirty_small pk invalid length
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = new byte[1];

      try {
        mc.crypto_x25519_dirty_small(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("pk must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(26)
  public void test_crypto_x25519_dirty_fast() {
    // crypto_x25519_dirty_fast happy path
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = new byte[32];

      mc.crypto_x25519_dirty_fast(pk, sk);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(pk);

      assertEquals(expected, actual, "pk mismatch");
    }

    // crypto_x25519_dirty_fast sad path null secret key
    {
      byte[] sk = null;
      byte[] pk = new byte[32];

      try {
        mc.crypto_x25519_dirty_fast(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("sk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_fast sad path null public key
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = null;

      try {
        mc.crypto_x25519_dirty_fast(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("pk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_fast sk invalid length
    {
      byte[] sk = fromHexToByteArray("00");
      byte[] pk = new byte[32];

      try {
        mc.crypto_x25519_dirty_fast(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("sk must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519_dirty_fast pk invalid length
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = new byte[1];

      try {
        mc.crypto_x25519_dirty_fast(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("pk must be an array of length 32 bytes", e.getMessage());
      }
    }
  }
}
