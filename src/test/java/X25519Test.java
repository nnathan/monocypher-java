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
public class X25519Test {

  @Test
  @Order(22)
  public void test_crypto_x25519_public_key() {
    // crypto_x25519_public_key happy path
    {
      ByteBuffer secret_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer public_key = ByteBuffer.allocateDirect(32);

      crypto_x25519_public_key(public_key, secret_key);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(public_key);

      assertEquals(expected, actual, "public_key mismatch");
    }

    // crypto_x25519_public_key sad path null secret key
    {
      ByteBuffer secret_key = null;
      ByteBuffer public_key = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519_public_key(public_key, secret_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("secret_key cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_public_key sad path null public key
    {
      ByteBuffer secret_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer public_key = null;

      try {
        crypto_x25519_public_key(public_key, secret_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("public_key cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_public_key secret_key invalid length
    {
      ByteBuffer secret_key = fromHexToByteBuffer("00");
      ByteBuffer public_key = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519_public_key(public_key, secret_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("secret_key must have exactly 32 bytes remaining", e.getMessage());
      }
    }

    // crypto_x25519_public_key public_key invalid length
    {
      ByteBuffer secret_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer public_key = ByteBuffer.allocateDirect(1);

      try {
        crypto_x25519_public_key(public_key, secret_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("public_key must have exactly 32 bytes remaining", e.getMessage());
      }
    }
  }

  @Test
  @Order(23)
  public void test_crypto_x25519() {
    // crypto_x25519 happy path
    {
      ByteBuffer your_secret_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer their_public_key =
          fromHexToByteBuffer("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      ByteBuffer raw_shared_secret = ByteBuffer.allocateDirect(32);

      crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);

      String expected = "df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64";
      String actual = toHex(raw_shared_secret);

      assertEquals(expected, actual, "raw_shared_secret mismatch");
    }

    // crypto_x25519 sad path null secret key
    {
      ByteBuffer your_secret_key = null;
      ByteBuffer their_public_key =
          fromHexToByteBuffer("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      ByteBuffer raw_shared_secret = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("your_secret_key cannot be null", e.getMessage());
      }
    }

    // crypto_x25519 sad path null public key
    {
      ByteBuffer your_secret_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer their_public_key = null;
      ByteBuffer raw_shared_secret = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("their_public_key cannot be null", e.getMessage());
      }
    }
    //
    // crypto_x25519 sad path raw shared secret
    {
      ByteBuffer your_secret_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer their_public_key =
          fromHexToByteBuffer("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      ByteBuffer raw_shared_secret = null;

      try {
        crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("raw_shared_secret cannot be null", e.getMessage());
      }
    }

    // crypto_x25519 secret_key invalid length
    {
      ByteBuffer your_secret_key = fromHexToByteBuffer("00");
      ByteBuffer their_public_key =
          fromHexToByteBuffer("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      ByteBuffer raw_shared_secret = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("your_secret_key must have exactly 32 bytes remaining", e.getMessage());
      }
    }

    // crypto_x25519 public_key invalid length
    {
      ByteBuffer your_secret_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer their_public_key = fromHexToByteBuffer("8f");
      ByteBuffer raw_shared_secret = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("their_public_key must have exactly 32 bytes remaining", e.getMessage());
      }
    }

    // crypto_x25519 public_key invalid length
    {
      ByteBuffer your_secret_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer their_public_key =
          fromHexToByteBuffer("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      ByteBuffer raw_shared_secret = ByteBuffer.allocateDirect(1);

      try {
        crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("raw_shared_secret must have exactly 32 bytes remaining", e.getMessage());
      }
    }
  }

  @Test
  @Order(24)
  public void test_crypto_x25519_to_eddsa() {
    // crypto_x25519_to_eddsa happy path
    {
      ByteBuffer x25519 =
          fromHexToByteBuffer("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      ByteBuffer eddsa = ByteBuffer.allocateDirect(32);

      crypto_x25519_to_eddsa(eddsa, x25519);

      String expected = "752f61d0e2d2e7577f2aafa6a92298b86bb32521d6d7f109dcd834fc41f2a72a";
      String actual = toHex(eddsa);

      assertEquals(expected, actual, "raw_shared_secret mismatch");
    }

    // crypto_x25519_to_eddsa sad path null x25519
    {
      ByteBuffer x25519 = null;
      ByteBuffer eddsa = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("x25519 cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_to_eddsa sad path null eddsa
    {
      ByteBuffer x25519 =
          fromHexToByteBuffer("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      ByteBuffer eddsa = null;

      try {
        crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("eddsa cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_to_eddsa sad path small x25519
    {
      ByteBuffer x25519 = fromHexToByteBuffer("df");
      ByteBuffer eddsa = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("x25519 must have exactly 32 bytes remaining", e.getMessage());
      }
    }

    // crypto_x25519_to_eddsa sad path small eddsa
    {
      ByteBuffer x25519 =
          fromHexToByteBuffer("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      ByteBuffer eddsa = ByteBuffer.allocateDirect(1);

      try {
        crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("eddsa must have exactly 32 bytes remaining", e.getMessage());
      }
    }
  }

  @Test
  @Order(25)
  public void test_crypto_x25519_inverse() {
    // crypto_x25519_inverse happy path
    {
      ByteBuffer curve_point =
          fromHexToByteBuffer("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      ByteBuffer private_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer blind_salt = ByteBuffer.allocateDirect(32);

      crypto_x25519_inverse(blind_salt, private_key, curve_point);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(blind_salt);

      assertEquals(expected, actual, "blind_salt mismatch");
    }

    // crypto_x25519_inverse sad path null blind_salt
    {
      ByteBuffer curve_point =
          fromHexToByteBuffer("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      ByteBuffer private_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer blind_salt = null;

      try {
        crypto_x25519_inverse(blind_salt, private_key, curve_point);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("blind_salt cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_inverse sad path blind_salt invalid length
    {
      ByteBuffer curve_point =
          fromHexToByteBuffer("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      ByteBuffer private_key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer blind_salt = ByteBuffer.allocateDirect(1);

      try {
        crypto_x25519_inverse(blind_salt, private_key, curve_point);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("blind_salt must have exactly 32 bytes remaining", e.getMessage());
      }
    }
  }

  @Test
  @Order(26)
  public void test_crypto_x25519_dirty_small() {
    // crypto_x25519_dirty_small happy path
    {
      ByteBuffer sk =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer pk = ByteBuffer.allocateDirect(32);

      crypto_x25519_dirty_small(pk, sk);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(pk);

      assertEquals(expected, actual, "pk mismatch");
    }

    // crypto_x25519_dirty_small sad path null secret key
    {
      ByteBuffer sk = null;
      ByteBuffer pk = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519_dirty_small(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("sk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_small sad path null public key
    {
      ByteBuffer sk =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer pk = null;

      try {
        crypto_x25519_dirty_small(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("pk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_small sk invalid length
    {
      ByteBuffer sk = fromHexToByteBuffer("00");
      ByteBuffer pk = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519_dirty_small(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("sk must have exactly 32 bytes remaining", e.getMessage());
      }
    }

    // crypto_x25519_dirty_small pk invalid length
    {
      ByteBuffer sk =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer pk = ByteBuffer.allocateDirect(1);

      try {
        crypto_x25519_dirty_small(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("pk must have exactly 32 bytes remaining", e.getMessage());
      }
    }
  }

  @Test
  @Order(26)
  public void test_crypto_x25519_dirty_fast() {
    // crypto_x25519_dirty_fast happy path
    {
      ByteBuffer sk =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer pk = ByteBuffer.allocateDirect(32);

      crypto_x25519_dirty_fast(pk, sk);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(pk);

      assertEquals(expected, actual, "pk mismatch");
    }

    // crypto_x25519_dirty_fast sad path null secret key
    {
      ByteBuffer sk = null;
      ByteBuffer pk = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519_dirty_fast(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("sk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_fast sad path null public key
    {
      ByteBuffer sk =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer pk = null;

      try {
        crypto_x25519_dirty_fast(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("pk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_fast sk invalid length
    {
      ByteBuffer sk = fromHexToByteBuffer("00");
      ByteBuffer pk = ByteBuffer.allocateDirect(32);

      try {
        crypto_x25519_dirty_fast(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("sk must have exactly 32 bytes remaining", e.getMessage());
      }
    }

    // crypto_x25519_dirty_fast pk invalid length
    {
      ByteBuffer sk =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer pk = ByteBuffer.allocateDirect(1);

      try {
        crypto_x25519_dirty_fast(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("pk must have exactly 32 bytes remaining", e.getMessage());
      }
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
  public void test_x25519_rejects_bad_arguments() {
    assertThrows(IllegalArgumentException.class, () -> crypto_x25519_public_key(buf(32), buf(31)));
    assertThrows(
        IllegalArgumentException.class,
        () -> crypto_x25519_public_key(buf(32).asReadOnlyBuffer(), buf(32)));
    assertThrows(
        IllegalArgumentException.class,
        () -> crypto_x25519_public_key(buf(32), ByteBuffer.allocate(32)));
    assertThrows(IllegalArgumentException.class, () -> crypto_x25519(buf(32), buf(32), buf(33)));
    assertThrows(
        IllegalArgumentException.class, () -> crypto_x25519_inverse(buf(32), buf(32), buf(31)));
    assertThrows(IllegalArgumentException.class, () -> crypto_x25519_dirty_fast(buf(31), buf(32)));
  }

  @Test
  @Order(101)
  public void test_x25519_key_exchange_agrees_and_honours_position() {
    ByteBuffer a_sk = counting(32, 1);
    ByteBuffer b_sk = counting(32, 7);
    ByteBuffer a_pk = buf(32);
    ByteBuffer b_pk = buf(32);
    crypto_x25519_public_key(a_pk, a_sk);
    crypto_x25519_public_key(b_pk, b_sk);

    ByteBuffer a_shared = buf(48);
    a_shared.position(8).limit(40);
    ByteBuffer b_shared = buf(32);
    crypto_x25519(a_shared, a_sk, b_pk);
    crypto_x25519(b_shared, b_sk, a_pk);
    assertEquals(8, a_shared.position());
    assertEquals(toHex(b_shared), toHex(a_shared));
  }
}
