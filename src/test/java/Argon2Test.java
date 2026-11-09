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
public class Argon2Test {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(19)
  public void test_crypto_argon2() {
    // argon2 happy path
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc
          .new Argon2_inputs(
              fromHexToByteArray("00010203040506070809"),
              fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext = mc.new Argon2_extras(null, null);

      byte[] hash = new byte[32];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "36ef27b9a646795126c9e41aa5bef66a50556bd8c84e73412856492529f8373a";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, empty password
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_I, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext = mc.new Argon2_extras(null, null);

      byte[] hash = new byte[32];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "4d0a33ee95d4dcd01cb8be2ad03c5babde3a20d4306a2348f7bceac3907c2b55";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, empty password, with key and ad
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[32];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "7ff21ad59ca877d7c2f78cd30b1d9ff2e2a23b65a058e2ea145d1770bfb638f9";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, 1 byte hash, empty password, with key and ad
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[1];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "b8";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, 0 byte hash, empty password, with key and ad
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[0];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 sad path, null hash
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = null;

      try {
        mc.crypto_argon2(hash, cfg, inp, ext);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }
    //
    // argon2 sad path, null salt
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp = mc.new Argon2_inputs(null, null);
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[32];

      try {
        mc.crypto_argon2(hash, cfg, inp, ext);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("salt cannot be null", e.getMessage());
      }
    }

    // argon2 sad path, small salt
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp = mc.new Argon2_inputs(null, fromHexToByteArray("00"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[32];

      try {
        mc.crypto_argon2(hash, cfg, inp, ext);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("salt needs to be at least 8 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(20)
  public void test_crypto_wipe_argon2_inputs() throws NoSuchFieldException, IllegalAccessException {
    Argon2_inputs input =
        mc.new Argon2_inputs(fromHexToByteArray("aabbccdd"), fromHexToByteArray("aabbccdd"));

    {
      Field passField = Argon2_inputs.class.getDeclaredField("pass");
      Field saltField = Argon2_inputs.class.getDeclaredField("salt");

      passField.setAccessible(true);
      saltField.setAccessible(true);

      byte[] pass = (byte[]) passField.get(input);
      byte[] salt = (byte[]) saltField.get(input);

      byte[] pass_expected = fromHexToByteArray("aabbccdd");
      byte[] salt_expected = fromHexToByteArray("aabbccdd");

      assertArrayEquals(pass_expected, pass, "pass mismatch");
      assertArrayEquals(salt_expected, salt, "salt mismatch");
    }

    mc.crypto_wipe(input);

    {
      Field passField = Argon2_inputs.class.getDeclaredField("pass");
      Field saltField = Argon2_inputs.class.getDeclaredField("salt");

      passField.setAccessible(true);
      saltField.setAccessible(true);

      byte[] pass = (byte[]) passField.get(input);
      byte[] salt = (byte[]) saltField.get(input);

      byte[] pass_expected = fromHexToByteArray("00000000");
      byte[] salt_expected = fromHexToByteArray("00000000");

      assertArrayEquals(pass_expected, pass, "pass mismatch");
      assertArrayEquals(salt_expected, salt, "salt mismatch");
    }
  }

  @Test
  @Order(21)
  public void test_crypto_wipe_argon2_extras() throws NoSuchFieldException, IllegalAccessException {
    Argon2_extras extra =
        mc.new Argon2_extras(fromHexToByteArray("aabbccdd"), fromHexToByteArray("aabbccdd"));

    {
      Field keyField = Argon2_extras.class.getDeclaredField("key");
      Field adField = Argon2_extras.class.getDeclaredField("ad");

      keyField.setAccessible(true);
      adField.setAccessible(true);

      byte[] key = (byte[]) keyField.get(extra);
      byte[] ad = (byte[]) adField.get(extra);

      byte[] key_expected = fromHexToByteArray("aabbccdd");
      byte[] ad_expected = fromHexToByteArray("aabbccdd");

      assertArrayEquals(key_expected, key, "key mismatch");
      assertArrayEquals(ad_expected, ad, "ad mismatch");
    }

    mc.crypto_wipe(extra);

    {
      Field keyField = Argon2_extras.class.getDeclaredField("key");
      Field adField = Argon2_extras.class.getDeclaredField("ad");

      keyField.setAccessible(true);
      adField.setAccessible(true);

      byte[] key = (byte[]) keyField.get(extra);
      byte[] ad = (byte[]) adField.get(extra);

      byte[] key_expected = fromHexToByteArray("00000000");
      byte[] ad_expected = fromHexToByteArray("00000000");

      assertArrayEquals(key_expected, key, "key mismatch");
      assertArrayEquals(ad_expected, ad, "ad mismatch");
    }
  }
}
