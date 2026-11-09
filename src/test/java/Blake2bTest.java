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
public class Blake2bTest {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(13)
  public void test_crypto_blake2b() {
    // blake2b with 1 byte hash
    {
      byte[] hash = new byte[1];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b(hash, message);

      String expected = "42";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with 32 byte hash
    {
      byte[] hash = new byte[32];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b(hash, message);

      String expected = "77065d25b622a8251094d869edf6b4e9ba0708a8db1f239cb68e4eeb45851621";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with 64 byte hash
    {
      byte[] hash = new byte[64];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b(hash, message);

      String expected =
          "e998e0dc03ec30eb99bb6bfaaf6618acc620320d7220b3af2b23d112d8e9cb1262f3c0d60d183b1ee7f096d12dae42c958418600214d04f5ed6f5e718be35566";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with 32 byte hash on empty message
    {
      byte[] hash = new byte[32];
      byte[] message = null;

      mc.crypto_blake2b(hash, message);

      String expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with invalid hash size of 0
    {
      byte[] hash = new byte[0];
      byte[] message = null;

      try {
        mc.crypto_blake2b(hash, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must be an array of length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }

    // blake2b with invalid hash size of 65
    {
      byte[] hash = new byte[65];
      byte[] message = null;

      try {
        mc.crypto_blake2b(hash, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must be an array of length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }

    // blake2b with null hash object (exception thrown)
    {
      byte[] hash = null;
      byte[] message = null;

      try {
        mc.crypto_blake2b(hash, message);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }
  }

  @Test
  @Order(14)
  public void test_crypto_blake2b_keyed() {
    // blake2b keyed with 1 byte hash and 1 byte key
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(1);
      ByteBuffer key = fromHexToByteBuffer("00");
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      mc.crypto_blake2b_keyed(hash, key, message);

      String expected = "6a";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with 32 byte hash and 32 byte key
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(32);
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      mc.crypto_blake2b_keyed(hash, key, message);

      String expected = "04b80510e5e9ad383d1a354f2d7cfb7ada56caefa6de9e17989316701975b384";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with 64 byte hash and 64 byte key
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(64);
      ByteBuffer key =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      mc.crypto_blake2b_keyed(hash, key, message);

      String expected =
          "380beaf6ea7cc9365e270ef0e6f3a64fb902acae51dd5512f84259ad2c91f4bc4108db73192a5bbfb0cbcf71e46c3e21aee1c5e860dc96e8eb0b7b8426e6abe9";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with 32 byte hash and null key and message
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(32);
      ByteBuffer key = null;
      ByteBuffer message = null;

      mc.crypto_blake2b_keyed(hash, key, message);

      String expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with 32 byte hash and 32 byte key (inplace)
    {
      ByteBuffer hash =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      mc.crypto_blake2b_keyed(hash, hash, message);

      String expected = "04b80510e5e9ad383d1a354f2d7cfb7ada56caefa6de9e17989316701975b384";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with invalid hash size of 0
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(0);
      ByteBuffer key = null;
      ByteBuffer message = null;

      try {
        mc.crypto_blake2b_keyed(hash, key, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must be a buffer of length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }

    // blake2b keyed with invalid hash size of 65
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(65);
      ByteBuffer key = null;
      ByteBuffer message = null;

      try {
        mc.crypto_blake2b_keyed(hash, key, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must be a buffer of length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }

    // blake2b keyed with null hash object (exception thrown)
    {
      ByteBuffer hash = null;
      ByteBuffer key = null;
      ByteBuffer message = null;

      try {
        mc.crypto_blake2b_keyed(hash, key, message);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }

    // blake2b keyed with invalid key size object (exception thrown)
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(64);
      ByteBuffer key = ByteBuffer.allocateDirect(65);
      ByteBuffer message = null;

      try {
        mc.crypto_blake2b_keyed(hash, key, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "key must be a buffer of length between (inclusive) 0 and 64 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(15)
  public void test_crypto_blake2b_init() throws NoSuchFieldException, IllegalAccessException {
    // blake2b init with 32 byte hash size
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();

      mc.crypto_blake2b_init(ctx, 32);

      Field hashField = Blake2b_ctx.class.getDeclaredField("hash");
      Field input_offsetField = Blake2b_ctx.class.getDeclaredField("input_offset");
      Field inputField = Blake2b_ctx.class.getDeclaredField("input");
      Field input_idxField = Blake2b_ctx.class.getDeclaredField("input_idx");
      Field hash_sizeField = Blake2b_ctx.class.getDeclaredField("hash_size");

      hashField.setAccessible(true);
      input_offsetField.setAccessible(true);
      inputField.setAccessible(true);
      input_idxField.setAccessible(true);
      hash_sizeField.setAccessible(true);

      long[] hash = (long[]) hashField.get(ctx);
      long[] input_offset = (long[]) input_offsetField.get(ctx);
      long[] input = (long[]) inputField.get(ctx);
      long input_idx = (long) input_idxField.get(ctx);
      long hash_size = (long) hash_sizeField.get(ctx);

      long[] hash_expected =
          new long[] {
            fromHexLEToLong("28c9bdf267e6096a"),
            fromHexLEToLong("3ba7ca8485ae67bb"),
            fromHexLEToLong("2bf894fe72f36e3c"),
            fromHexLEToLong("f1361d5f3af54fa5"),
            fromHexLEToLong("d182e6ad7f520e51"),
            fromHexLEToLong("1f6c3e2b8c68059b"),
            fromHexLEToLong("6bbd41fbabd9831f"),
            fromHexLEToLong("79217e1319cde05b"),
          };

      long[] input_offset_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"), fromHexLEToLong("0000000000000000"),
          };

      long[] input_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
          };

      long input_idx_expected = fromHexLEToLong("0000000000000000");
      long hash_size_expected = fromHexLEToLong("2000000000000000");

      assertArrayEquals(hash_expected, hash, "hash mismatch");
      assertArrayEquals(input_offset_expected, input_offset, "input_offset mismatch");
      assertArrayEquals(input_expected, input, "input mismatch");
      assertEquals(input_idx_expected, input_idx, "input_idx mismatch");
      assertEquals(hash_size_expected, hash_size, "hash_size mismatch");
    }

    // blake2b init with null ctx
    {
      Blake2b_ctx ctx = null;

      try {
        mc.crypto_blake2b_init(ctx, 32);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("ctx cannot be null", e.getMessage());
      }
    }

    // blake2b init with invalid hash size
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();

      try {
        mc.crypto_blake2b_init(ctx, 65);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash_size must be a length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(16)
  public void test_crypto_blake2b_update() throws NoSuchFieldException, IllegalAccessException {
    // blake2b update with 32 byte hash size and 256 byte message
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();
      byte[] message =
          fromHexToByteArray(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                  + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                  + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                  + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                  + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                  + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

      mc.crypto_blake2b_init(ctx, 32);
      mc.crypto_blake2b_update(ctx, message);

      Field hashField = Blake2b_ctx.class.getDeclaredField("hash");
      Field input_offsetField = Blake2b_ctx.class.getDeclaredField("input_offset");
      Field inputField = Blake2b_ctx.class.getDeclaredField("input");
      Field input_idxField = Blake2b_ctx.class.getDeclaredField("input_idx");
      Field hash_sizeField = Blake2b_ctx.class.getDeclaredField("hash_size");

      hashField.setAccessible(true);
      input_offsetField.setAccessible(true);
      inputField.setAccessible(true);
      input_idxField.setAccessible(true);
      hash_sizeField.setAccessible(true);

      long[] hash = (long[]) hashField.get(ctx);
      long[] input_offset = (long[]) input_offsetField.get(ctx);
      long[] input = (long[]) inputField.get(ctx);
      long input_idx = (long) input_idxField.get(ctx);
      long hash_size = (long) hash_sizeField.get(ctx);

      long[] hash_expected =
          new long[] {
            fromHexLEToLong("21dccc8883c3da12"),
            fromHexLEToLong("d1e501e4b85be497"),
            fromHexLEToLong("eb58f03bd95088fa"),
            fromHexLEToLong("42d699ee4c933134"),
            fromHexLEToLong("92cbb67014beaa75"),
            fromHexLEToLong("368c5d990c25add4"),
            fromHexLEToLong("f775b1edbbb081a4"),
            fromHexLEToLong("97e2e005c5348f3d"),
          };

      long[] input_offset_expected =
          new long[] {
            fromHexLEToLong("8000000000000000"), fromHexLEToLong("0000000000000000"),
          };

      long[] input_expected =
          new long[] {
            fromHexLEToLong("8081828384858687"),
            fromHexLEToLong("88898a8b8c8d8e8f"),
            fromHexLEToLong("9091929394959697"),
            fromHexLEToLong("98999a9b9c9d9e9f"),
            fromHexLEToLong("a0a1a2a3a4a5a6a7"),
            fromHexLEToLong("a8a9aaabacadaeaf"),
            fromHexLEToLong("b0b1b2b3b4b5b6b7"),
            fromHexLEToLong("b8b9babbbcbdbebf"),
            fromHexLEToLong("c0c1c2c3c4c5c6c7"),
            fromHexLEToLong("c8c9cacbcccdcecf"),
            fromHexLEToLong("d0d1d2d3d4d5d6d7"),
            fromHexLEToLong("d8d9dadbdcdddedf"),
            fromHexLEToLong("e0e1e2e3e4e5e6e7"),
            fromHexLEToLong("e8e9eaebecedeeef"),
            fromHexLEToLong("f0f1f2f3f4f5f6f7"),
            fromHexLEToLong("f8f9fafbfcfdfeff"),
          };

      long input_idx_expected = fromHexLEToLong("8000000000000000");
      long hash_size_expected = fromHexLEToLong("2000000000000000");

      assertArrayEquals(hash_expected, hash, "hash mismatch");
      assertArrayEquals(input_offset_expected, input_offset, "input_offset mismatch");
      assertArrayEquals(input_expected, input, "input mismatch");
      assertEquals(input_idx_expected, input_idx, "input_idx mismatch");
      assertEquals(hash_size_expected, hash_size, "hash_size mismatch");
    }

    // blake2b update with null ctx
    {
      Blake2b_ctx ctx = null;

      try {
        mc.crypto_blake2b_update(ctx, null);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("ctx cannot be null", e.getMessage());
      }
    }
  }

  @Test
  @Order(17)
  public void test_crypto_blake2b_final() throws NoSuchFieldException, IllegalAccessException {
    // blake2b final with 32 byte hash size and 8 byte message
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();
      byte[] hash = new byte[32];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b_init(ctx, hash.length);
      mc.crypto_blake2b_update(ctx, message);
      mc.crypto_blake2b_final(ctx, hash);

      String expected = "77065d25b622a8251094d869edf6b4e9ba0708a8db1f239cb68e4eeb45851621";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");

      Field hashField = Blake2b_ctx.class.getDeclaredField("hash");
      Field input_offsetField = Blake2b_ctx.class.getDeclaredField("input_offset");
      Field inputField = Blake2b_ctx.class.getDeclaredField("input");
      Field input_idxField = Blake2b_ctx.class.getDeclaredField("input_idx");
      Field hash_sizeField = Blake2b_ctx.class.getDeclaredField("hash_size");

      hashField.setAccessible(true);
      input_offsetField.setAccessible(true);
      inputField.setAccessible(true);
      input_idxField.setAccessible(true);
      hash_sizeField.setAccessible(true);

      long[] hashArray = (long[]) hashField.get(ctx);
      long[] input_offset = (long[]) input_offsetField.get(ctx);
      long[] input = (long[]) inputField.get(ctx);
      long input_idx = (long) input_idxField.get(ctx);
      long hash_size = (long) hash_sizeField.get(ctx);

      long[] hash_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
          };

      long[] input_offset_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"), fromHexLEToLong("0000000000000000"),
          };

      long[] input_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
          };

      long input_idx_expected = fromHexLEToLong("0000000000000000");
      long hash_size_expected = fromHexLEToLong("0000000000000000");

      assertArrayEquals(hash_expected, hashArray, "hash mismatch");
      assertArrayEquals(input_offset_expected, input_offset, "input_offset mismatch");
      assertArrayEquals(input_expected, input, "input mismatch");
      assertEquals(input_idx_expected, input_idx, "input_idx mismatch");
      assertEquals(hash_size_expected, hash_size, "hash_size mismatch");
    }

    // blake2b final with incorrect hash size
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();
      byte[] hash = new byte[32];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b_init(ctx, 2 * hash.length);
      mc.crypto_blake2b_update(ctx, message);

      try {
        mc.crypto_blake2b_final(ctx, hash);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("hash must be of length 64 bytes", e.getMessage());
      }
    }

    // blake2b final with null ctx
    {
      Blake2b_ctx ctx = null;
      byte[] hash = new byte[32];

      try {
        mc.crypto_blake2b_final(ctx, null);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("ctx cannot be null", e.getMessage());
      }
    }

    // blake2b final with null hash
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();

      try {
        mc.crypto_blake2b_final(ctx, null);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }
  }

  @Test
  @Order(18)
  public void test_crypto_wipe_blake2b_ctx() throws NoSuchFieldException, IllegalAccessException {
    Blake2b_ctx ctx = mc.new Blake2b_ctx();

    mc.crypto_blake2b_init(ctx, 32);

    {
      Field hashField = Blake2b_ctx.class.getDeclaredField("hash");
      Field input_offsetField = Blake2b_ctx.class.getDeclaredField("input_offset");
      Field inputField = Blake2b_ctx.class.getDeclaredField("input");
      Field input_idxField = Blake2b_ctx.class.getDeclaredField("input_idx");
      Field hash_sizeField = Blake2b_ctx.class.getDeclaredField("hash_size");

      hashField.setAccessible(true);
      input_offsetField.setAccessible(true);
      inputField.setAccessible(true);
      input_idxField.setAccessible(true);
      hash_sizeField.setAccessible(true);

      long[] hash = (long[]) hashField.get(ctx);
      long[] input_offset = (long[]) input_offsetField.get(ctx);
      long[] input = (long[]) inputField.get(ctx);
      long input_idx = (long) input_idxField.get(ctx);
      long hash_size = (long) hash_sizeField.get(ctx);

      long[] hash_expected =
          new long[] {
            fromHexLEToLong("28c9bdf267e6096a"),
            fromHexLEToLong("3ba7ca8485ae67bb"),
            fromHexLEToLong("2bf894fe72f36e3c"),
            fromHexLEToLong("f1361d5f3af54fa5"),
            fromHexLEToLong("d182e6ad7f520e51"),
            fromHexLEToLong("1f6c3e2b8c68059b"),
            fromHexLEToLong("6bbd41fbabd9831f"),
            fromHexLEToLong("79217e1319cde05b"),
          };

      long[] input_offset_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"), fromHexLEToLong("0000000000000000"),
          };

      long[] input_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
          };

      long input_idx_expected = fromHexLEToLong("0000000000000000");
      long hash_size_expected = fromHexLEToLong("2000000000000000");

      assertArrayEquals(hash_expected, hash, "hash mismatch");
      assertArrayEquals(input_offset_expected, input_offset, "input_offset mismatch");
      assertArrayEquals(input_expected, input, "input mismatch");
      assertEquals(input_idx_expected, input_idx, "input_idx mismatch");
      assertEquals(hash_size_expected, hash_size, "hash_size mismatch");
    }

    mc.crypto_wipe(ctx);

    {
      Field hashField = Blake2b_ctx.class.getDeclaredField("hash");
      Field input_offsetField = Blake2b_ctx.class.getDeclaredField("input_offset");
      Field inputField = Blake2b_ctx.class.getDeclaredField("input");
      Field input_idxField = Blake2b_ctx.class.getDeclaredField("input_idx");
      Field hash_sizeField = Blake2b_ctx.class.getDeclaredField("hash_size");

      hashField.setAccessible(true);
      input_offsetField.setAccessible(true);
      inputField.setAccessible(true);
      input_idxField.setAccessible(true);
      hash_sizeField.setAccessible(true);

      long[] hash = (long[]) hashField.get(ctx);
      long[] input_offset = (long[]) input_offsetField.get(ctx);
      long[] input = (long[]) inputField.get(ctx);
      long input_idx = (long) input_idxField.get(ctx);
      long hash_size = (long) hash_sizeField.get(ctx);

      long[] hash_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
          };

      long[] input_offset_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"), fromHexLEToLong("0000000000000000"),
          };

      long[] input_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
          };

      long input_idx_expected = fromHexLEToLong("0000000000000000");
      long hash_size_expected = fromHexLEToLong("0000000000000000");

      assertArrayEquals(hash_expected, hash, "hash mismatch");
      assertArrayEquals(input_offset_expected, input_offset, "input_offset mismatch");
      assertArrayEquals(input_expected, input, "input mismatch");
      assertEquals(input_idx_expected, input_idx, "input_idx mismatch");
      assertEquals(hash_size_expected, hash_size, "hash_size mismatch");
    }
  }
}
