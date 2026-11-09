import static org.junit.jupiter.api.Assertions.*;
import static net.lastninja.monocypher.Monocypher.*;
import static net.lastninja.monocypher.TestUtil.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import net.lastninja.monocypher.Monocypher;
import net.lastninja.monocypher.Monocypher.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Blake2bTest {

  private static void assertBlake2bCtx(
      Blake2b_ctx ctx,
      long[] hash,
      long[] input_offset,
      long[] input,
      long input_idx,
      long hash_size) {
    // input_idx and hash_size are size_t, so their width depends on the platform.
    int sizeT = (ctxStructSize(ctx) - 26 * 8) / 2;
    ByteBuffer expected = ByteBuffer.allocate(26 * 8 + 2 * sizeT).order(ByteOrder.nativeOrder());
    for (long v : hash) expected.putLong(v);
    for (long v : input_offset) expected.putLong(v);
    for (long v : input) expected.putLong(v);
    if (sizeT == 8) {
      expected.putLong(input_idx).putLong(hash_size);
    } else {
      expected.putInt((int) input_idx).putInt((int) hash_size);
    }
    assertTrue(ctxContains(ctx, expected.array()), "ctx does not hold the expected state");
  }

  @Test
  @Order(13)
  public void test_crypto_blake2b() {
    // blake2b with 1 byte hash
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(1);
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      crypto_blake2b(hash, message);

      String expected = "42";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with 32 byte hash
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(32);
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      crypto_blake2b(hash, message);

      String expected = "77065d25b622a8251094d869edf6b4e9ba0708a8db1f239cb68e4eeb45851621";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with 64 byte hash
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(64);
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      crypto_blake2b(hash, message);

      String expected =
          "e998e0dc03ec30eb99bb6bfaaf6618acc620320d7220b3af2b23d112d8e9cb1262f3c0d60d183b1ee7f096d12dae42c958418600214d04f5ed6f5e718be35566";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with 32 byte hash on empty message
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(32);
      ByteBuffer message = null;

      crypto_blake2b(hash, message);

      String expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with invalid hash size of 0
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(0);
      ByteBuffer message = null;

      try {
        crypto_blake2b(hash, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must have between 1 and 64 bytes remaining", e.getMessage());
      }
    }

    // blake2b with invalid hash size of 65
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(65);
      ByteBuffer message = null;

      try {
        crypto_blake2b(hash, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must have between 1 and 64 bytes remaining", e.getMessage());
      }
    }

    // blake2b with null hash object (exception thrown)
    {
      ByteBuffer hash = null;
      ByteBuffer message = null;

      try {
        crypto_blake2b(hash, message);
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

      crypto_blake2b_keyed(hash, key, message);

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

      crypto_blake2b_keyed(hash, key, message);

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

      crypto_blake2b_keyed(hash, key, message);

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

      crypto_blake2b_keyed(hash, key, message);

      String expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with 32 byte hash and 32 byte key (inplace)
    {
      ByteBuffer hash =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      crypto_blake2b_keyed(hash, hash, message);

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
        crypto_blake2b_keyed(hash, key, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must have between 1 and 64 bytes remaining", e.getMessage());
      }
    }

    // blake2b keyed with invalid hash size of 65
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(65);
      ByteBuffer key = null;
      ByteBuffer message = null;

      try {
        crypto_blake2b_keyed(hash, key, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must have between 1 and 64 bytes remaining", e.getMessage());
      }
    }

    // blake2b keyed with null hash object (exception thrown)
    {
      ByteBuffer hash = null;
      ByteBuffer key = null;
      ByteBuffer message = null;

      try {
        crypto_blake2b_keyed(hash, key, message);
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
        crypto_blake2b_keyed(hash, key, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "key must have at most 64 bytes remaining", e.getMessage());
      }
    }
  }

  @Test
  @Order(15)
  public void test_crypto_blake2b_init() {
    // blake2b init with 32 byte hash size
    {
      Blake2b_ctx ctx = new Blake2b_ctx();

      crypto_blake2b_init(ctx, 32);




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

      assertBlake2bCtx(
          ctx, hash_expected, input_offset_expected, input_expected, input_idx_expected, hash_size_expected);
    }

    // blake2b init with null ctx
    {
      Blake2b_ctx ctx = null;

      try {
        crypto_blake2b_init(ctx, 32);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("ctx cannot be null", e.getMessage());
      }
    }

    // blake2b init with invalid hash size
    {
      Blake2b_ctx ctx = new Blake2b_ctx();

      try {
        crypto_blake2b_init(ctx, 65);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash_size must be between 1 and 64", e.getMessage());
      }
    }
  }

  @Test
  @Order(16)
  public void test_crypto_blake2b_update() {
    // blake2b update with 32 byte hash size and 256 byte message
    {
      Blake2b_ctx ctx = new Blake2b_ctx();
      ByteBuffer message =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                  + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                  + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                  + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                  + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                  + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

      crypto_blake2b_init(ctx, 32);
      crypto_blake2b_update(ctx, message);




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

      assertBlake2bCtx(
          ctx, hash_expected, input_offset_expected, input_expected, input_idx_expected, hash_size_expected);
    }

    // blake2b update with null ctx
    {
      Blake2b_ctx ctx = null;

      try {
        crypto_blake2b_update(ctx, null);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("ctx cannot be null", e.getMessage());
      }
    }
  }

  @Test
  @Order(17)
  public void test_crypto_blake2b_final() {
    // blake2b final with 32 byte hash size and 8 byte message
    {
      Blake2b_ctx ctx = new Blake2b_ctx();
      ByteBuffer hash = ByteBuffer.allocateDirect(32);
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      crypto_blake2b_init(ctx, hash.remaining());
      crypto_blake2b_update(ctx, message);
      crypto_blake2b_final(ctx, hash);

      String expected = "77065d25b622a8251094d869edf6b4e9ba0708a8db1f239cb68e4eeb45851621";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");




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

      // Monocypher wipes the context in final, and the binding marks it unusable.
      assertTrue(ctxIsZero(ctx), "ctx not wiped by final");
    }

    // blake2b final with incorrect hash size
    {
      Blake2b_ctx ctx = new Blake2b_ctx();
      ByteBuffer hash = ByteBuffer.allocateDirect(32);
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      crypto_blake2b_init(ctx, 2 * hash.remaining());
      crypto_blake2b_update(ctx, message);

      try {
        crypto_blake2b_final(ctx, hash);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("hash must have exactly the hash_size given to init remaining", e.getMessage());
      }
    }

    // blake2b final with null ctx
    {
      Blake2b_ctx ctx = null;
      ByteBuffer hash = ByteBuffer.allocateDirect(32);

      try {
        crypto_blake2b_final(ctx, null);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("ctx cannot be null", e.getMessage());
      }
    }

    // blake2b final with null hash
    {
      Blake2b_ctx ctx = new Blake2b_ctx();
      crypto_blake2b_init(ctx, 32);

      try {
        crypto_blake2b_final(ctx, null);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }
  }

  @Test
  @Order(18)
  public void test_crypto_wipe_blake2b_ctx() {
    Blake2b_ctx ctx = new Blake2b_ctx();

    crypto_blake2b_init(ctx, 32);

    {



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

      assertBlake2bCtx(
          ctx, hash_expected, input_offset_expected, input_expected, input_idx_expected, hash_size_expected);
    }

    crypto_wipe(ctx);

    {



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

      assertBlake2bCtx(
          ctx, hash_expected, input_offset_expected, input_expected, input_idx_expected, hash_size_expected);
    }
  }

  private static ByteBuffer buf(int len) {
    return ByteBuffer.allocateDirect(len);
  }

  private static IllegalArgumentException assertIae(org.junit.jupiter.api.function.Executable e) {
    return assertThrows(IllegalArgumentException.class, e);
  }

  private static String hashOf(ByteBuffer message) {
    ByteBuffer hash = buf(64);
    crypto_blake2b(hash, message);
    return toHex(hash);
  }

  @Test
  @Order(100)
  public void test_keyed_checks_the_key_not_the_hash() {
    IllegalArgumentException e =
        assertIae(() -> crypto_blake2b_keyed(buf(64), ByteBuffer.allocate(16), buf(8)));
    assertEquals("key must be a direct ByteBuffer", e.getMessage());
    assertEquals(
        "key must have at most 64 bytes remaining",
        assertIae(() -> crypto_blake2b_keyed(buf(64), buf(65), buf(8))).getMessage());
  }

  @Test
  @Order(101)
  public void test_streaming_matches_one_shot_and_keyed_init() {
    ByteBuffer message = buf(300);
    for (int i = 0; i < 300; i++) message.put(i, (byte) i);

    try (Blake2b_ctx ctx = new Blake2b_ctx()) {
      ByteBuffer streamed = buf(64);
      crypto_blake2b_init(ctx, 64);
      for (int i = 0; i < 300; i += 100) {
        ByteBuffer chunk = message.duplicate();
        chunk.position(i).limit(i + 100);
        crypto_blake2b_update(ctx, chunk);
      }
      crypto_blake2b_final(ctx, streamed);
      assertEquals(hashOf(message), toHex(streamed));
    }

    ByteBuffer key = buf(32);
    key.put(0, (byte) 1);
    ByteBuffer expected = buf(32);
    crypto_blake2b_keyed(expected, key, message);
    try (Blake2b_ctx ctx = new Blake2b_ctx()) {
      ByteBuffer actual = buf(32);
      crypto_blake2b_keyed_init(ctx, 32, key);
      crypto_blake2b_update(ctx, message);
      crypto_blake2b_final(ctx, actual);
      assertEquals(toHex(expected), toHex(actual));
    }
  }

  @Test
  @Order(102)
  public void test_ctx_unusable_before_init_and_after_final() {
    Blake2b_ctx ctx = new Blake2b_ctx();
    assertThrows(IllegalStateException.class, () -> crypto_blake2b_update(ctx, buf(8)));

    crypto_blake2b_init(ctx, 32);
    crypto_blake2b_update(ctx, buf(8));
    crypto_blake2b_final(ctx, buf(32));

    assertTrue(ctxIsZero(ctx), "ctx not wiped by final");
    assertThrows(IllegalStateException.class, () -> crypto_blake2b_update(ctx, buf(8)));
    assertThrows(IllegalStateException.class, () -> crypto_blake2b_final(ctx, buf(32)));

    crypto_blake2b_init(ctx, 32);
    crypto_blake2b_update(ctx, buf(8));
  }

  @Test
  @Order(103)
  public void test_rejects_bad_sizes_and_buffers() {
    Blake2b_ctx ctx = new Blake2b_ctx();
    assertIae(() -> crypto_blake2b_init(ctx, 0));
    assertIae(() -> crypto_blake2b_init(ctx, 65));
    assertIae(() -> crypto_blake2b_keyed_init(ctx, 32, buf(65)));
    assertIae(() -> crypto_blake2b(buf(0), buf(8)));
    assertIae(() -> crypto_blake2b(buf(65), buf(8)));
    assertIae(() -> crypto_blake2b(buf(32).asReadOnlyBuffer(), buf(8)));
    assertIae(() -> crypto_blake2b(buf(32), ByteBuffer.allocate(8)));

    crypto_blake2b_init(ctx, 32);
    assertIae(() -> crypto_blake2b_final(ctx, buf(64)));
  }

  @Test
  @Order(104)
  public void test_hash_may_overlap_message_like_upstream() {
    ByteBuffer shared = buf(256);
    for (int i = 0; i < 256; i++) shared.put(i, (byte) (i * 3));

    ByteBuffer message = shared.duplicate();
    message.position(64).limit(192);
    String expected = hashOf(message.slice());

    ByteBuffer hash = shared.duplicate();
    hash.position(100).limit(164);
    crypto_blake2b(hash.slice(), message.slice());
    assertEquals(expected, toHex(hash.slice()));
  }

  @Test
  @Order(105)
  public void test_honours_position_and_leaves_it_alone() {
    ByteBuffer message = buf(40);
    for (int i = 0; i < 40; i++) message.put(i, (byte) i);
    message.position(8).limit(24);

    ByteBuffer exact = buf(16);
    for (int i = 0; i < 16; i++) exact.put(i, (byte) (i + 8));

    assertEquals(hashOf(exact), hashOf(message));
    assertEquals(8, message.position());
  }
}
