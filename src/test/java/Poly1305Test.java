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
public class Poly1305Test {

  // c is left out: the tests treat it as unspecified.
  private static void assertPoly1305Ctx(
      Poly1305_ctx ctx, long c_idx, int[] r, int[] pad, int[] h) {
    // c_idx is a size_t between c and the uint32_t fields: 80-byte struct on
    // 64-bit platforms, 72 on 32-bit.
    int sizeT = ctxStructSize(ctx) >= 80 ? 8 : 4;
    ByteBuffer expected = ByteBuffer.allocate(sizeT + 13 * 4).order(ByteOrder.nativeOrder());
    if (sizeT == 8) {
      expected.putLong(c_idx);
    } else {
      expected.putInt((int) c_idx);
    }
    for (int v : r) expected.putInt(v);
    for (int v : pad) expected.putInt(v);
    for (int v : h) expected.putInt(v);
    assertTrue(ctxContains(ctx, expected.array()), "ctx does not hold the expected state");
  }

  @Test
  @Order(39)
  public void test_crypto_poly1305() {
    // crypto_poly1305 (inplace)happy path
    {
      ByteBuffer message = fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f");
      ByteBuffer mac = message.duplicate();
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      crypto_poly1305(mac, message, key);

      String expected = "a2291a363def0b53845fa4126a6ad364";

      String actual = toHex(mac);

      assertEquals(expected, actual, "mac mismatch");
    }

    // crypto_poly1305 (null message) happy path
    {
      ByteBuffer message = null;
      ByteBuffer mac = ByteBuffer.allocateDirect(16);
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      crypto_poly1305(mac, message, key);

      String expected = "101112131415161718191a1b1c1d1e1f";

      String actual = toHex(mac);

      assertEquals(expected, actual, "mac mismatch");
    }
  }

  @Test
  @Order(40)
  public void test_crypto_poly1305_init() {
    // poly1305 init
    {
      Poly1305_ctx ctx = new Poly1305_ctx();
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      crypto_poly1305_init(ctx, key);

      // c is uninitialised

      // c is uninitialised

      // c is uninitialised

      // c is uninitialised
      // ByteBuffer c_expected = fromHexToByteBuffer("010000000000000040ec266f01000000");

      long c_idx_expected = fromHexLEToLong("0000000000000000");

      int[] r_expected =
          new int[] {
            fromHexLEToInt("00010203"),
            fromHexLEToInt("04050607"),
            fromHexLEToInt("08090a0b"),
            fromHexLEToInt("0c0d0e0f"),
          };

      int[] pad_expected =
          new int[] {
            fromHexLEToInt("10111213"),
            fromHexLEToInt("14151617"),
            fromHexLEToInt("18191a1b"),
            fromHexLEToInt("1c1d1e1f"),
          };

      int[] h_expected =
          new int[] {
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
          };

      // c is uninitialised
      // assertArrayEquals(c_expected, c, "c mismatch");
      assertPoly1305Ctx(ctx, c_idx_expected, r_expected, pad_expected, h_expected);
    }
  }

  @Test
  @Order(41)
  public void test_crypto_poly1305_update() {
    // poly1305 update
    {
      Poly1305_ctx ctx = new Poly1305_ctx();
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer message =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122");

      crypto_poly1305_init(ctx, key);

      crypto_poly1305_update(ctx, message);

      {
        // c is not deterministic

        // c is not deterministic

        // c is not deterministic

        // c is not deterministic
        // ByteBuffer c_expected = fromHexToByteBuffer("2021224200000000445c7a9b01000000");

        long c_idx_expected = fromHexLEToLong("0300000000000000");

        int[] r_expected =
            new int[] {
              fromHexLEToInt("00010203"),
              fromHexLEToInt("04050607"),
              fromHexLEToInt("08090a0b"),
              fromHexLEToInt("0c0d0e0f"),
            };

        int[] pad_expected =
            new int[] {
              fromHexLEToInt("10111213"),
              fromHexLEToInt("14151617"),
              fromHexLEToInt("18191a1b"),
              fromHexLEToInt("1c1d1e1f"),
            };

        int[] h_expected =
            new int[] {
              fromHexLEToInt("d492fbae"),
              fromHexLEToInt("86a68c21"),
              fromHexLEToInt("c86d9a80"),
              fromHexLEToInt("0df9d521"),
              fromHexLEToInt("01000000"),
            };

        // c is not deterministic
        // assertArrayEquals(c_expected, c, "c mismatch");
        assertPoly1305Ctx(ctx, c_idx_expected, r_expected, pad_expected, h_expected);
      }

      crypto_poly1305_update(ctx, null);

      {

        // c is not deterministic

        // c is not deterministic

        // c is not deterministic
        // ByteBuffer c_expected = fromHexToByteBuffer("2021224200000000445c7a9b01000000");

        long c_idx_expected = fromHexLEToLong("0300000000000000");

        int[] r_expected =
            new int[] {
              fromHexLEToInt("00010203"),
              fromHexLEToInt("04050607"),
              fromHexLEToInt("08090a0b"),
              fromHexLEToInt("0c0d0e0f"),
            };

        int[] pad_expected =
            new int[] {
              fromHexLEToInt("10111213"),
              fromHexLEToInt("14151617"),
              fromHexLEToInt("18191a1b"),
              fromHexLEToInt("1c1d1e1f"),
            };

        int[] h_expected =
            new int[] {
              fromHexLEToInt("d492fbae"),
              fromHexLEToInt("86a68c21"),
              fromHexLEToInt("c86d9a80"),
              fromHexLEToInt("0df9d521"),
              fromHexLEToInt("01000000"),
            };

        // c is not deterministic
        // assertArrayEquals(c_expected, c, "c mismatch");
        assertPoly1305Ctx(ctx, c_idx_expected, r_expected, pad_expected, h_expected);
      }

      crypto_poly1305_update(ctx, message);

      {
        // c is not deterministic

        // c is not deterministic

        // c is not deterministic

        ByteBuffer c_expected = fromHexToByteBuffer("1d1e1f202122030405060708090a0b0c");

        long c_idx_expected = fromHexLEToLong("0600000000000000");

        int[] r_expected =
            new int[] {
              fromHexLEToInt("00010203"),
              fromHexLEToInt("04050607"),
              fromHexLEToInt("08090a0b"),
              fromHexLEToInt("0c0d0e0f"),
            };

        int[] pad_expected =
            new int[] {
              fromHexLEToInt("10111213"),
              fromHexLEToInt("14151617"),
              fromHexLEToInt("18191a1b"),
              fromHexLEToInt("1c1d1e1f"),
            };

        int[] h_expected =
            new int[] {
              fromHexLEToInt("e2f47dfb"),
              fromHexLEToInt("b8e142c1"),
              fromHexLEToInt("16e78301"),
              fromHexLEToInt("881743b2"),
              fromHexLEToInt("00000000"),
            };

        // c is not deterministic
        // assertArrayEquals(c_expected, c, "c mismatch");
        assertPoly1305Ctx(ctx, c_idx_expected, r_expected, pad_expected, h_expected);
      }
    }
  }

  @Test
  @Order(42)
  public void test_crypto_poly1305_final() {
    // poly1305 final
    {
      Poly1305_ctx ctx = new Poly1305_ctx();
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer message =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122");
      ByteBuffer mac = ByteBuffer.allocateDirect(16);

      crypto_poly1305_init(ctx, key);
      crypto_poly1305_update(ctx, message);
      crypto_poly1305_update(ctx, null);
      crypto_poly1305_update(ctx, message);
      crypto_poly1305_final(ctx, mac);

      String expected = "b133a3488588876cf36daebd4abf060e";

      String actual = toHex(mac);

      assertEquals(expected, actual, "mac mismatch");




      ByteBuffer c_expected = fromHexToByteBuffer("00000000000000000000000000000000");

      long c_idx_expected = fromHexLEToLong("0000000000000000");

      int[] r_expected =
          new int[] {
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
          };

      int[] pad_expected =
          new int[] {
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
          };

      int[] h_expected =
          new int[] {
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
            fromHexLEToInt("00000000"),
          };

      // Every field, including c, is zero once wiped.
      assertTrue(ctxIsZero(ctx), "ctx not wiped");
    }
  }

  @Test
  @Order(43)
  public void test_crypto_wipe_poly1305_ctx() {
    // crypto_wipe poly1305
    {
      Poly1305_ctx ctx = new Poly1305_ctx();
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      crypto_poly1305_init(ctx, key);
      {
        // c is uninitialised

        // c is uninitialised

        // c is uninitialised

        // c is uninitialised
        // ByteBuffer c_expected = fromHexToByteBuffer("010000000000000040ec266f01000000");

        long c_idx_expected = fromHexLEToLong("0000000000000000");

        int[] r_expected =
            new int[] {
              fromHexLEToInt("00010203"),
              fromHexLEToInt("04050607"),
              fromHexLEToInt("08090a0b"),
              fromHexLEToInt("0c0d0e0f"),
            };

        int[] pad_expected =
            new int[] {
              fromHexLEToInt("10111213"),
              fromHexLEToInt("14151617"),
              fromHexLEToInt("18191a1b"),
              fromHexLEToInt("1c1d1e1f"),
            };

        int[] h_expected =
            new int[] {
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
            };

        // c is uninitialised
        // assertArrayEquals(c_expected, c, "c mismatch");
        assertPoly1305Ctx(ctx, c_idx_expected, r_expected, pad_expected, h_expected);
      }

      crypto_wipe(ctx);

      {



        ByteBuffer c_expected = fromHexToByteBuffer("00000000000000000000000000000000");

        long c_idx_expected = fromHexLEToLong("0000000000000000");

        int[] r_expected =
            new int[] {
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
            };

        int[] pad_expected =
            new int[] {
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
            };

        int[] h_expected =
            new int[] {
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
              fromHexLEToInt("00000000"),
            };

        // Every field, including c, is zero once wiped.
        assertTrue(ctxIsZero(ctx), "ctx not wiped");
      }
    }
  }

  private static ByteBuffer buf(int len) {
    return ByteBuffer.allocateDirect(len);
  }

  private static IllegalArgumentException assertIae(org.junit.jupiter.api.function.Executable e) {
    return assertThrows(IllegalArgumentException.class, e);
  }

  private static ByteBuffer counting(int len) {
    ByteBuffer b = buf(len);
    for (int i = 0; i < len; i++) b.put(i, (byte) i);
    return b;
  }

  @Test
  @Order(100)
  public void test_streaming_matches_one_shot() {
    ByteBuffer message = counting(100);
    ByteBuffer key = counting(32);

    ByteBuffer expected = buf(16);
    crypto_poly1305(expected, message, key);

    try (Poly1305_ctx ctx = new Poly1305_ctx()) {
      crypto_poly1305_init(ctx, key);
      for (int i = 0; i < 100; i += 30) {
        ByteBuffer chunk = message.duplicate();
        chunk.position(i).limit(Math.min(i + 30, 100));
        crypto_poly1305_update(ctx, chunk);
      }
      ByteBuffer actual = buf(16);
      crypto_poly1305_final(ctx, actual);
      assertEquals(toHex(expected), toHex(actual));
    }
  }

  @Test
  @Order(101)
  public void test_ctx_unusable_before_init_and_after_final() {
    Poly1305_ctx ctx = new Poly1305_ctx();
    assertThrows(IllegalStateException.class, () -> crypto_poly1305_update(ctx, buf(8)));

    crypto_poly1305_init(ctx, buf(32));
    crypto_poly1305_final(ctx, buf(16));

    assertTrue(ctxIsZero(ctx), "ctx not wiped by final");
    assertThrows(IllegalStateException.class, () -> crypto_poly1305_update(ctx, buf(8)));
    assertThrows(IllegalStateException.class, () -> crypto_poly1305_final(ctx, buf(16)));
  }

  @Test
  @Order(102)
  public void test_rejects_bad_arguments() {
    assertIae(() -> crypto_poly1305(buf(15), buf(8), buf(32)));
    assertIae(() -> crypto_poly1305(buf(16), buf(8), buf(31)));
    assertIae(() -> crypto_poly1305(buf(16).asReadOnlyBuffer(), buf(8), buf(32)));
    assertIae(() -> crypto_poly1305(buf(16), buf(8), ByteBuffer.allocate(32)));
    assertThrows(NullPointerException.class, () -> crypto_poly1305(buf(16), buf(8), null));
    assertIae(() -> crypto_poly1305_init(new Poly1305_ctx(), buf(31)));
    assertThrows(NullPointerException.class, () -> crypto_poly1305_init(null, buf(32)));

    Poly1305_ctx ctx = new Poly1305_ctx();
    crypto_poly1305_init(ctx, buf(32));
    assertIae(() -> crypto_poly1305_final(ctx, buf(15)));
  }

  @Test
  @Order(103)
  public void test_mac_may_overlap_message_like_upstream() {
    ByteBuffer shared = counting(128);
    ByteBuffer message = shared.duplicate();
    message.position(16).limit(112);

    ByteBuffer expected = buf(16);
    crypto_poly1305(expected, message.slice(), counting(32));

    ByteBuffer mac = shared.duplicate();
    mac.position(40).limit(56);
    crypto_poly1305(mac.slice(), message.slice(), counting(32));
    assertEquals(toHex(expected), toHex(mac.slice()));
  }

  @Test
  @Order(104)
  public void test_honours_position_and_leaves_it_alone() {
    ByteBuffer message = counting(40);
    message.position(8).limit(24);

    ByteBuffer exact = buf(16);
    for (int i = 0; i < 16; i++) exact.put(i, (byte) (i + 8));

    ByteBuffer a = buf(16);
    ByteBuffer b = buf(16);
    crypto_poly1305(a, message, counting(32));
    crypto_poly1305(b, exact, counting(32));
    assertEquals(toHex(b), toHex(a));
    assertEquals(8, message.position());
  }
}
