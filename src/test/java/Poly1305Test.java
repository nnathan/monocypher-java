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
public class Poly1305Test {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(39)
  public void test_crypto_poly1305() {
    // crypto_poly1305 (inplace)happy path
    {
      ByteBuffer message = fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f");
      ByteBuffer mac = message.duplicate();
      byte[] key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      mc.crypto_poly1305(mac, message, key);

      String expected = "a2291a363def0b53845fa4126a6ad364";

      String actual = toHex(mac);

      assertEquals(expected, actual, "mac mismatch");
    }

    // crypto_poly1305 (null message) happy path
    {
      ByteBuffer message = null;
      ByteBuffer mac = ByteBuffer.allocateDirect(16);
      byte[] key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      mc.crypto_poly1305(mac, message, key);

      String expected = "101112131415161718191a1b1c1d1e1f";

      String actual = toHex(mac);

      assertEquals(expected, actual, "mac mismatch");
    }
  }

  @Test
  @Order(40)
  public void test_crypto_poly1305_init() throws NoSuchFieldException, IllegalAccessException {
    // poly1305 init
    {
      Poly1305_ctx ctx = mc.new Poly1305_ctx();
      byte[] key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      mc.crypto_poly1305_init(ctx, key);

      // c is uninitialised
      // Field cField = Poly1305_ctx.class.getDeclaredField("c");
      Field c_idxField = Poly1305_ctx.class.getDeclaredField("c_idx");
      Field rField = Poly1305_ctx.class.getDeclaredField("r");
      Field padField = Poly1305_ctx.class.getDeclaredField("pad");
      Field hField = Poly1305_ctx.class.getDeclaredField("h");

      // c is uninitialised
      // cField.setAccessible(true);
      c_idxField.setAccessible(true);
      rField.setAccessible(true);
      padField.setAccessible(true);
      hField.setAccessible(true);

      // c is uninitialised
      // byte[] c = (byte[]) cField.get(ctx);
      long c_idx = (long) c_idxField.get(ctx);
      int[] r = (int[]) rField.get(ctx);
      int[] pad = (int[]) padField.get(ctx);
      int[] h = (int[]) hField.get(ctx);

      // c is uninitialised
      // byte[] c_expected = fromHexToByteArray("010000000000000040ec266f01000000");

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
      assertEquals(c_idx_expected, c_idx, "c_idx mismatch");
      assertArrayEquals(r_expected, r, "r mismatch");
      assertArrayEquals(pad_expected, pad, "pad mismatch");
      assertArrayEquals(h_expected, h, "h mismatch");
    }
  }

  @Test
  @Order(41)
  public void test_crypto_poly1305_update() throws NoSuchFieldException, IllegalAccessException {
    // poly1305 update
    {
      Poly1305_ctx ctx = mc.new Poly1305_ctx();
      byte[] key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] message =
          fromHexToByteArray(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122");

      mc.crypto_poly1305_init(ctx, key);

      mc.crypto_poly1305_update(ctx, message);

      {
        // c is not deterministic
        // Field cField = Poly1305_ctx.class.getDeclaredField("c");
        Field c_idxField = Poly1305_ctx.class.getDeclaredField("c_idx");
        Field rField = Poly1305_ctx.class.getDeclaredField("r");
        Field padField = Poly1305_ctx.class.getDeclaredField("pad");
        Field hField = Poly1305_ctx.class.getDeclaredField("h");

        // c is not deterministic
        // cField.setAccessible(true);
        c_idxField.setAccessible(true);
        rField.setAccessible(true);
        padField.setAccessible(true);
        hField.setAccessible(true);

        // c is not deterministic
        // byte[] c = (byte[]) cField.get(ctx);
        long c_idx = (long) c_idxField.get(ctx);
        int[] r = (int[]) rField.get(ctx);
        int[] pad = (int[]) padField.get(ctx);
        int[] h = (int[]) hField.get(ctx);

        // c is not deterministic
        // byte[] c_expected = fromHexToByteArray("2021224200000000445c7a9b01000000");

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
        assertEquals(c_idx_expected, c_idx, "c_idx mismatch");
        assertArrayEquals(r_expected, r, "r mismatch");
        assertArrayEquals(pad_expected, pad, "pad mismatch");
        assertArrayEquals(h_expected, h, "h mismatch");
      }

      mc.crypto_poly1305_update(ctx, null);

      {
        Field cField = Poly1305_ctx.class.getDeclaredField("c");
        Field c_idxField = Poly1305_ctx.class.getDeclaredField("c_idx");
        Field rField = Poly1305_ctx.class.getDeclaredField("r");
        Field padField = Poly1305_ctx.class.getDeclaredField("pad");
        Field hField = Poly1305_ctx.class.getDeclaredField("h");

        // c is not deterministic
        // cField.setAccessible(true);
        c_idxField.setAccessible(true);
        rField.setAccessible(true);
        padField.setAccessible(true);
        hField.setAccessible(true);

        // c is not deterministic
        // byte[] c = (byte[]) cField.get(ctx);
        long c_idx = (long) c_idxField.get(ctx);
        int[] r = (int[]) rField.get(ctx);
        int[] pad = (int[]) padField.get(ctx);
        int[] h = (int[]) hField.get(ctx);

        // c is not deterministic
        // byte[] c_expected = fromHexToByteArray("2021224200000000445c7a9b01000000");

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
        assertEquals(c_idx_expected, c_idx, "c_idx mismatch");
        assertArrayEquals(r_expected, r, "r mismatch");
        assertArrayEquals(pad_expected, pad, "pad mismatch");
        assertArrayEquals(h_expected, h, "h mismatch");
      }

      mc.crypto_poly1305_update(ctx, message);

      {
        // c is not deterministic
        // Field cField = Poly1305_ctx.class.getDeclaredField("c");
        Field c_idxField = Poly1305_ctx.class.getDeclaredField("c_idx");
        Field rField = Poly1305_ctx.class.getDeclaredField("r");
        Field padField = Poly1305_ctx.class.getDeclaredField("pad");
        Field hField = Poly1305_ctx.class.getDeclaredField("h");

        // c is not deterministic
        // cField.setAccessible(true);
        c_idxField.setAccessible(true);
        rField.setAccessible(true);
        padField.setAccessible(true);
        hField.setAccessible(true);

        // c is not deterministic
        // byte[] c = (byte[]) cField.get(ctx);
        long c_idx = (long) c_idxField.get(ctx);
        int[] r = (int[]) rField.get(ctx);
        int[] pad = (int[]) padField.get(ctx);
        int[] h = (int[]) hField.get(ctx);

        byte[] c_expected = fromHexToByteArray("1d1e1f202122030405060708090a0b0c");

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
        assertEquals(c_idx_expected, c_idx, "c_idx mismatch");
        assertArrayEquals(r_expected, r, "r mismatch");
        assertArrayEquals(pad_expected, pad, "pad mismatch");
        assertArrayEquals(h_expected, h, "h mismatch");
      }
    }
  }

  @Test
  @Order(42)
  public void test_crypto_poly1305_final() throws NoSuchFieldException, IllegalAccessException {
    // poly1305 final
    {
      Poly1305_ctx ctx = mc.new Poly1305_ctx();
      byte[] key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] message =
          fromHexToByteArray(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122");
      byte[] mac = new byte[16];

      mc.crypto_poly1305_init(ctx, key);
      mc.crypto_poly1305_update(ctx, message);
      mc.crypto_poly1305_update(ctx, null);
      mc.crypto_poly1305_update(ctx, message);
      mc.crypto_poly1305_final(ctx, mac);

      String expected = "b133a3488588876cf36daebd4abf060e";

      String actual = toHex(mac);

      assertEquals(expected, actual, "mac mismatch");

      Field cField = Poly1305_ctx.class.getDeclaredField("c");
      Field c_idxField = Poly1305_ctx.class.getDeclaredField("c_idx");
      Field rField = Poly1305_ctx.class.getDeclaredField("r");
      Field padField = Poly1305_ctx.class.getDeclaredField("pad");
      Field hField = Poly1305_ctx.class.getDeclaredField("h");

      cField.setAccessible(true);
      c_idxField.setAccessible(true);
      rField.setAccessible(true);
      padField.setAccessible(true);
      hField.setAccessible(true);

      byte[] c = (byte[]) cField.get(ctx);
      long c_idx = (long) c_idxField.get(ctx);
      int[] r = (int[]) rField.get(ctx);
      int[] pad = (int[]) padField.get(ctx);
      int[] h = (int[]) hField.get(ctx);

      byte[] c_expected = fromHexToByteArray("00000000000000000000000000000000");

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

      assertArrayEquals(c_expected, c, "c mismatch");
      assertEquals(c_idx_expected, c_idx, "c_idx mismatch");
      assertArrayEquals(r_expected, r, "r mismatch");
      assertArrayEquals(pad_expected, pad, "pad mismatch");
      assertArrayEquals(h_expected, h, "h mismatch");
    }
  }

  @Test
  @Order(43)
  public void test_crypto_wipe_poly1305_ctx() throws NoSuchFieldException, IllegalAccessException {
    // crypto_wipe poly1305
    {
      Poly1305_ctx ctx = mc.new Poly1305_ctx();
      byte[] key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      mc.crypto_poly1305_init(ctx, key);
      {
        // c is uninitialised
        // Field cField = Poly1305_ctx.class.getDeclaredField("c");
        Field c_idxField = Poly1305_ctx.class.getDeclaredField("c_idx");
        Field rField = Poly1305_ctx.class.getDeclaredField("r");
        Field padField = Poly1305_ctx.class.getDeclaredField("pad");
        Field hField = Poly1305_ctx.class.getDeclaredField("h");

        // c is uninitialised
        // cField.setAccessible(true);
        c_idxField.setAccessible(true);
        rField.setAccessible(true);
        padField.setAccessible(true);
        hField.setAccessible(true);

        // c is uninitialised
        // byte[] c = (byte[]) cField.get(ctx);
        long c_idx = (long) c_idxField.get(ctx);
        int[] r = (int[]) rField.get(ctx);
        int[] pad = (int[]) padField.get(ctx);
        int[] h = (int[]) hField.get(ctx);

        // c is uninitialised
        // byte[] c_expected = fromHexToByteArray("010000000000000040ec266f01000000");

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
        assertEquals(c_idx_expected, c_idx, "c_idx mismatch");
        assertArrayEquals(r_expected, r, "r mismatch");
        assertArrayEquals(pad_expected, pad, "pad mismatch");
        assertArrayEquals(h_expected, h, "h mismatch");
      }

      mc.crypto_wipe(ctx);

      {
        Field cField = Poly1305_ctx.class.getDeclaredField("c");
        Field c_idxField = Poly1305_ctx.class.getDeclaredField("c_idx");
        Field rField = Poly1305_ctx.class.getDeclaredField("r");
        Field padField = Poly1305_ctx.class.getDeclaredField("pad");
        Field hField = Poly1305_ctx.class.getDeclaredField("h");

        cField.setAccessible(true);
        c_idxField.setAccessible(true);
        rField.setAccessible(true);
        padField.setAccessible(true);
        hField.setAccessible(true);

        byte[] c = (byte[]) cField.get(ctx);
        long c_idx = (long) c_idxField.get(ctx);
        int[] r = (int[]) rField.get(ctx);
        int[] pad = (int[]) padField.get(ctx);
        int[] h = (int[]) hField.get(ctx);

        byte[] c_expected = fromHexToByteArray("00000000000000000000000000000000");

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

        assertArrayEquals(c_expected, c, "c mismatch");
        assertEquals(c_idx_expected, c_idx, "c_idx mismatch");
        assertArrayEquals(r_expected, r, "r mismatch");
        assertArrayEquals(pad_expected, pad, "pad mismatch");
        assertArrayEquals(h_expected, h, "h mismatch");
      }
    }
  }
}
