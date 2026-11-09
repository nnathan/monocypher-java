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
public class Argon2Test {

  @Test
  @Order(19)
  public void test_crypto_argon2() {
    // argon2 happy path
    {
      Argon2_config cfg = new Argon2_config(CRYPTO_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          new Argon2_inputs(
              fromHexToByteBuffer("00010203040506070809"),
              fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext = new Argon2_extras(null, null);

      ByteBuffer hash = ByteBuffer.allocateDirect(32);

      crypto_argon2(hash, ByteBuffer.allocateDirect(10 * 1024), cfg, inp, ext);

      String expected = "36ef27b9a646795126c9e41aa5bef66a50556bd8c84e73412856492529f8373a";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, empty password
    {
      Argon2_config cfg = new Argon2_config(CRYPTO_ARGON2_I, 10, 1, 1);
      Argon2_inputs inp =
          new Argon2_inputs(null, fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext = new Argon2_extras(null, null);

      ByteBuffer hash = ByteBuffer.allocateDirect(32);

      crypto_argon2(hash, ByteBuffer.allocateDirect(10 * 1024), cfg, inp, ext);

      String expected = "4d0a33ee95d4dcd01cb8be2ad03c5babde3a20d4306a2348f7bceac3907c2b55";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, empty password, with key and ad
    {
      Argon2_config cfg = new Argon2_config(CRYPTO_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          new Argon2_inputs(null, fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          new Argon2_extras(
              fromHexToByteBuffer("0001020304050607"), fromHexToByteBuffer("0001020304050607"));

      ByteBuffer hash = ByteBuffer.allocateDirect(32);

      crypto_argon2(hash, ByteBuffer.allocateDirect(10 * 1024), cfg, inp, ext);

      String expected = "7ff21ad59ca877d7c2f78cd30b1d9ff2e2a23b65a058e2ea145d1770bfb638f9";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, 1 byte hash, empty password, with key and ad
    {
      Argon2_config cfg = new Argon2_config(CRYPTO_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          new Argon2_inputs(null, fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          new Argon2_extras(
              fromHexToByteBuffer("0001020304050607"), fromHexToByteBuffer("0001020304050607"));

      ByteBuffer hash = ByteBuffer.allocateDirect(1);

      crypto_argon2(hash, ByteBuffer.allocateDirect(10 * 1024), cfg, inp, ext);

      String expected = "b8";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, 0 byte hash, empty password, with key and ad
    {
      Argon2_config cfg = new Argon2_config(CRYPTO_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          new Argon2_inputs(null, fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          new Argon2_extras(
              fromHexToByteBuffer("0001020304050607"), fromHexToByteBuffer("0001020304050607"));

      ByteBuffer hash = ByteBuffer.allocateDirect(0);

      crypto_argon2(hash, ByteBuffer.allocateDirect(10 * 1024), cfg, inp, ext);

      String expected = "";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 sad path, null hash
    {
      Argon2_config cfg = new Argon2_config(CRYPTO_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          new Argon2_inputs(null, fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          new Argon2_extras(
              fromHexToByteBuffer("0001020304050607"), fromHexToByteBuffer("0001020304050607"));

      ByteBuffer hash = null;

      try {
        crypto_argon2(hash, ByteBuffer.allocateDirect(10 * 1024), cfg, inp, ext);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }
    //
    // argon2 sad path, null salt
    {
      Argon2_config cfg = new Argon2_config(CRYPTO_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp = new Argon2_inputs(null, null);
      Argon2_extras ext =
          new Argon2_extras(
              fromHexToByteBuffer("0001020304050607"), fromHexToByteBuffer("0001020304050607"));

      ByteBuffer hash = ByteBuffer.allocateDirect(32);

      try {
        crypto_argon2(hash, ByteBuffer.allocateDirect(10 * 1024), cfg, inp, ext);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("salt cannot be null", e.getMessage());
      }
    }

    // argon2 sad path, small salt
    {
      Argon2_config cfg = new Argon2_config(CRYPTO_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp = new Argon2_inputs(null, fromHexToByteBuffer("00"));
      Argon2_extras ext =
          new Argon2_extras(
              fromHexToByteBuffer("0001020304050607"), fromHexToByteBuffer("0001020304050607"));

      ByteBuffer hash = ByteBuffer.allocateDirect(32);

      try {
        crypto_argon2(hash, ByteBuffer.allocateDirect(10 * 1024), cfg, inp, ext);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("salt must have at least 8 bytes remaining", e.getMessage());
      }
    }
  }

  private static ByteBuffer buf(int len) {
    return ByteBuffer.allocateDirect(len);
  }

  private static Argon2_config small() {
    return new Argon2_config(CRYPTO_ARGON2_ID, 8, 1, 1);
  }

  private static Argon2_inputs inputs() {
    return new Argon2_inputs(buf(8), buf(16));
  }

  private static IllegalArgumentException assertIae(org.junit.jupiter.api.function.Executable e) {
    return assertThrows(IllegalArgumentException.class, e);
  }

  @Test
  @Order(100)
  public void test_config_rejects_bad_values() {
    assertEquals(
        "nb_lanes must be at least 1",
        assertIae(() -> new Argon2_config(CRYPTO_ARGON2_ID, 8, 1, 0)).getMessage());
    assertEquals(
        "nb_passes must be at least 1",
        assertIae(() -> new Argon2_config(CRYPTO_ARGON2_ID, 8, 0, 1)).getMessage());
    assertEquals(
        "nb_blocks must be at least 8 * nb_lanes",
        assertIae(() -> new Argon2_config(CRYPTO_ARGON2_ID, 15, 1, 2)).getMessage());
    // 8 * nb_lanes overflows a 32-bit int here.
    assertIae(() -> new Argon2_config(CRYPTO_ARGON2_ID, 0, 1, 536870912));
    assertIae(() -> new Argon2_config(CRYPTO_ARGON2_ID, -8, 1, 1));
    // The value whose work area wrapped to 0 bytes before.
    assertEquals(
        "nb_blocks must be at most 2097151",
        assertIae(() -> new Argon2_config(CRYPTO_ARGON2_ID, 4194304, 1, 1)).getMessage());
    assertThrows(NullPointerException.class, () -> new Argon2_config(null, 8, 1, 1));
  }

  @Test
  @Order(101)
  public void test_null_extras_throws_and_no_extras_works() {
    NullPointerException e =
        assertThrows(
            NullPointerException.class,
            () -> crypto_argon2(buf(32), buf(8 * 1024), small(), inputs(), null));
    assertEquals("extras cannot be null", e.getMessage());

    ByteBuffer a = buf(32);
    ByteBuffer b = buf(32);
    crypto_argon2(a, buf(8 * 1024), small(), inputs(), crypto_argon2_no_extras);
    crypto_argon2(b, buf(8 * 1024), small(), inputs(), new Argon2_extras(null, null));
    assertEquals(toHex(a), toHex(b));
  }

  @Test
  @Order(102)
  public void test_work_area_is_checked_and_wiped() {
    assertEquals(
        "work_area must have exactly nb_blocks * 1024 bytes remaining",
        assertIae(
                () -> crypto_argon2(buf(32), buf(8 * 1024 - 1), small(), inputs(), crypto_argon2_no_extras))
            .getMessage());

    ByteBuffer misaligned = buf(8 * 1024 + 1);
    misaligned.position(1);
    ByteBuffer slice = misaligned.slice();
    assertEquals(
        "work_area must be 8-byte aligned",
        assertIae(() -> crypto_argon2(buf(32), slice, small(), inputs(), crypto_argon2_no_extras))
            .getMessage());

    ByteBuffer work_area = buf(8 * 1024);
    crypto_argon2(buf(32), work_area, small(), inputs(), crypto_argon2_no_extras);
    for (int i = 0; i < work_area.capacity(); i++) assertEquals(0, work_area.get(i));
  }

  @Test
  @Order(103)
  public void test_rejects_bad_hash_and_buffers() {
    assertIae(
        () ->
            crypto_argon2(
                buf(32).asReadOnlyBuffer(), buf(8 * 1024), small(), inputs(), crypto_argon2_no_extras));
    assertIae(
        () ->
            crypto_argon2(
                ByteBuffer.allocate(32), buf(8 * 1024), small(), inputs(), crypto_argon2_no_extras));
    assertIae(
        () ->
            crypto_argon2(
                buf(32),
                buf(8 * 1024),
                small(),
                new Argon2_inputs(null, ByteBuffer.allocate(16)),
                crypto_argon2_no_extras));
  }

  @Test
  @Order(104)
  public void test_rejects_overlap_with_outputs() {
    ByteBuffer shared = buf(8 * 1024 + 64);
    ByteBuffer work_area = shared.duplicate();
    work_area.limit(8 * 1024);
    ByteBuffer hash = shared.duplicate();
    hash.position(8 * 1024 - 16).limit(8 * 1024 + 16);
    ByteBuffer workSlice = work_area.slice();
    ByteBuffer hashSlice = hash.slice();
    assertIae(() -> crypto_argon2(hashSlice, workSlice, small(), inputs(), crypto_argon2_no_extras));

    ByteBuffer salt = buf(32);
    ByteBuffer saltAsHash = salt.duplicate();
    assertIae(
        () ->
            crypto_argon2(
                saltAsHash, buf(8 * 1024), small(), new Argon2_inputs(null, salt), crypto_argon2_no_extras));
  }

  @Test
  @Order(105)
  public void test_honours_position_and_leaves_it_alone() {
    ByteBuffer hash = buf(48);
    hash.position(8).limit(40);
    crypto_argon2(hash, buf(8 * 1024), small(), inputs(), crypto_argon2_no_extras);
    assertEquals(8, hash.position());

    ByteBuffer expected = buf(32);
    crypto_argon2(expected, buf(8 * 1024), small(), inputs(), crypto_argon2_no_extras);
    assertEquals(toHex(expected), toHex(hash));
  }
}
