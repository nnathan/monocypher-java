import static net.lastninja.monocypher.Monocypher.*;
import static net.lastninja.monocypher.TestUtil.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import net.lastninja.monocypher.Monocypher.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Sha512Test {

  private static ByteBuffer buf(int size) {
    return ByteBuffer.allocateDirect(size);
  }

  private static ByteBuffer ascii(String s) {
    return direct(s.getBytes(StandardCharsets.US_ASCII));
  }

  private static ByteBuffer pattern(int size) {
    ByteBuffer b = buf(size);
    for (int i = 0; i < size; i++) b.put(i, (byte) (i * 7 + 3));
    return b;
  }

  private static ByteBuffer slice(ByteBuffer b, int offset, int length) {
    ByteBuffer view = b.duplicate();
    view.position(offset);
    view.limit(offset + length);
    return view.slice();
  }

  private static void assertIae(Executable e) {
    assertThrows(IllegalArgumentException.class, e);
  }

  private static String sha512(ByteBuffer message) {
    ByteBuffer hash = buf(64);
    crypto_sha512(hash, message);
    return toHex(hash);
  }

  private static String hmac(ByteBuffer key, ByteBuffer message) {
    ByteBuffer out = buf(64);
    crypto_sha512_hmac(out, key, message);
    return toHex(out);
  }

  @Test
  @Order(1)
  public void test_crypto_sha512() {
    // FIPS 180-2
    assertEquals(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        sha512(ascii("abc")));
    String empty =
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    assertEquals(empty, sha512(buf(0)));
    assertEquals(empty, sha512(null));
  }

  @Test
  @Order(2)
  public void test_sha512_streaming_matches_one_shot() {
    ByteBuffer message = pattern(300);
    try (SHA512_ctx ctx = new SHA512_ctx()) {
      ByteBuffer hash = buf(64);
      crypto_sha512_init(ctx);
      crypto_sha512_update(ctx, slice(message, 0, 100));
      crypto_sha512_update(ctx, null);
      crypto_sha512_update(ctx, slice(message, 100, 200));
      crypto_sha512_final(ctx, hash);
      assertEquals(sha512(message), toHex(hash));
    }
  }

  @Test
  @Order(3)
  public void test_crypto_sha512_hmac() {
    // RFC 4231, test case 2
    String expected =
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
            + "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
    ByteBuffer key = ascii("Jefe");
    ByteBuffer message = ascii("what do ya want for nothing?");
    assertEquals(expected, hmac(key, message));

    try (SHA512_HMAC_ctx ctx = new SHA512_HMAC_ctx()) {
      ByteBuffer out = buf(64);
      crypto_sha512_hmac_init(ctx, key);
      crypto_sha512_hmac_update(ctx, slice(message, 0, 10));
      crypto_sha512_hmac_update(ctx, slice(message, 10, message.remaining() - 10));
      crypto_sha512_hmac_final(ctx, out);
      assertEquals(expected, toHex(out));
    }
  }

  @Test
  @Order(4)
  public void test_hmac_accepts_empty_and_long_keys() {
    hmac(buf(0), null);
    // Keys longer than the 128-byte block are hashed first.
    ByteBuffer longKey = pattern(200);
    ByteBuffer hashedKey = buf(64);
    crypto_sha512(hashedKey, longKey);
    assertEquals(hmac(hashedKey, ascii("x")), hmac(longKey, ascii("x")));
  }

  @Test
  @Order(5)
  public void test_hkdf_is_hmac_extract_then_expand() {
    ByteBuffer ikm = pattern(22);
    ByteBuffer salt = pattern(13);
    ByteBuffer info = pattern(10);

    ByteBuffer prk = buf(64);
    crypto_sha512_hmac(prk, salt, ikm);

    for (int size : new int[] {0, 1, 64, 65, 200, 16320}) {
      ByteBuffer expanded = buf(size);
      ByteBuffer full = buf(size);
      crypto_sha512_hkdf_expand(expanded, prk, info);
      crypto_sha512_hkdf(full, ikm, salt, info);
      assertEquals(toHex(expanded), toHex(full), "okm size " + size);
    }
  }

  @Test
  @Order(6)
  public void test_hkdf_null_salt_and_info_are_empty() {
    ByteBuffer ikm = pattern(32);
    ByteBuffer a = buf(80);
    ByteBuffer b = buf(80);
    crypto_sha512_hkdf(a, ikm, null, null);
    crypto_sha512_hkdf(b, ikm, buf(0), buf(0));
    assertEquals(toHex(a), toHex(b));

    ByteBuffer prk = pattern(64);
    crypto_sha512_hkdf_expand(a, prk, null);
    crypto_sha512_hkdf_expand(b, prk, buf(0));
    assertEquals(toHex(a), toHex(b));
  }

  @Test
  @Order(100)
  public void test_ctx_unusable_before_init_and_after_final() {
    SHA512_ctx ctx = new SHA512_ctx();
    assertThrows(IllegalStateException.class, () -> crypto_sha512_update(ctx, buf(8)));
    crypto_sha512_init(ctx);
    crypto_sha512_final(ctx, buf(64));
    assertTrue(ctxIsZero(ctx), "ctx not wiped by final");
    assertThrows(IllegalStateException.class, () -> crypto_sha512_final(ctx, buf(64)));

    crypto_sha512_init(ctx);
    crypto_wipe(ctx);
    assertTrue(ctxIsZero(ctx), "ctx not wiped by crypto_wipe");
    assertThrows(IllegalStateException.class, () -> crypto_sha512_update(ctx, buf(8)));

    SHA512_HMAC_ctx hctx = new SHA512_HMAC_ctx();
    assertThrows(IllegalStateException.class, () -> crypto_sha512_hmac_update(hctx, buf(8)));
    crypto_sha512_hmac_init(hctx, buf(32));
    crypto_sha512_hmac_final(hctx, buf(64));
    assertTrue(ctxIsZero(hctx), "hmac ctx not wiped by final");
    assertThrows(IllegalStateException.class, () -> crypto_sha512_hmac_final(hctx, buf(64)));

    crypto_sha512_hmac_init(hctx, buf(32));
    hctx.close();
    assertTrue(ctxIsZero(hctx), "hmac ctx not wiped by close");
  }

  @Test
  @Order(101)
  public void test_rejects_bad_arguments() {
    assertIae(() -> crypto_sha512(buf(63), buf(8)));
    assertIae(() -> crypto_sha512(buf(65), buf(8)));
    assertIae(() -> crypto_sha512(buf(64).asReadOnlyBuffer(), buf(8)));
    assertIae(() -> crypto_sha512(buf(64), ByteBuffer.allocate(8)));
    assertThrows(NullPointerException.class, () -> crypto_sha512(null, buf(8)));

    assertIae(() -> crypto_sha512_hmac(buf(32), buf(32), buf(8)));
    assertThrows(NullPointerException.class, () -> crypto_sha512_hmac(buf(64), null, buf(8)));
    assertThrows(NullPointerException.class, () -> crypto_sha512_init(null));
    assertThrows(
        NullPointerException.class,
        () -> crypto_sha512_hmac_init(new SHA512_HMAC_ctx(), null));

    try (SHA512_ctx ctx = new SHA512_ctx()) {
      crypto_sha512_init(ctx);
      assertIae(() -> crypto_sha512_final(ctx, buf(32)));
    }
    try (SHA512_HMAC_ctx ctx = new SHA512_HMAC_ctx()) {
      crypto_sha512_hmac_init(ctx, buf(32));
      assertIae(() -> crypto_sha512_hmac_final(ctx, buf(32)));
    }

    assertIae(() -> crypto_sha512_hkdf(buf(16321), buf(32), null, null));
    assertIae(() -> crypto_sha512_hkdf_expand(buf(16321), buf(64), null));
    assertIae(() -> crypto_sha512_hkdf(buf(32).asReadOnlyBuffer(), buf(32), null, null));
    assertThrows(NullPointerException.class, () -> crypto_sha512_hkdf(buf(32), null, null, null));
    assertThrows(NullPointerException.class, () -> crypto_sha512_hkdf_expand(buf(32), null, null));
  }

  @Test
  @Order(102)
  public void test_hash_and_hmac_may_overlap_message_like_upstream() {
    ByteBuffer shared = pattern(256);
    String expectedHash = sha512(slice(pattern(256), 64, 128));
    crypto_sha512(slice(shared, 100, 64), slice(shared, 64, 128));
    assertEquals(expectedHash, toHex(slice(shared, 100, 64)));

    shared = pattern(256);
    ByteBuffer key = pattern(32);
    String expectedHmac = hmac(key, slice(pattern(256), 64, 128));
    crypto_sha512_hmac(slice(shared, 100, 64), key, slice(shared, 64, 128));
    assertEquals(expectedHmac, toHex(slice(shared, 100, 64)));
  }

  @Test
  @Order(103)
  public void test_hkdf_okm_must_not_overlap_inputs() {
    ByteBuffer shared = pattern(256);
    ByteBuffer okm = slice(shared, 0, 64);
    assertIae(() -> crypto_sha512_hkdf(okm, slice(shared, 32, 32), null, null));
    assertIae(() -> crypto_sha512_hkdf(okm, buf(32), slice(shared, 63, 16), null));
    assertIae(() -> crypto_sha512_hkdf(okm, buf(32), null, slice(shared, 10, 4)));
    assertIae(() -> crypto_sha512_hkdf_expand(okm, slice(shared, 0, 64), null));
    assertIae(() -> crypto_sha512_hkdf_expand(okm, buf(64), slice(shared, 60, 8)));

    // Adjacent is fine.
    crypto_sha512_hkdf(okm, slice(shared, 64, 32), slice(shared, 96, 16), slice(shared, 112, 8));
  }

  @Test
  @Order(104)
  public void test_honours_position_and_leaves_it_alone() {
    ByteBuffer message = pattern(40);
    message.position(8).limit(24);
    ByteBuffer exact = direct(new byte[16]);
    for (int i = 0; i < 16; i++) exact.put(i, message.get(8 + i));

    assertEquals(sha512(exact), sha512(message));
    assertEquals(8, message.position());

    ByteBuffer hash = buf(80);
    hash.position(16);
    crypto_sha512(hash, exact);
    assertEquals(16, hash.position());
    assertEquals(sha512(exact), toHex(hash));
  }
}
