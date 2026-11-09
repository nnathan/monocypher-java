import static net.lastninja.monocypher.Hazmat.*;
import static net.lastninja.monocypher.Monocypher.*;
import static net.lastninja.monocypher.TestUtil.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import net.lastninja.monocypher.Monocypher;
import net.lastninja.monocypher.Monocypher.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * A port of Monocypher's {@code tests/test.c} (version 4.0.3), in the same order.
 *
 * <p>The vectors are vendored, see {@code src/test/resources/upstream/PROVENANCE.md}.
 *
 * <p>These parts of {@code test.c} are not ported:
 *
 * <ul>
 *   <li>SHA-512, HMAC-SHA-512, HKDF-SHA-512 and Ed25519, as these bindings do not include
 *       Monocypher's optional {@code monocypher-ed25519.h}.
 *   <li>BLAKE2b vectors with a zero-length hash, as the manual requires a hash size between 1 and
 *       64 and the binding enforces that.
 * </ul>
 *
 * <p>The Argon2 overlap test is adapted: upstream overlaps the hash and inputs with the work area,
 * which the binding rejects. Here the inputs overlap each other, as the manual allows, and the
 * rejected overlaps are checked to throw.
 *
 * <p>{@code test.c} shares one random generator between all of its tests, here each test has its
 * own.
 */
@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class UpstreamTest {

  private static final String VECTORS_SHA512 =
      "c6b83b5c6cbdbe16e6dae4b056940b7c3a561ce5bef3196e9961f05974b6f2d0"
          + "0fc37f517857e913044503beed72952b48ec6e48ce7f41ef255a449ac40d142a";

  private static final byte[] L =
      fromHexToByteArray("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

  private static byte[] vectorsFile;

  @BeforeAll
  public static void loadVectors() throws IOException {
    try (InputStream in = UpstreamTest.class.getResourceAsStream("/upstream/vectors.h")) {
      assertNotNull(in, "upstream/vectors.h is not on the test classpath");
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] chunk = new byte[1 << 16];
      int n;
      while ((n = in.read(chunk)) > 0) {
        out.write(chunk, 0, n);
      }
      vectorsFile = out.toByteArray();
    }
  }

  /** Returns the named vectors, grouped into arity values per test case. */
  private static List<byte[][]> vectors(String name, int arity, int expectedCases) {
    String text = new String(vectorsFile, StandardCharsets.US_ASCII);
    String start = "static const char *" + name + "_vectors[]={";
    int from = text.indexOf(start);
    assertTrue(from >= 0, name);
    from += start.length();
    String body = text.substring(from, text.indexOf("};", from));

    List<byte[]> strings = new ArrayList<>();
    for (String line : body.split("\n")) {
      line = line.trim();
      if (line.startsWith("\"")) {
        strings.add(fromHexToByteArray(line.substring(1, line.lastIndexOf('"'))));
      }
    }
    assertEquals(expectedCases * arity, strings.size(), name);

    List<byte[][]> cases = new ArrayList<>();
    for (int i = 0; i < strings.size(); i += arity) {
      cases.add(strings.subList(i, i + arity).toArray(new byte[arity][]));
    }
    return cases;
  }

  /** The xorshift* generator from Monocypher's {@code tests/utils.c}. */
  private static final class Rng {
    private long state = 12345;

    long next() {
      state ^= state >>> 12;
      state ^= state << 25;
      state ^= state >>> 27;
      return state * 0x2545F4914F6CDD1DL;
    }

    byte[] bytes(int size) {
      byte[] out = new byte[size];
      for (int i = 0; i < size; i++) {
        out[i] = (byte) next();
      }
      return out;
    }

    ByteBuffer buffer(int size) {
      return direct(bytes(size));
    }

    int below(int bound) {
      return (int) Long.remainderUnsigned(next(), bound);
    }
  }

  private static ByteBuffer buf(byte[] bytes) {
    return direct(bytes);
  }

  private static ByteBuffer out(int size) {
    return ByteBuffer.allocateDirect(size);
  }

  /** The bytes from position to limit, without moving position. */
  private static byte[] bytes(ByteBuffer buffer) {
    byte[] out = new byte[buffer.remaining()];
    buffer.duplicate().get(out);
    return out;
  }

  /** A view of length bytes starting at offset, sharing memory with buffer. */
  private static ByteBuffer slice(ByteBuffer buffer, int offset, int length) {
    ByteBuffer view = buffer.duplicate();
    view.position(offset);
    view.limit(offset + length);
    return view.slice();
  }

  private static byte[] range(byte[] bytes, int from, int to) {
    return Arrays.copyOfRange(bytes, from, to);
  }

  private static long le32(byte[] v) {
    return (v[0] & 0xffL) | (v[1] & 0xffL) << 8 | (v[2] & 0xffL) << 16 | (v[3] & 0xffL) << 24;
  }

  private static long le64(byte[] v) {
    return le32(v) | le32(range(v, 4, 8)) << 32;
  }

  @Test
  @Order(1)
  public void vendored_vectors_are_unmodified() throws Exception {
    byte[] hash = MessageDigest.getInstance("SHA-512").digest(vectorsFile);
    assertEquals(VECTORS_SHA512, toHex(hash));
  }

  // Wipe

  @Test
  @Order(2)
  public void wipe() {
    Rng rng = new Rng();

    for (int i = 0; i < 50; i++) {
      byte[] original = rng.bytes(50);
      ByteBuffer buffer = buf(original);

      crypto_wipe(slice(buffer, 0, i));

      assertArrayEquals(new byte[i], range(bytes(buffer), 0, i));
      assertArrayEquals(range(original, i, 50), range(bytes(buffer), i, 50));
    }
  }

  // Constant time comparison

  private interface Verify {
    int apply(ByteBuffer a, ByteBuffer b);
  }

  private static void verify(int size, Verify verify) {
    for (int i = 0; i < 2; i++) {
      for (int j = 0; j < 2; j++) {
        byte[] a = new byte[size];
        byte[] b = new byte[size];
        Arrays.fill(a, (byte) i);
        Arrays.fill(b, (byte) j);
        assertEquals(i == j ? 0 : -1, verify.apply(buf(a), buf(b)));

        for (int k = 0; k < size / 2; k++) {
          a = new byte[size];
          b = new byte[size];
          a[k] = (byte) i;
          a[k + size / 2 - 1] = (byte) i;
          b[k] = (byte) j;
          b[k + size / 2 - 1] = (byte) j;
          assertEquals(i == j ? 0 : -1, verify.apply(buf(a), buf(b)));
        }
      }
    }
  }

  @Test
  @Order(3)
  public void verify16() {
    verify(16, Monocypher::crypto_verify16);
  }

  @Test
  @Order(4)
  public void verify32() {
    verify(32, Monocypher::crypto_verify32);
  }

  @Test
  @Order(5)
  public void verify64() {
    verify(64, Monocypher::crypto_verify64);
  }

  // Chacha20

  private interface Chacha {
    long apply(ByteBuffer cipher_text, ByteBuffer plain_text, ByteBuffer key, ByteBuffer nonce, long ctr);
  }

  /** ctrMask keeps the low 32 bits of the counter for IETF, whose counter is a uint32_t. */
  private static void chachaVectors(String name, int cases, Chacha chacha, boolean ietf) {
    long ctrMask = ietf ? 0xffffffffL : -1L;

    for (byte[][] t : vectors(name, 5, cases)) {
      byte[] plain = t[2];
      long ctr = ietf ? le32(t[3]) : le64(t[3]);
      long nbBlocks = plain.length / 64 + (plain.length % 64 != 0 ? 1 : 0);
      ByteBuffer output = out(plain.length);

      long newCtr = chacha.apply(output, buf(plain), buf(t[0]), buf(t[1]), ctr);

      assertArrayEquals(t[4], bytes(output));
      assertEquals(nbBlocks, (newCtr - ctr) & ctrMask);
    }
  }

  private static void chachaCtr(Chacha chacha, int nonceSize) {
    Rng rng = new Rng();
    ByteBuffer key = rng.buffer(32);
    ByteBuffer nonce = rng.buffer(nonceSize);
    ByteBuffer plain = rng.buffer(128);
    ByteBuffer full = out(128);
    ByteBuffer out1 = out(64);
    ByteBuffer out2 = out(64);

    chacha.apply(full, plain, key, nonce, 0);
    chacha.apply(out1, slice(plain, 0, 64), key, nonce, 0);
    chacha.apply(out2, slice(plain, 64, 64), key, nonce, 1);

    assertArrayEquals(bytes(slice(full, 0, 64)), bytes(out1));
    assertArrayEquals(bytes(slice(full, 64, 64)), bytes(out2));
  }

  @Test
  @Order(10)
  public void chacha20_vectors() {
    chachaVectors("chacha20", 136, Monocypher::crypto_chacha20_djb, false);
  }

  @Test
  @Order(11)
  public void chacha20_ctr() {
    chachaCtr(Monocypher::crypto_chacha20_djb, 8);
  }

  @Test
  @Order(12)
  public void chacha20_null_is_zeroes() {
    int inputSize = 64 * 2 + 1;
    Rng rng = new Rng();

    for (int i = 0; i < inputSize; i++) {
      ByteBuffer key = rng.buffer(32);
      ByteBuffer nonce = rng.buffer(8);
      ByteBuffer normal = out(i);
      ByteBuffer stream = out(i);

      crypto_chacha20_djb(normal, out(i), key, nonce, 0);
      crypto_chacha20_djb(stream, null, key, nonce, 0);

      assertArrayEquals(bytes(normal), bytes(stream));
    }
  }

  @Test
  @Order(13)
  public void chacha20_output_is_input() {
    int inputSize = 64 * 4;
    Rng rng = new Rng();
    ByteBuffer input = rng.buffer(inputSize);
    ByteBuffer key = rng.buffer(32);
    ByteBuffer nonce = rng.buffer(8);
    ByteBuffer output = out(inputSize);

    crypto_chacha20_djb(output, input, key, nonce, 0);
    crypto_chacha20_djb(input, input, key, nonce, 0);

    assertArrayEquals(bytes(output), bytes(input));
  }

  @Test
  @Order(14)
  public void ietf_chacha20_vectors() {
    chachaVectors("ietf_chacha20", 128, Monocypher::crypto_chacha20_ietf, true);
  }

  @Test
  @Order(15)
  public void ietf_chacha20_ctr() {
    chachaCtr(Monocypher::crypto_chacha20_ietf, 12);
  }

  @Test
  @Order(16)
  public void xchacha20_vectors() {
    chachaVectors("xchacha20", 131, Monocypher::crypto_chacha20_x, false);
  }

  @Test
  @Order(17)
  public void xchacha20_ctr() {
    chachaCtr(Monocypher::crypto_chacha20_x, 24);
  }

  @Test
  @Order(18)
  public void hchacha20_vectors() {
    for (byte[][] t : vectors("hchacha20", 3, 50)) {
      ByteBuffer output = out(32);
      crypto_chacha20_h(output, buf(t[0]), buf(t[1]));
      assertArrayEquals(t[2], bytes(output));
    }
  }

  @Test
  @Order(19)
  public void hchacha20_overlap() {
    Rng rng = new Rng();

    for (int i = 0; i < 100; i++) {
      ByteBuffer buffer = rng.buffer(80);
      int outIdx = rng.below(48);
      int keyIdx = rng.below(48);
      int inIdx = rng.below(64);
      ByteBuffer key = buf(bytes(slice(buffer, keyIdx, 32)));
      ByteBuffer in = buf(bytes(slice(buffer, inIdx, 16)));
      ByteBuffer separate = out(32);

      crypto_chacha20_h(separate, key, in);
      crypto_chacha20_h(slice(buffer, outIdx, 32), slice(buffer, keyIdx, 32), slice(buffer, inIdx, 16));

      assertArrayEquals(bytes(separate), bytes(slice(buffer, outIdx, 32)));
    }
  }

  // Poly1305

  @Test
  @Order(20)
  public void poly1305_vectors() {
    for (byte[][] t : vectors("poly1305", 3, 48)) {
      ByteBuffer mac = out(16);
      crypto_poly1305(mac, buf(t[1]), buf(t[0]));
      assertArrayEquals(t[2], bytes(mac));
    }
  }

  @Test
  @Order(21)
  public void poly1305_incremental() {
    int inputSize = 16 * 4;
    Rng rng = new Rng();

    for (int i = 0; i < inputSize; i++) {
      ByteBuffer input = rng.buffer(inputSize);
      ByteBuffer key = rng.buffer(32);
      ByteBuffer chunk = out(16);
      ByteBuffer whole = out(16);

      try (Poly1305_ctx ctx = new Poly1305_ctx()) {
        crypto_poly1305_init(ctx, key);
        crypto_poly1305_update(ctx, slice(input, 0, i));
        crypto_poly1305_update(ctx, slice(input, i, inputSize - i));
        crypto_poly1305_final(ctx, chunk);
      }
      crypto_poly1305(whole, input, key);

      assertArrayEquals(bytes(whole), bytes(chunk));
    }
  }

  @Test
  @Order(22)
  public void poly1305_overlapping_io() {
    int inputSize = 16 + 2 * 16;
    Rng rng = new Rng();

    for (int i = 0; i < 16 + 16; i++) {
      ByteBuffer input = rng.buffer(inputSize);
      ByteBuffer key = rng.buffer(32);
      ByteBuffer mac = out(16);

      crypto_poly1305(mac, slice(input, 16, 16), key);
      crypto_poly1305(slice(input, i, 16), slice(input, 16, 16), key);

      assertArrayEquals(bytes(mac), bytes(slice(input, i, 16)));
    }
  }

  // Authenticated encryption

  @Test
  @Order(30)
  public void aead_ietf_vectors() {
    for (byte[][] t : vectors("aead_ietf", 5, 320)) {
      ByteBuffer output = out(t[3].length);
      ByteBuffer mac = out(16);

      crypto_aead_lock(output, mac, buf(t[0]), buf(t[1]), buf(t[2]), buf(t[3]));

      assertArrayEquals(range(t[4], 16, t[4].length), bytes(output));
      assertArrayEquals(range(t[4], 0, 16), bytes(mac));
    }
  }

  @Test
  @Order(31)
  public void aead_8439_vectors() {
    for (byte[][] t : vectors("aead_8439", 5, 320)) {
      ByteBuffer output = out(t[3].length);
      ByteBuffer mac = out(16);

      try (AEAD_ctx ctx = new AEAD_ctx()) {
        crypto_aead_init_ietf(ctx, buf(t[0]), buf(t[1]));
        crypto_aead_write(ctx, output, mac, buf(t[2]), buf(t[3]));
      }

      assertArrayEquals(range(t[4], 16, t[4].length), bytes(output));
      assertArrayEquals(range(t[4], 0, 16), bytes(mac));
    }
  }

  @Test
  @Order(32)
  public void aead_roundtrip() {
    Rng rng = new Rng();

    for (int i = 0; i < 1000; i++) {
      ByteBuffer key = rng.buffer(32);
      ByteBuffer nonce = rng.buffer(24);
      ByteBuffer ad = rng.buffer(4);
      ByteBuffer plain = rng.buffer(8);
      ByteBuffer cipher = out(8);
      ByteBuffer mac = out(16);
      ByteBuffer output = out(8);

      crypto_aead_lock(cipher, mac, key, nonce, ad, plain);
      assertEquals(0, crypto_aead_unlock(output, mac, key, nonce, ad, cipher));
      assertArrayEquals(bytes(plain), bytes(output));

      mac.put(0, (byte) (mac.get(0) + 1));
      assertEquals(-1, crypto_aead_unlock(output, mac, key, nonce, ad, cipher));
    }
  }

  private static void aeadStep(AEAD_ctx a, AEAD_ctx b, ByteBuffer ad, ByteBuffer plain) {
    ByteBuffer mac = out(16);
    ByteBuffer cipher = out(8);
    ByteBuffer output = out(8);

    crypto_aead_write(a, cipher, mac, ad, plain);
    assertEquals(0, crypto_aead_read(b, output, mac, ad, cipher));
    assertArrayEquals(bytes(plain), bytes(output));
  }

  @Test
  @Order(33)
  public void aead_incremental_roundtrip() {
    Rng rng = new Rng();

    for (int i = 0; i < 50; i++) {
      ByteBuffer key = rng.buffer(32);
      ByteBuffer nonce = rng.buffer(24);

      try (AEAD_ctx xa = new AEAD_ctx();
          AEAD_ctx xb = new AEAD_ctx();
          AEAD_ctx da = new AEAD_ctx();
          AEAD_ctx db = new AEAD_ctx();
          AEAD_ctx ia = new AEAD_ctx();
          AEAD_ctx ib = new AEAD_ctx()) {
        crypto_aead_init_x(xa, key, nonce);
        crypto_aead_init_x(xb, key, nonce);
        crypto_aead_init_djb(da, key, slice(nonce, 0, 8));
        crypto_aead_init_djb(db, key, slice(nonce, 0, 8));
        crypto_aead_init_ietf(ia, key, slice(nonce, 0, 12));
        crypto_aead_init_ietf(ib, key, slice(nonce, 0, 12));

        for (int j = 0; j < 10; j++) {
          ByteBuffer ad = rng.buffer(4);
          ByteBuffer plain = rng.buffer(8);

          aeadStep(xa, xb, ad, plain);
          assertTrue(ctxSameStruct(xa, xb));
          aeadStep(da, db, ad, plain);
          aeadStep(ia, ib, ad, plain);
        }
      }
    }
  }

  // BLAKE2b

  @Test
  @Order(40)
  public void blake2b_vectors() {
    int skipped = 0;

    for (byte[][] t : vectors("blake2b", 3, 681)) {
      if (t[2].length == 0) {
        skipped++;
        continue;
      }
      ByteBuffer hash = out(t[2].length);
      crypto_blake2b_keyed(hash, buf(t[1]), buf(t[0]));
      assertArrayEquals(t[2], bytes(hash));
    }

    assertEquals(85, skipped);
  }

  @Test
  @Order(41)
  public void blake2b_zero_input() {
    Rng rng = new Rng();
    ByteBuffer key = rng.buffer(32);
    ByteBuffer chunk = out(64);
    ByteBuffer whole = out(64);

    try (Blake2b_ctx ctx = new Blake2b_ctx()) {
      ctxFill(ctx, (byte) 0x5c);
      crypto_blake2b_keyed_init(ctx, 64, key);
      crypto_blake2b_final(ctx, chunk);
      crypto_blake2b_keyed(whole, key, out(0));
      assertArrayEquals(bytes(whole), bytes(chunk));

      ctxFill(ctx, (byte) 0x5c);
      crypto_blake2b_init(ctx, 64);
      crypto_blake2b_final(ctx, chunk);
      crypto_blake2b(whole, out(0));
      assertArrayEquals(bytes(whole), bytes(chunk));
    }
  }

  @Test
  @Order(42)
  public void blake2b_incremental() {
    int inputSize = 128 * 3;
    ByteBuffer input = new Rng().buffer(inputSize);
    ByteBuffer whole = out(64);
    ByteBuffer chunk = out(64);
    crypto_blake2b(whole, input);

    try (Blake2b_ctx ctx = new Blake2b_ctx()) {
      for (int j = 0; j < inputSize; j++) {
        for (int i = 0; i <= j; i++) {
          crypto_blake2b_init(ctx, 64);
          crypto_blake2b_update(ctx, slice(input, 0, i));
          crypto_blake2b_update(ctx, slice(input, i, j - i));
          crypto_blake2b_update(ctx, slice(input, j, inputSize - j));
          crypto_blake2b_final(ctx, chunk);

          assertArrayEquals(bytes(whole), bytes(chunk));
        }
      }
    }
  }

  @Test
  @Order(43)
  public void blake2b_overlapping_io() {
    int inputSize = 128 + 2 * 64;
    Rng rng = new Rng();

    for (int i = 0; i < 128 + 64; i++) {
      ByteBuffer input = rng.buffer(inputSize);
      ByteBuffer hash = out(64);

      crypto_blake2b(hash, slice(input, 64, 128));
      crypto_blake2b(slice(input, i, 64), slice(input, 64, 128));

      assertArrayEquals(bytes(hash), bytes(slice(input, i, 64)));
    }
  }

  // Argon2

  @Test
  @Order(50)
  public void argon2_vectors() {
    for (byte[][] t : vectors("argon2", 9, 28)) {
      crypto_argon2_algorithm algorithm = crypto_argon2_algorithm.values()[(int) le32(t[0])];
      int nbBlocks = (int) le32(t[1]);
      Argon2_config config =
          new Argon2_config(algorithm, nbBlocks, (int) le32(t[2]), (int) le32(t[3]));
      ByteBuffer hash = out(t[8].length);

      crypto_argon2(
          hash,
          out(nbBlocks * 1024),
          config,
          new Argon2_inputs(buf(t[4]), buf(t[5])),
          new Argon2_extras(buf(t[6]), buf(t[7])));

      assertArrayEquals(t[8], bytes(hash));
    }
  }

  @Test
  @Order(51)
  public void argon2_overlapping_io() {
    Rng rng = new Rng();
    Argon2_config config = new Argon2_config(CRYPTO_ARGON2_I, 8, 1, 1);

    for (int i = 0; i < 10; i++) {
      ByteBuffer shared = rng.buffer(8 * 1024);
      int passOffset = rng.below(64);
      int saltOffset = rng.below(64);
      int keyOffset = rng.below(64);
      int adOffset = rng.below(64);
      ByteBuffer pass = slice(shared, passOffset, 16);
      ByteBuffer salt = slice(shared, saltOffset, 16);
      ByteBuffer key = slice(shared, keyOffset, 32);
      ByteBuffer ad = slice(shared, adOffset, 32);
      ByteBuffer hash1 = out(32);
      ByteBuffer hash2 = out(32);

      crypto_argon2(
          hash1,
          out(8 * 1024),
          config,
          new Argon2_inputs(buf(bytes(pass)), buf(bytes(salt))),
          new Argon2_extras(buf(bytes(key)), buf(bytes(ad))));

      // The inputs overlap each other, as the manual allows.
      crypto_argon2(
          hash2, out(8 * 1024), config, new Argon2_inputs(pass, salt), new Argon2_extras(key, ad));

      assertArrayEquals(bytes(hash1), bytes(hash2));

      // Upstream also overlaps the hash and inputs with the work area. The binding rejects that.
      ByteBuffer workArea = out(8 * 1024);
      assertThrows(
          IllegalArgumentException.class,
          () ->
              crypto_argon2(
                  slice(workArea, 0, 32),
                  workArea,
                  config,
                  new Argon2_inputs(pass, salt),
                  new Argon2_extras(key, ad)));
      assertThrows(
          IllegalArgumentException.class,
          () ->
              crypto_argon2(
                  out(32),
                  workArea,
                  config,
                  new Argon2_inputs(slice(workArea, passOffset, 16), salt),
                  new Argon2_extras(key, ad)));
    }
  }

  // X25519

  @Test
  @Order(60)
  public void x25519_vectors() {
    for (byte[][] t : vectors("x25519", 3, 623)) {
      ByteBuffer output = out(32);
      crypto_x25519(output, buf(t[0]), buf(t[1]));
      assertArrayEquals(t[2], bytes(output));
    }
  }

  @Test
  @Order(61)
  public void x25519_pk_vectors() {
    for (byte[][] t : vectors("x25519_pk", 2, 51)) {
      ByteBuffer output = out(32);
      crypto_x25519_public_key(output, buf(t[0]));
      assertArrayEquals(t[1], bytes(output));
    }
  }

  @Test
  @Order(62)
  public void x25519_1_and_1k() {
    byte[] u = new byte[32];
    u[0] = 9;
    ByteBuffer k = out(32);

    crypto_x25519_public_key(k, buf(u));
    assertEquals("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", toHex(k));

    for (int i = 1; i < 1000; i++) {
      ByteBuffer tmp = out(32);
      crypto_x25519(tmp, k, buf(u));
      u = bytes(k);
      k = tmp;
    }
    assertEquals("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", toHex(k));
  }

  @Test
  @Order(63)
  public void x25519_overlapping_io() {
    Rng rng = new Rng();

    for (int i = 0; i < 62; i++) {
      ByteBuffer overlapping = out(94);
      ByteBuffer separate = out(32);
      byte[] sk = rng.bytes(32);
      ByteBuffer pk = rng.buffer(32);
      slice(overlapping, 31, 32).put(sk);

      crypto_x25519(slice(overlapping, i, 32), slice(overlapping, 31, 32), pk);
      crypto_x25519(separate, buf(sk), pk);

      assertArrayEquals(bytes(separate), bytes(slice(overlapping, i, 32)));
    }
  }

  @Test
  @Order(64)
  public void x25519_inverse() {
    Rng rng = new Rng();
    ByteBuffer base = out(32);
    crypto_x25519_public_key(base, rng.buffer(32));

    for (int i = 0; i < 50; i++) {
      ByteBuffer sk = rng.buffer(32);
      ByteBuffer pk = out(32);
      ByteBuffer blind = out(32);

      crypto_x25519(pk, sk, base);
      crypto_x25519_inverse(blind, sk, pk);

      assertArrayEquals(bytes(base), bytes(blind));
    }

    byte[] one = new byte[32];
    one[0] = 1;
    byte[][] lowOrder = {
      new byte[32],
      one,
      fromHexToByteArray("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
      fromHexToByteArray("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    };

    for (int i = 0; i < 32; i++) {
      ByteBuffer blind = out(32);
      crypto_x25519_inverse(blind, rng.buffer(32), buf(lowOrder[i % 4]));
      assertArrayEquals(new byte[32], bytes(blind));
    }
  }

  @Test
  @Order(65)
  public void x25519_inverse_overlapping_io() {
    Rng rng = new Rng();

    for (int i = 0; i < 62; i++) {
      ByteBuffer overlapping = out(94);
      ByteBuffer separate = out(32);
      byte[] sk = rng.bytes(32);
      ByteBuffer pk = rng.buffer(32);
      slice(overlapping, 31, 32).put(sk);

      crypto_x25519_inverse(slice(overlapping, i, 32), slice(overlapping, 31, 32), pk);
      crypto_x25519_inverse(separate, buf(sk), pk);

      assertArrayEquals(bytes(separate), bytes(slice(overlapping, i, 32)));
    }
  }

  // EdDSA utils

  /** Adds L * factor to a little-endian scalar, which must not overflow 256 bits. */
  private static byte[] addXL(byte[] in, int factor) {
    byte[] out = new byte[32];
    int acc = 0;

    assertTrue(factor <= 8);
    for (int i = 0; i < 32; i++) {
      acc += (in[i] & 0xff) + (L[i] & 0xff) * factor;
      out[i] = (byte) acc;
      acc >>>= 8;
    }
    assertEquals(0, acc);

    return out;
  }

  @Test
  @Order(70)
  public void eddsa_scalarbase() {
    Rng rng = new Rng();

    for (int i = 0; i < 50; i++) {
      byte[] scalar = rng.bytes(32);
      scalar[31] &= 0xf;
      byte[] scalarPlus = addXL(scalar, 8);
      assertFalse(Arrays.equals(scalar, scalarPlus));

      ByteBuffer point = out(32);
      ByteBuffer pointPlus = out(32);
      crypto_eddsa_scalarbase(point, buf(scalar));
      crypto_eddsa_scalarbase(pointPlus, buf(scalarPlus));

      assertArrayEquals(bytes(point), bytes(pointPlus));
    }
  }

  // EdDSA

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  @Test
  @Order(71)
  public void eddsa_vectors() {
    for (byte[][] t : vectors("edDSA", 4, 256)) {
      ByteBuffer signature = out(64);
      crypto_eddsa_sign(signature, buf(concat(t[0], t[1])), buf(t[2]));
      assertArrayEquals(t[3], bytes(signature));
    }
  }

  @Test
  @Order(72)
  public void eddsa_pk_vectors() {
    for (byte[][] t : vectors("edDSA_pk", 2, 257)) {
      ByteBuffer seed = buf(t[0]);
      ByteBuffer secretKey = out(64);
      ByteBuffer publicKey = out(32);

      crypto_eddsa_key_pair(secretKey, publicKey, seed);

      assertArrayEquals(t[1], bytes(publicKey));
      assertArrayEquals(new byte[32], bytes(seed));
      assertArrayEquals(t[0], bytes(slice(secretKey, 0, 32)));
      assertArrayEquals(bytes(publicKey), bytes(slice(secretKey, 32, 32)));
    }
  }

  @Test
  @Order(73)
  public void eddsa_roundtrip() {
    int messageSize = 30;
    Rng rng = new Rng();

    for (int i = 0; i < messageSize; i++) {
      ByteBuffer message = slice(rng.buffer(messageSize), 0, i);
      ByteBuffer seed = rng.buffer(32);
      ByteBuffer sk = out(64);
      ByteBuffer pk = out(32);
      ByteBuffer signature = out(64);

      crypto_eddsa_key_pair(sk, pk, seed);
      crypto_eddsa_sign(signature, sk, message);
      assertEquals(0, crypto_eddsa_check(signature, pk, message));

      assertEquals(-1, crypto_eddsa_check(out(64), pk, message));
      for (int j = 0; j < 64; j++) {
        byte[] forgery = bytes(signature);
        forgery[j]++;
        assertEquals(-1, crypto_eddsa_check(buf(forgery), pk, message));
      }
    }
  }

  @Test
  @Order(74)
  public void eddsa_random() {
    int messageSize = 30;
    Rng rng = new Rng();

    for (int i = 0; i < 100; i++) {
      ByteBuffer message = rng.buffer(messageSize);
      ByteBuffer pk = rng.buffer(32);
      ByteBuffer signature = rng.buffer(64);

      assertEquals(-1, crypto_eddsa_check(signature, pk, message));
    }

    // S == L
    ByteBuffer message = rng.buffer(messageSize);
    ByteBuffer pk = rng.buffer(32);
    ByteBuffer signature = buf(concat(new byte[32], L));

    assertEquals(-1, crypto_eddsa_check(signature, pk, message));
  }

  @Test
  @Order(75)
  public void eddsa_overlap() {
    int messageSize = 30;
    Rng rng = new Rng();

    for (int i = 0; i < messageSize + 64; i++) {
      ByteBuffer input = rng.buffer(messageSize + 2 * 64);
      ByteBuffer seed = rng.buffer(32);
      ByteBuffer sk = out(64);
      ByteBuffer pk = out(32);
      ByteBuffer signature = out(64);

      crypto_eddsa_key_pair(sk, pk, seed);
      crypto_eddsa_sign(signature, sk, slice(input, 64, messageSize));
      crypto_eddsa_sign(slice(input, i, 64), sk, slice(input, 64, messageSize));

      assertArrayEquals(bytes(signature), bytes(slice(input, i, 64)));
    }
  }

  // Elligator

  @Test
  @Order(80)
  public void elligator_dir_vectors() {
    for (byte[][] t : vectors("elligator_dir", 2, 92)) {
      ByteBuffer curve = out(32);
      crypto_elligator_map(curve, buf(t[0]));
      assertArrayEquals(t[1], bytes(curve));
    }
  }

  @Test
  @Order(81)
  public void elligator_direct_msb() {
    Rng rng = new Rng();

    for (int i = 0; i < 20; i++) {
      byte[] r = rng.bytes(32);
      ByteBuffer u = out(32);
      crypto_elligator_map(u, buf(r));

      for (int msb : new int[] {0x00, 0x40, 0x80, 0xc0}) {
        byte[] other = r.clone();
        other[31] = (byte) ((r[31] & 0x3f) | msb);
        ByteBuffer otherU = out(32);

        crypto_elligator_map(otherU, buf(other));

        assertArrayEquals(bytes(u), bytes(otherU));
      }
    }
  }

  @Test
  @Order(82)
  public void elligator_direct_overlapping_io() {
    Rng rng = new Rng();

    for (int i = 0; i < 62; i++) {
      ByteBuffer overlapping = out(94);
      ByteBuffer separate = out(32);
      byte[] r = rng.bytes(32);
      slice(overlapping, 31, 32).put(r);

      crypto_elligator_map(slice(overlapping, i, 32), slice(overlapping, 31, 32));
      crypto_elligator_map(separate, buf(r));

      assertArrayEquals(bytes(separate), bytes(slice(overlapping, i, 32)));
    }
  }

  @Test
  @Order(83)
  public void elligator_inv_vectors() {
    for (byte[][] t : vectors("elligator_inv", 4, 77)) {
      ByteBuffer hidden = out(32);
      int check = crypto_elligator_rev(hidden, buf(t[0]), t[1][0] & 0xff);

      assertEquals(t[2][0], (byte) check);
      if (t[3].length != 0) {
        assertArrayEquals(t[3], bytes(hidden));
      }
    }
  }

  @Test
  @Order(84)
  public void elligator_inverse_overlapping_io() {
    Rng rng = new Rng();

    for (int i = 0; i < 62; i++) {
      ByteBuffer overlapping = out(94);
      ByteBuffer separate = out(32);
      byte[] pk = rng.bytes(33);
      int tweak = pk[32] & 0xff;
      slice(overlapping, 31, 32).put(pk, 0, 32);

      int a = crypto_elligator_rev(slice(overlapping, i, 32), slice(overlapping, 31, 32), tweak);
      int b = crypto_elligator_rev(separate, buf(range(pk, 0, 32)), tweak);

      assertEquals(b, a);
      if (a == 0) {
        // The buffers are the same only if written to to begin with
        assertArrayEquals(bytes(separate), bytes(slice(overlapping, i, 32)));
      }
    }
  }

  @Test
  @Order(85)
  public void elligator_x25519() {
    Rng rng = new Rng();
    int i = 0;

    while (i < 64) {
      byte[] sk1 = rng.bytes(32);
      ByteBuffer sk2 = rng.buffer(32);
      byte[] skc = sk1.clone();
      skc[0] &= (byte) 248;
      ByteBuffer pks = out(32);
      ByteBuffer pksc = out(32);
      ByteBuffer pkf = out(32);
      ByteBuffer pkfc = out(32);
      ByteBuffer pk1 = out(32);

      crypto_x25519_dirty_small(pks, buf(sk1));
      crypto_x25519_dirty_small(pksc, buf(skc));
      crypto_x25519_dirty_fast(pkf, buf(sk1));
      crypto_x25519_dirty_fast(pkfc, buf(skc));
      crypto_x25519_public_key(pk1, buf(sk1));

      assertArrayEquals(bytes(pks), bytes(pkf));
      assertArrayEquals(bytes(pksc), bytes(pk1));
      assertArrayEquals(bytes(pkfc), bytes(pk1));
      if ((sk1[0] & 7) == 0) {
        assertArrayEquals(bytes(pk1), bytes(pkf));
      } else {
        assertFalse(Arrays.equals(bytes(pk1), bytes(pkf)));
      }

      int tweak = ((i & 1) + (i << 5)) & 0xff;
      ByteBuffer r = out(32);
      if (crypto_elligator_rev(r, pkf, tweak) != 0) {
        continue;
      }
      assertEquals(tweak >> 6, (r.get(31) & 0xff) >> 6);

      ByteBuffer pkr = out(32);
      crypto_elligator_map(pkr, r);
      assertArrayEquals(bytes(pkf), bytes(pkr));

      ByteBuffer e1 = out(32);
      ByteBuffer e2 = out(32);
      crypto_x25519(e1, sk2, pk1);
      crypto_x25519(e2, sk2, pkr);
      assertArrayEquals(bytes(e1), bytes(e2));

      i++;
    }
  }

  @Test
  @Order(86)
  public void elligator_key_pair() {
    Rng rng = new Rng();

    for (int i = 0; i < 32; i++) {
      ByteBuffer seed = rng.buffer(32);
      ByteBuffer sk2 = rng.buffer(32);
      ByteBuffer r = out(32);
      ByteBuffer sk1 = out(32);
      ByteBuffer pkr = out(32);
      ByteBuffer pk1 = out(32);
      ByteBuffer e1 = out(32);
      ByteBuffer e2 = out(32);

      crypto_elligator_key_pair(r, sk1, seed);
      crypto_elligator_map(pkr, r);
      crypto_x25519_public_key(pk1, sk1);
      crypto_x25519(e1, sk2, pk1);
      crypto_x25519(e2, sk2, pkr);

      assertArrayEquals(bytes(e1), bytes(e2));
    }
  }

  @Test
  @Order(87)
  public void elligator_key_pair_overlapping_io() {
    Rng rng = new Rng();

    for (int i = 0; i < 94; i++) {
      ByteBuffer over = out(158);
      ByteBuffer sep = out(64);
      byte[] s1 = rng.bytes(32);
      ByteBuffer s2 = slice(over, 63, 32);
      s2.duplicate().put(s1);

      crypto_elligator_key_pair(slice(sep, 0, 32), slice(sep, 32, 32), buf(s1));
      crypto_elligator_key_pair(slice(over, i, 32), slice(over, i + 32, 32), s2);

      assertArrayEquals(bytes(sep), bytes(slice(over, i, 64)));
    }
  }

  // X25519 <-> EdDSA

  @Test
  @Order(90)
  public void x25519_eddsa_conversions() {
    Rng rng = new Rng();

    for (int i = 0; i < 32; i++) {
      ByteBuffer seed = rng.buffer(32);
      ByteBuffer secret = out(64);
      ByteBuffer ePublic1 = out(32);
      crypto_eddsa_key_pair(secret, ePublic1, seed);

      ByteBuffer xPrivate = out(64);
      crypto_blake2b(xPrivate, slice(secret, 0, 32));

      ByteBuffer xPublic1 = out(32);
      ByteBuffer xPublic2 = out(32);
      ByteBuffer ePublic2 = out(32);
      crypto_eddsa_to_x25519(xPublic1, ePublic1);
      crypto_x25519_public_key(xPublic2, slice(xPrivate, 0, 32));
      assertArrayEquals(bytes(xPublic1), bytes(xPublic2));

      crypto_x25519_to_eddsa(ePublic2, xPublic1);
      assertEquals(0, ePublic2.get(31) & 0x80);

      ePublic1.put(31, (byte) (ePublic1.get(31) & 0x7f));
      assertArrayEquals(bytes(ePublic1), bytes(ePublic2));
    }
  }
}
