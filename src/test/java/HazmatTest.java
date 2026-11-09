import static org.junit.jupiter.api.Assertions.*;
import static net.lastninja.monocypher.Hazmat.*;
import static net.lastninja.monocypher.Monocypher.*;
import static net.lastninja.monocypher.TestUtil.*;

import java.nio.ByteBuffer;
import net.lastninja.monocypher.Monocypher;
import net.lastninja.monocypher.Monocypher.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class HazmatTest {

  @Test
  @Order(30)
  public void test_crypto_trim_scalar() {
    // crypto_trim_scalar happy path
    {
      ByteBuffer in =
          fromHexToByteBuffer("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
      ByteBuffer out = ByteBuffer.allocateDirect(32);

      crypto_eddsa_trim_scalar(out, in);

      String expected = "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
      String actual = toHex(out);

      assertEquals(expected, actual, "out mismatch");
    }
  }

  @Test
  @Order(31)
  public void test_crypto_eddsa_reduce() {
    // crypto_eddsa_reduce happy path
    {
      ByteBuffer expanded =
          fromHexToByteBuffer(
              "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                  + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
      ByteBuffer reduced = ByteBuffer.allocateDirect(32);
      ;

      crypto_eddsa_reduce(reduced, expanded);

      String expected = "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903";
      String actual = toHex(reduced);

      assertEquals(expected, actual, "reduced mismatch");
    }
  }

  @Test
  @Order(32)
  public void test_crypto_eddsa_mul_add() {
    // crypto_eddsa_mul_add happy path
    {
      ByteBuffer a =
          fromHexToByteBuffer("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
      ByteBuffer b =
          fromHexToByteBuffer("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
      ByteBuffer c =
          fromHexToByteBuffer("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
      ByteBuffer r = ByteBuffer.allocateDirect(32);

      crypto_eddsa_mul_add(r, a, b, c);

      String expected = "2a05f60b2d496b1b6c6223f3c345190ee88483d888cca6371eacab86796f7802";
      String actual = toHex(r);

      assertEquals(expected, actual, "r mismatch");
    }
  }

  @Test
  @Order(33)
  public void test_crypto_eddsa_scalarbase() {
    // crypto_eddsa_scalarbase happy path
    {
      ByteBuffer scalar =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer point = ByteBuffer.allocateDirect(32);

      crypto_eddsa_scalarbase(point, scalar);

      String expected = "ca4a448c3fc4d04945da9fdf920976c05e9bbe3d8cebb1858ea44d587c5e63c3";
      String actual = toHex(point);

      assertEquals(expected, actual, "point mismatch");
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
  public void test_check_equation_matches_check() {
    ByteBuffer sk = buf(64);
    ByteBuffer pk = buf(32);
    crypto_eddsa_key_pair(sk, pk, counting(32, 9));
    ByteBuffer message = counting(50, 0);
    ByteBuffer signature = buf(64);
    crypto_eddsa_sign(signature, sk, message);

    // h_ram = reduce(BLAKE2b-512(R || public_key || message)), as crypto_eddsa_check does.
    ByteBuffer input = buf(32 + 32 + 50);
    for (int i = 0; i < 32; i++) input.put(i, signature.get(i));
    for (int i = 0; i < 32; i++) input.put(32 + i, pk.get(i));
    for (int i = 0; i < 50; i++) input.put(64 + i, message.get(i));
    ByteBuffer hash = buf(64);
    crypto_blake2b(hash, input);
    ByteBuffer h_ram = buf(32);
    crypto_eddsa_reduce(h_ram, hash);

    assertEquals(0, crypto_eddsa_check_equation(signature, pk, h_ram));
    h_ram.put(0, (byte) (h_ram.get(0) ^ 1));
    assertEquals(-1, crypto_eddsa_check_equation(signature, pk, h_ram));

    assertThrows(
        IllegalArgumentException.class,
        () -> crypto_eddsa_check_equation(buf(63), buf(32), buf(32)));
  }

  @Test
  @Order(101)
  public void test_hazmat_rejects_bad_sizes() {
    assertThrows(IllegalArgumentException.class, () -> crypto_eddsa_reduce(buf(32), buf(32)));
    assertThrows(IllegalArgumentException.class, () -> crypto_eddsa_trim_scalar(buf(31), buf(32)));
    assertThrows(
        IllegalArgumentException.class,
        () -> crypto_eddsa_mul_add(buf(32), buf(32), buf(32), buf(31)));
    assertThrows(
        IllegalArgumentException.class,
        () -> crypto_eddsa_scalarbase(buf(32).asReadOnlyBuffer(), buf(32)));
  }
}
