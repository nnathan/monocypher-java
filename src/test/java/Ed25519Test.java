import static net.lastninja.monocypher.Monocypher.*;
import static net.lastninja.monocypher.TestUtil.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Ed25519Test {

  private static ByteBuffer buf(int size) {
    return ByteBuffer.allocateDirect(size);
  }

  private static void assertIae(Executable e) {
    assertThrows(IllegalArgumentException.class, e);
  }

  private static ByteBuffer sha512(ByteBuffer message) {
    ByteBuffer hash = buf(64);
    crypto_sha512(hash, message);
    return hash;
  }

  /** Returns {secret_key, public_key} for a seed, leaving the seed untouched. */
  private static ByteBuffer[] keyPair(String seedHex) {
    ByteBuffer sk = buf(64);
    ByteBuffer pk = buf(32);
    crypto_ed25519_key_pair(sk, pk, fromHexToByteBuffer(seedHex));
    return new ByteBuffer[] {sk, pk};
  }

  @Test
  @Order(1)
  public void test_crypto_ed25519_rfc8032_test_1() {
    String seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    String expectedPk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    String expectedSig =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
            + "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    ByteBuffer seedBuf = fromHexToByteBuffer(seed);
    ByteBuffer sk = buf(64);
    ByteBuffer pk = buf(32);
    crypto_ed25519_key_pair(sk, pk, seedBuf);
    assertEquals(expectedPk, toHex(pk));
    assertEquals(seed + expectedPk, toHex(sk));
    assertEquals(toHex(buf(32)), toHex(seedBuf), "seed not wiped");

    ByteBuffer sig = buf(64);
    crypto_ed25519_sign(sig, sk, null);
    assertEquals(expectedSig, toHex(sig));
    assertEquals(0, crypto_ed25519_check(sig, pk, null));
    assertEquals(0, crypto_ed25519_check(sig, pk, buf(0)));
    assertEquals(-1, crypto_ed25519_check(sig, pk, buf(1)));
  }

  @Test
  @Order(2)
  public void test_crypto_ed25519_ph_rfc8032_abc() {
    ByteBuffer[] keys = keyPair("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    assertEquals("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf", toHex(keys[1]));

    ByteBuffer hash = sha512(fromHexToByteBuffer("616263"));
    ByteBuffer sig = buf(64);
    crypto_ed25519_ph_sign(sig, keys[0], hash);
    assertEquals(
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
            + "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
        toHex(sig));
    assertEquals(0, crypto_ed25519_ph_check(sig, keys[1], hash));

    hash.put(0, (byte) (hash.get(0) ^ 1));
    assertEquals(-1, crypto_ed25519_ph_check(sig, keys[1], hash));
  }

  @Test
  @Order(3)
  public void test_ed25519_and_eddsa_differ() {
    // Same seed, different hash: the BLAKE2b and SHA-512 variants must not be interchangeable.
    String seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    ByteBuffer[] ed = keyPair(seed);
    ByteBuffer eddsaSk = buf(64);
    ByteBuffer eddsaPk = buf(32);
    crypto_eddsa_key_pair(eddsaSk, eddsaPk, fromHexToByteBuffer(seed));
    assertNotEquals(toHex(ed[1]), toHex(eddsaPk));
  }

  @Test
  @Order(100)
  public void test_rejects_bad_arguments() {
    assertIae(() -> crypto_ed25519_key_pair(buf(63), buf(32), buf(32)));
    assertIae(() -> crypto_ed25519_key_pair(buf(64), buf(31), buf(32)));
    assertIae(() -> crypto_ed25519_key_pair(buf(64), buf(32), buf(33)));
    assertIae(() -> crypto_ed25519_key_pair(buf(64), buf(32), buf(32).asReadOnlyBuffer()));
    assertThrows(NullPointerException.class, () -> crypto_ed25519_key_pair(buf(64), buf(32), null));

    assertIae(() -> crypto_ed25519_sign(buf(63), buf(64), null));
    assertIae(() -> crypto_ed25519_sign(buf(64), buf(32), null));
    assertIae(() -> crypto_ed25519_sign(buf(64).asReadOnlyBuffer(), buf(64), null));
    assertIae(() -> crypto_ed25519_check(buf(64), buf(31), null));
    assertIae(() -> crypto_ed25519_check(buf(65), buf(32), null));
    assertIae(() -> crypto_ed25519_check(buf(64), buf(32), ByteBuffer.allocate(4)));

    assertIae(() -> crypto_ed25519_ph_sign(buf(64), buf(64), buf(32)));
    assertIae(() -> crypto_ed25519_ph_check(buf(64), buf(32), buf(65)));
    assertThrows(NullPointerException.class, () -> crypto_ed25519_ph_sign(buf(64), buf(64), null));
    assertThrows(NullPointerException.class, () -> crypto_ed25519_ph_check(buf(64), buf(32), null));
  }

  @Test
  @Order(101)
  public void test_signature_may_overlap_message() {
    ByteBuffer[] keys = keyPair("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    ByteBuffer shared = buf(160);
    for (int i = 0; i < 160; i++) shared.put(i, (byte) i);

    ByteBuffer message = shared.duplicate();
    message.position(64).limit(94);
    ByteBuffer expected = buf(64);
    crypto_ed25519_sign(expected, keys[0], message.slice());

    for (int i = 0; i < 94; i++) {
      for (int j = 0; j < 160; j++) shared.put(j, (byte) j);
      ByteBuffer sig = shared.duplicate();
      sig.position(i).limit(i + 64);
      crypto_ed25519_sign(sig.slice(), keys[0], message.slice());
      assertEquals(toHex(expected), toHex(sig.slice()), "offset " + i);
    }
  }
}
