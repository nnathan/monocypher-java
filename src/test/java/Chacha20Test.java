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
public class Chacha20Test {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(34)
  public void test_crypto_chacha20_h() {
    // crypto_chacha20_h happy path
    {
      byte[] in = fromHexToByteArray("000102030405060708090a0b0c0d0e0f");
      byte[] key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] out = new byte[32];

      mc.crypto_chacha20_h(out, key, in);

      String expected = "51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6";
      String actual = toHex(out);

      assertEquals(expected, actual, "out mismatch");
    }
  }

  @Test
  @Order(35)
  public void test_crypto_chacha20_djb() {
    // crypto_chacha20_djb happy path
    {
      ByteBuffer plain_text =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  + "40");
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer nonce = fromHexToByteBuffer("0001020304050607");
      ByteBuffer cipher_text = ByteBuffer.allocateDirect(65);
      long text_size = cipher_text.remaining();

      long ctr = 0;

      ctr = mc.crypto_chacha20_djb(cipher_text, plain_text, text_size, key, nonce, ctr);

      String expected =
          "f799a38af590e06e8a1955f06806b97a6f468fb00217ea84f418b64de447ddde"
              + "14857658571e6066186be36f2c64394635e28c6ade2965c6612f2f6717d51a25"
              + "78";

      String actual = toHex(cipher_text);

      assertEquals(expected, actual, "cipher_text mismatch");

      long expected_ctr = 2;

      assertEquals(expected_ctr, ctr, "ctr mismatch");
    }

    // crypto_chacha20_djb incremental happy path
    {
      ByteBuffer plain_text =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  + "40");
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer nonce = fromHexToByteBuffer("0001020304050607");
      ByteBuffer cipher_text = ByteBuffer.allocateDirect(65);
      ByteBuffer plain_text_view;
      ByteBuffer cipher_text_view;
      long text_size;
      long ctr = 0;

      {
        plain_text_view = plain_text.duplicate();
        cipher_text_view = cipher_text.duplicate();
        plain_text_view.position(0).limit(64);
        plain_text_view = plain_text_view.slice();
        cipher_text_view.position(0).limit(64);
        cipher_text_view = cipher_text_view.slice();
        text_size = cipher_text_view.remaining();

        ctr = mc.crypto_chacha20_djb(cipher_text_view, plain_text_view, text_size, key, nonce, ctr);
      }

      {
        plain_text_view = plain_text.duplicate();
        cipher_text_view = cipher_text.duplicate();
        plain_text_view.position(64).limit(65);
        plain_text_view = plain_text_view.slice();
        cipher_text_view.position(64).limit(65);
        cipher_text_view = cipher_text_view.slice();
        text_size = cipher_text_view.remaining();

        ctr = mc.crypto_chacha20_djb(cipher_text_view, plain_text_view, text_size, key, nonce, ctr);
      }

      String expected =
          "f799a38af590e06e8a1955f06806b97a6f468fb00217ea84f418b64de447ddde"
              + "14857658571e6066186be36f2c64394635e28c6ade2965c6612f2f6717d51a25"
              + "78";

      String actual = toHex(cipher_text);

      assertEquals(expected, actual, "cipher_text mismatch");

      long expected_ctr = 2;

      assertEquals(expected_ctr, ctr, "ctr mismatch");
    }

    // crypto_chacha20_djb happy path with null plaintext
    {
      ByteBuffer plain_text = null;
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer nonce = fromHexToByteBuffer("0001020304050607");
      ByteBuffer cipher_text = ByteBuffer.allocateDirect(65);
      long text_size = cipher_text.remaining();

      long ctr = 0;

      ctr = mc.crypto_chacha20_djb(cipher_text, plain_text, text_size, key, nonce, ctr);

      String expected =
          "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c1"
              + "34a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a"
              + "38";

      String actual = toHex(cipher_text);

      assertEquals(expected, actual, "cipher_text mismatch");

      long expected_ctr = 2;

      assertEquals(expected_ctr, ctr, "ctr mismatch");
    }
  }

  @Test
  @Order(36)
  public void test_crypto_chacha20_ietf() {
    // crypto_chacha20_ietf happy path
    {
      ByteBuffer plain_text =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  + "40");
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer nonce = fromHexToByteBuffer("000102030405060708090a0b");
      ByteBuffer cipher_text = ByteBuffer.allocateDirect(65);
      long text_size = cipher_text.remaining();

      long ctr = 0;

      ctr = mc.crypto_chacha20_ietf(cipher_text, plain_text, text_size, key, nonce, ctr);

      String expected =
          "103bf312c58e529a312d85bb716dcc9585c0c99bcc87e1a3b7698044c8678054"
              + "f5deb846a9f00a57a3c635244e061968343e9166273587c5ab2c30b35e3061d2"
              + "c9";

      String actual = toHex(cipher_text);

      assertEquals(expected, actual, "cipher_text mismatch");

      long expected_ctr = 2;

      assertEquals(expected_ctr, ctr, "ctr mismatch");
    }

    // crypto_chacha20_ietf incremental happy path
    {
      ByteBuffer plain_text =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  + "40");
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer nonce = fromHexToByteBuffer("000102030405060708090a0b");
      ByteBuffer cipher_text = ByteBuffer.allocateDirect(65);
      ByteBuffer plain_text_view;
      ByteBuffer cipher_text_view;
      long text_size;
      long ctr = 0;

      {
        plain_text_view = plain_text.duplicate();
        cipher_text_view = cipher_text.duplicate();
        plain_text_view.position(0).limit(64);
        plain_text_view = plain_text_view.slice();
        cipher_text_view.position(0).limit(64);
        cipher_text_view = cipher_text_view.slice();
        text_size = cipher_text_view.remaining();

        ctr =
            mc.crypto_chacha20_ietf(cipher_text_view, plain_text_view, text_size, key, nonce, ctr);
      }

      {
        plain_text_view = plain_text.duplicate();
        cipher_text_view = cipher_text.duplicate();
        plain_text_view.position(64).limit(65);
        plain_text_view = plain_text_view.slice();
        cipher_text_view.position(64).limit(65);
        cipher_text_view = cipher_text_view.slice();
        text_size = cipher_text_view.remaining();

        ctr =
            mc.crypto_chacha20_ietf(cipher_text_view, plain_text_view, text_size, key, nonce, ctr);
      }

      String expected =
          "103bf312c58e529a312d85bb716dcc9585c0c99bcc87e1a3b7698044c8678054"
              + "f5deb846a9f00a57a3c635244e061968343e9166273587c5ab2c30b35e3061d2"
              + "c9";

      String actual = toHex(cipher_text);

      assertEquals(expected, actual, "cipher_text mismatch");

      long expected_ctr = 2;

      assertEquals(expected_ctr, ctr, "ctr mismatch");
    }

    // crypto_chacha20_ietf happy path with null plaintext
    {
      ByteBuffer plain_text = null;
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer nonce = fromHexToByteBuffer("000102030405060708090a0b");
      ByteBuffer cipher_text = ByteBuffer.allocateDirect(65);
      long text_size = cipher_text.remaining();

      long ctr = 0;

      ctr = mc.crypto_chacha20_ietf(cipher_text, plain_text, text_size, key, nonce, ctr);

      String expected =
          "103af111c18b549d39248fb07d60c29a95d1db88d892f7b4af709a5fd47a9e4b"
              + "d5ff9a658dd52c708bef1f0f622b3747040fa3551300b1f293150a88620d5fed"
              + "89";

      String actual = toHex(cipher_text);

      assertEquals(expected, actual, "cipher_text mismatch");

      long expected_ctr = 2;

      assertEquals(expected_ctr, ctr, "ctr mismatch");
    }
  }

  @Test
  @Order(37)
  public void test_crypto_chacha20_x() {
    // crypto_chacha20_x happy path
    {
      ByteBuffer plain_text =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  + "40");
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer nonce = fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f1011121314151617");
      ByteBuffer cipher_text = ByteBuffer.allocateDirect(65);
      long text_size = cipher_text.remaining();

      long ctr = 0;

      ctr = mc.crypto_chacha20_x(cipher_text, plain_text, text_size, key, nonce, ctr);

      String expected =
          "e53b63cdf554ee13090f77e836d2ce2180ba324075a18d4487c365157faca262"
              + "48dacc75ede72a1ebe277374128a42b8a835e2bfce47b851f3664c50b833f820"
              + "de";

      String actual = toHex(cipher_text);

      assertEquals(expected, actual, "cipher_text mismatch");

      long expected_ctr = 2;

      assertEquals(expected_ctr, ctr, "ctr mismatch");
    }

    // crypto_chacha20_x incremental happy path
    {
      ByteBuffer plain_text =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  + "40");
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer nonce = fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f1011121314151617");
      ByteBuffer cipher_text = ByteBuffer.allocateDirect(65);
      ByteBuffer plain_text_view;
      ByteBuffer cipher_text_view;
      long text_size;
      long ctr = 0;

      {
        plain_text_view = plain_text.duplicate();
        cipher_text_view = cipher_text.duplicate();
        plain_text_view.position(0).limit(64);
        plain_text_view = plain_text_view.slice();
        cipher_text_view.position(0).limit(64);
        cipher_text_view = cipher_text_view.slice();
        text_size = cipher_text_view.remaining();

        ctr = mc.crypto_chacha20_x(cipher_text_view, plain_text_view, text_size, key, nonce, ctr);
      }

      {
        plain_text_view = plain_text.duplicate();
        cipher_text_view = cipher_text.duplicate();
        plain_text_view.position(64).limit(65);
        plain_text_view = plain_text_view.slice();
        cipher_text_view.position(64).limit(65);
        cipher_text_view = cipher_text_view.slice();
        text_size = cipher_text_view.remaining();

        ctr = mc.crypto_chacha20_x(cipher_text_view, plain_text_view, text_size, key, nonce, ctr);
      }

      String expected =
          "e53b63cdf554ee13090f77e836d2ce2180ba324075a18d4487c365157faca262"
              + "48dacc75ede72a1ebe277374128a42b8a835e2bfce47b851f3664c50b833f820"
              + "de";

      String actual = toHex(cipher_text);

      assertEquals(expected, actual, "cipher_text mismatch");

      long expected_ctr = 2;

      assertEquals(expected_ctr, ctr, "ctr mismatch");
    }

    // crypto_chacha20_x happy path with null plaintext
    {
      ByteBuffer plain_text = null;
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer nonce = fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f1011121314151617");
      ByteBuffer cipher_text = ByteBuffer.allocateDirect(65);
      long text_size = cipher_text.remaining();

      long ctr = 0;

      ctr = mc.crypto_chacha20_x(cipher_text, plain_text, text_size, key, nonce, ctr);

      String expected =
          "e53a61cef151e81401067de33adfc02e90ab205361b49b539fda7f0e63b1bc7d"
              + "68fbee56c9c20c39960e595f3ea76c979804d08cfa728e66cb5f766b840ec61f"
              + "9e";

      String actual = toHex(cipher_text);

      assertEquals(expected, actual, "cipher_text mismatch");

      long expected_ctr = 2;

      assertEquals(expected_ctr, ctr, "ctr mismatch");
    }
  }
}
