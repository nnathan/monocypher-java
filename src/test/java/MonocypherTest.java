import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import net.lastninja.monocypher.Monocypher;
import org.junit.Test;

public class MonocypherTest {

  private final Monocypher mc = new Monocypher();

  @Test
  public void test_crypto_verify16_Pass() {
    byte[] a = new byte[16];
    byte[] b = new byte[16];
    for (int i = 0; i < 16; i++) a[i] = b[i] = (byte) i;

    int result = mc.crypto_verify16(a, b);
    assertEquals("Equal arrays should return 0", 0, result);
  }

  @Test
  public void test_crypto_verify16_Fail() {
    byte[] a = new byte[16];
    byte[] b = new byte[16];
    for (int i = 0; i < 16; i++) {
      a[i] = (byte) i;
      b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
    }

    int result = mc.crypto_verify16(a, b);
    assertEquals("Different arrays should return -1", -1, result);
  }

  @Test
  public void test_crypto_verify16_LengthMismatch() {
    byte[] a = new byte[15];
    byte[] b = new byte[16];
    try {
      mc.crypto_verify16(a, b);
      fail("Expected IllegalArgumentException was not thrown");
    } catch (IllegalArgumentException e) {
      assertEquals("Both arrays must be 16 bytes long", e.getMessage());
    }
  }

  @Test
  public void test_crypto_verify32_Pass() {
    byte[] a = new byte[32];
    byte[] b = new byte[32];
    for (int i = 0; i < 32; i++) a[i] = b[i] = (byte) i;

    int result = mc.crypto_verify32(a, b);
    assertEquals("Equal arrays should return 0", 0, result);
  }

  @Test
  public void test_crypto_verify32_Fail() {
    byte[] a = new byte[32];
    byte[] b = new byte[32];
    for (int i = 0; i < 32; i++) {
      a[i] = (byte) i;
      b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
    }

    int result = mc.crypto_verify32(a, b);
    assertEquals("Different arrays should return -1", -1, result);
  }

  @Test
  public void test_crypto_verify32_LengthMismatch() {
    byte[] a = new byte[15];
    byte[] b = new byte[32];
    try {
      mc.crypto_verify32(a, b);
      fail("Expected IllegalArgumentException was not thrown");
    } catch (IllegalArgumentException e) {
      assertEquals("Both arrays must be 32 bytes long", e.getMessage());
    }
  }

  @Test
  public void test_crypto_verify64_Pass() {
    byte[] a = new byte[64];
    byte[] b = new byte[64];
    for (int i = 0; i < 64; i++) a[i] = b[i] = (byte) i;

    int result = mc.crypto_verify64(a, b);
    assertEquals("Equal arrays should return 0", 0, result);
  }

  @Test
  public void test_crypto_verify64_Fail() {
    byte[] a = new byte[64];
    byte[] b = new byte[64];
    for (int i = 0; i < 64; i++) {
      a[i] = (byte) i;
      b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
    }

    int result = mc.crypto_verify64(a, b);
    assertEquals("Different arrays should return -1", -1, result);
  }

  @Test
  public void test_crypto_verify64_LengthMismatch() {
    byte[] a = new byte[15];
    byte[] b = new byte[64];
    try {
      mc.crypto_verify64(a, b);
      fail("Expected IllegalArgumentException was not thrown");
    } catch (IllegalArgumentException e) {
      assertEquals("Both arrays must be 64 bytes long", e.getMessage());
    }
  }

  @Test
  public void test_crypto_wipe_Pass() {
    byte[] actual = new byte[] {(byte) 0xaa, (byte) 0xbb};
    byte[] expected = new byte[] {(byte) 0x00, (byte) 0x00};

    mc.crypto_wipe(actual);
    assertArrayEquals(expected, actual);
  }

  @Test
  public void test_crypto_wipe_nullptr_Pass() {
    byte[] actual = null;

    mc.crypto_wipe(actual);
  }

  private static String toHex(ByteBuffer buffer) {
    StringBuilder sb = new StringBuilder();
    int pos = buffer.position();
    int lim = buffer.limit();
    for (int i = pos; i < lim; i++) {
      sb.append(String.format("%02x", buffer.get(i)));
    }
    return sb.toString();
  }

  @Test
  public void test_crypto_aead_lock_with_ad_Pass() {
    byte[] key = new byte[32];
    ByteBuffer cipher_text = ByteBuffer.allocateDirect(64);
    ByteBuffer nonce = ByteBuffer.allocateDirect(24);
    ByteBuffer mac = ByteBuffer.allocateDirect(16);
    ByteBuffer ad = ByteBuffer.allocateDirect(24);
    ByteBuffer plain_text = ByteBuffer.allocateDirect(64);

    {
      ByteBuffer tmp = nonce.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x41);
    }

    {
      ByteBuffer tmp = ad.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x42);
    }

    {
      ByteBuffer tmp = plain_text.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x43);
    }

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    mc.crypto_aead_lock(cipher_text, mac, key, nonce, ad, plain_text);

    String cipher_text_expected =
        "a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3";
    String mac_expected = "6a17088c55c90308e787ed60f8e7fdd7";

    String cipher_text_actual = toHex(cipher_text);
    String mac_actual = toHex(mac);

    assertEquals(cipher_text_expected, cipher_text_actual);
    assertEquals(mac_expected, mac_actual);
  }

  @Test
  public void test_crypto_aead_lock_without_ad_Pass() {
    byte[] key = new byte[32];
    ByteBuffer cipher_text = ByteBuffer.allocateDirect(64);
    ByteBuffer nonce = ByteBuffer.allocateDirect(24);
    ByteBuffer mac = ByteBuffer.allocateDirect(16);
    ByteBuffer plain_text = ByteBuffer.allocateDirect(64);

    {
      ByteBuffer tmp = nonce.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x41);
    }

    {
      ByteBuffer tmp = plain_text.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x43);
    }

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    mc.crypto_aead_lock(cipher_text, mac, key, nonce, null, plain_text);

    String cipher_text_expected =
        "a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3";
    String mac_expected = "3c5d023efcae618eaee3bfcd2503ede5";

    String cipher_text_actual = toHex(cipher_text);
    String mac_actual = toHex(mac);

    assertEquals(cipher_text_expected, cipher_text_actual);
    assertEquals(mac_expected, mac_actual);
  }

  @Test
  public void test_crypto_aead_lock_inplace_with_ad_Pass() {
    byte[] key = new byte[32];
    ByteBuffer encrypted_message = ByteBuffer.allocateDirect(128);

    ByteBuffer nonce = encrypted_message.duplicate();
    nonce.position(0).limit(24);
    nonce = nonce.slice();

    ByteBuffer mac = encrypted_message.duplicate();
    mac.position(24).limit(40);
    mac = mac.slice();

    ByteBuffer ad = encrypted_message.duplicate();
    ad.position(40).limit(64);
    ad = ad.slice();

    ByteBuffer plain_text = encrypted_message.duplicate();
    plain_text.position(64).limit(128);
    plain_text = plain_text.slice();

    {
      ByteBuffer tmp = nonce.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x41);
    }

    {
      ByteBuffer tmp = ad.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x42);
    }

    {
      ByteBuffer tmp = plain_text.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x43);
    }

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    mc.crypto_aead_lock(plain_text, mac, key, nonce, ad, plain_text);

    String expected =
        "4141414141414141414141414141414141414141414141416a17088c55c90308e787ed60f8e7fdd7424242424242424242424242424242424242424242424242a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3";

    String actual = toHex(encrypted_message);

    assertEquals(expected, actual);
  }

  @Test
  public void test_crypto_aead_lock_inplace_without_ad_Pass() {
    byte[] key = new byte[32];
    ByteBuffer encrypted_message = ByteBuffer.allocateDirect(128);

    ByteBuffer nonce = encrypted_message.duplicate();
    nonce.position(0).limit(24);
    nonce = nonce.slice();

    ByteBuffer mac = encrypted_message.duplicate();
    mac.position(24).limit(40);
    mac = mac.slice();

    ByteBuffer ad = null;

    ByteBuffer plain_text = encrypted_message.duplicate();
    plain_text.position(64).limit(128);
    plain_text = plain_text.slice();

    {
      ByteBuffer tmp = nonce.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x41);
    }

    {
      ByteBuffer tmp = plain_text.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x43);
    }

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    mc.crypto_aead_lock(plain_text, mac, key, nonce, ad, plain_text);

    String expected =
        "4141414141414141414141414141414141414141414141413c5d023efcae618eaee3bfcd2503ede5000000000000000000000000000000000000000000000000a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3";

    String actual = toHex(encrypted_message);

    assertEquals(expected, actual);
  }

  @Test
  public void test_crypto_aead_lock_Pass() {}
}
