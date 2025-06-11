import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import net.lastninja.monocypher.Monocypher;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class MonocypherTest {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(1)
  public void test_crypto_verify16_Pass() {
    byte[] a = new byte[16];
    byte[] b = new byte[16];
    for (int i = 0; i < 16; i++) a[i] = b[i] = (byte) i;

    int result = mc.crypto_verify16(a, b);
    assertEquals(0, result, "Equal arrays should return 0");
  }

  @Test
  @Order(2)
  public void test_crypto_verify16_Fail() {
    byte[] a = new byte[16];
    byte[] b = new byte[16];
    for (int i = 0; i < 16; i++) {
      a[i] = (byte) i;
      b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
    }

    int result = mc.crypto_verify16(a, b);
    assertEquals(-1, result, "Different arrays should return -1");
  }

  @Test
  @Order(3)
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
  @Order(4)
  public void test_crypto_verify32_Pass() {
    byte[] a = new byte[32];
    byte[] b = new byte[32];
    for (int i = 0; i < 32; i++) a[i] = b[i] = (byte) i;

    int result = mc.crypto_verify32(a, b);
    assertEquals(0, result, "Equal arrays should return 0");
  }

  @Test
  @Order(5)
  public void test_crypto_verify32_Fail() {
    byte[] a = new byte[32];
    byte[] b = new byte[32];
    for (int i = 0; i < 32; i++) {
      a[i] = (byte) i;
      b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
    }

    int result = mc.crypto_verify32(a, b);
    assertEquals(-1, result, "Different arrays should return -1");
  }

  @Test
  @Order(6)
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
  @Order(7)
  public void test_crypto_verify64_Pass() {
    byte[] a = new byte[64];
    byte[] b = new byte[64];
    for (int i = 0; i < 64; i++) a[i] = b[i] = (byte) i;

    int result = mc.crypto_verify64(a, b);
    assertEquals(0, result, "Equal arrays should return 0");
  }

  @Test
  @Order(8)
  public void test_crypto_verify64_Fail() {
    byte[] a = new byte[64];
    byte[] b = new byte[64];
    for (int i = 0; i < 64; i++) {
      a[i] = (byte) i;
      b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
    }

    int result = mc.crypto_verify64(a, b);
    assertEquals(-1, result, "Different arrays should return -1");
  }

  @Test
  @Order(9)
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
  @Order(10)
  public void test_crypto_wipe_Pass() {
    byte[] actual = new byte[] {(byte) 0xaa, (byte) 0xbb};
    byte[] expected = new byte[] {(byte) 0x00, (byte) 0x00};

    mc.crypto_wipe(actual);
    assertArrayEquals(expected, actual);
  }

  @Test
  @Order(11)
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
  @Order(12)
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
  @Order(13)
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
  @Order(14)
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
  @Order(15)
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

  private static ByteBuffer fromHex(String hex) {
    int len = hex.length();
    if (len % 2 != 0) {
      throw new IllegalArgumentException("Hex string must have even length");
    }

    ByteBuffer buffer = ByteBuffer.allocateDirect(len / 2);
    for (int i = 0; i < len; i += 2) {
      byte b = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
      buffer.put(b);
    }

    buffer.flip(); // Reset position to 0 for reading
    return buffer;
  }

  @Test
  @Order(16)
  public void test_crypto_aead_unlock_with_ad_Pass() {
    byte[] key = new byte[32];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    ByteBuffer ad = ByteBuffer.allocateDirect(24);
    ByteBuffer nonce = ByteBuffer.allocateDirect(24);

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

    ByteBuffer cipher_text =
        fromHex(
            "a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3");
    ByteBuffer mac = fromHex("6a17088c55c90308e787ed60f8e7fdd7");
    ByteBuffer plain_text = ByteBuffer.allocateDirect(cipher_text.limit());

    int result = mc.crypto_aead_unlock(plain_text, mac, key, nonce, ad, cipher_text);

    assertEquals(result, 0);

    String plain_text_expected =
        "43434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";
    String plain_text_actual = toHex(plain_text);

    assertEquals(plain_text_expected, plain_text_actual);
  }

  @Test
  @Order(17)
  public void test_crypto_aead_unlock_without_ad_Pass() {
    byte[] key = new byte[32];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    ByteBuffer nonce = ByteBuffer.allocateDirect(24);

    {
      ByteBuffer tmp = nonce.duplicate();
      tmp.position(0);
      while (tmp.hasRemaining()) tmp.put((byte) 0x41);
    }

    ByteBuffer cipher_text =
        fromHex(
            "a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3");
    ByteBuffer mac = fromHex("3c5d023efcae618eaee3bfcd2503ede5");
    ByteBuffer plain_text = ByteBuffer.allocateDirect(cipher_text.limit());

    int result = mc.crypto_aead_unlock(plain_text, mac, key, nonce, null, cipher_text);

    assertEquals(result, 0);

    String plain_text_expected =
        "43434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";
    String plain_text_actual = toHex(plain_text);

    assertEquals(plain_text_expected, plain_text_actual);
  }

  @Test
  @Order(18)
  public void test_crypto_aead_unlock_inplace_with_ad_Pass() {
    byte[] key = new byte[32];
    ByteBuffer encrypted_message =
        fromHex(
            "4141414141414141414141414141414141414141414141416a17088c55c90308e787ed60f8e7fdd7424242424242424242424242424242424242424242424242a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3");

    ByteBuffer nonce = encrypted_message.duplicate();
    nonce.position(0).limit(24);
    nonce = nonce.slice();

    ByteBuffer mac = encrypted_message.duplicate();
    mac.position(24).limit(40);
    mac = mac.slice();

    ByteBuffer ad = encrypted_message.duplicate();
    ad.position(40).limit(64);
    ad = ad.slice();

    ByteBuffer cipher_text = encrypted_message.duplicate();
    cipher_text.position(64).limit(128);
    cipher_text = cipher_text.slice();

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    mc.crypto_aead_unlock(cipher_text, mac, key, nonce, ad, cipher_text);

    String expected =
        "4141414141414141414141414141414141414141414141416a17088c55c90308e787ed60f8e7fdd742424242424242424242424242424242424242424242424243434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";

    String actual = toHex(encrypted_message);

    assertEquals(expected, actual);
  }

  @Test
  @Order(19)
  public void test_crypto_aead_unlock_inplace_without_ad_Pass() {
    byte[] key = new byte[32];
    ByteBuffer encrypted_message =
        fromHex(
            "4141414141414141414141414141414141414141414141413c5d023efcae618eaee3bfcd2503ede5000000000000000000000000000000000000000000000000a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3");

    ByteBuffer nonce = encrypted_message.duplicate();
    nonce.position(0).limit(24);
    nonce = nonce.slice();

    ByteBuffer mac = encrypted_message.duplicate();
    mac.position(24).limit(40);
    mac = mac.slice();

    ByteBuffer cipher_text = encrypted_message.duplicate();
    cipher_text.position(64).limit(128);
    cipher_text = cipher_text.slice();

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    mc.crypto_aead_unlock(cipher_text, mac, key, nonce, null, cipher_text);

    String expected =
        "4141414141414141414141414141414141414141414141413c5d023efcae618eaee3bfcd2503ede500000000000000000000000000000000000000000000000043434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";
    String actual = toHex(encrypted_message);

    assertEquals(expected, actual);
  }
}
