import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import net.lastninja.monocypher.Monocypher;
import net.lastninja.monocypher.Monocypher.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class MonocypherTest {

  private final Monocypher mc = new Monocypher();

  @Test
  @Order(1)
  public void test_crypto_verify16() {
    {
      byte[] a = new byte[16];
      byte[] b = new byte[16];
      for (int i = 0; i < 16; i++) a[i] = b[i] = (byte) i;

      int result = mc.crypto_verify16(a, b);
      assertEquals(0, result, "Equal arrays should return 0");
    }

    {
      byte[] a = new byte[16];
      byte[] b = new byte[16];
      for (int i = 0; i < 16; i++) {
        a[i] = (byte) i;
        b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
      }

      int result = mc.crypto_verify16(a, b);
      assertEquals(-1, result, "Different arrays should return -1");
    }

    {
      byte[] a = new byte[15];
      byte[] b = new byte[16];
      try {
        mc.crypto_verify16(a, b);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("Both arrays must be 16 bytes long", e.getMessage());
      }
    }
  }

  @Test
  @Order(2)
  public void test_crypto_verify32() {
    {
      byte[] a = new byte[32];
      byte[] b = new byte[32];
      for (int i = 0; i < 32; i++) a[i] = b[i] = (byte) i;

      int result = mc.crypto_verify32(a, b);
      assertEquals(0, result, "Equal arrays should return 0");
    }

    {
      byte[] a = new byte[32];
      byte[] b = new byte[32];
      for (int i = 0; i < 32; i++) {
        a[i] = (byte) i;
        b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
      }

      int result = mc.crypto_verify32(a, b);
      assertEquals(-1, result, "Different arrays should return -1");
    }

    {
      byte[] a = new byte[15];
      byte[] b = new byte[32];
      try {
        mc.crypto_verify32(a, b);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("Both arrays must be 32 bytes long", e.getMessage());
      }
    }
  }

  @Test
  @Order(3)
  public void test_crypto_verify64() {
    {
      byte[] a = new byte[64];
      byte[] b = new byte[64];
      for (int i = 0; i < 64; i++) a[i] = b[i] = (byte) i;

      int result = mc.crypto_verify64(a, b);
      assertEquals(0, result, "Equal arrays should return 0");
    }

    {
      byte[] a = new byte[64];
      byte[] b = new byte[64];
      for (int i = 0; i < 64; i++) {
        a[i] = (byte) i;
        b[i] = (byte) (i == 8 ? 0xFF : i); // change one byte
      }

      int result = mc.crypto_verify64(a, b);
      assertEquals(-1, result, "Different arrays should return -1");
    }

    {
      byte[] a = new byte[15];
      byte[] b = new byte[64];
      try {
        mc.crypto_verify64(a, b);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("Both arrays must be 64 bytes long", e.getMessage());
      }
    }
  }

  @Test
  @Order(4)
  public void test_crypto_wipe() {
    {
      byte[] actual = new byte[] {(byte) 0xaa, (byte) 0xbb};
      byte[] expected = new byte[] {(byte) 0x00, (byte) 0x00};

      mc.crypto_wipe(actual);
      assertArrayEquals(expected, actual);
    }

    {
      byte[] actual = null;

      mc.crypto_wipe(actual);
    }
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
  @Order(5)
  public void test_crypto_aead_lock() {
    // with ad (detached)
    {
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

    // without ad (detached)
    {
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

    // with ad (inplace)
    {
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

    // without ad (inplace)
    {
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
  }

  private static ByteBuffer fromHexToByteBuffer(String hex) {
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
  @Order(6)
  public void test_crypto_aead_unlock() {

    // with ad (detached)
    {
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
          fromHexToByteBuffer(
              "a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3");
      ByteBuffer mac = fromHexToByteBuffer("6a17088c55c90308e787ed60f8e7fdd7");
      ByteBuffer plain_text = ByteBuffer.allocateDirect(cipher_text.limit());

      int result = mc.crypto_aead_unlock(plain_text, mac, key, nonce, ad, cipher_text);

      assertEquals(result, 0);

      String plain_text_expected =
          "43434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";
      String plain_text_actual = toHex(plain_text);

      assertEquals(plain_text_expected, plain_text_actual);
    }

    // without ad (detached)
    {
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
          fromHexToByteBuffer(
              "a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3");
      ByteBuffer mac = fromHexToByteBuffer("3c5d023efcae618eaee3bfcd2503ede5");
      ByteBuffer plain_text = ByteBuffer.allocateDirect(cipher_text.limit());

      int result = mc.crypto_aead_unlock(plain_text, mac, key, nonce, null, cipher_text);

      assertEquals(result, 0);

      String plain_text_expected =
          "43434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";
      String plain_text_actual = toHex(plain_text);

      assertEquals(plain_text_expected, plain_text_actual);
    }

    // with ad (inplace)
    {
      byte[] key = new byte[32];
      ByteBuffer encrypted_message =
          fromHexToByteBuffer(
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

    // without ad (inplace)
    {
      byte[] key = new byte[32];
      ByteBuffer encrypted_message =
          fromHexToByteBuffer(
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

    // sad path: with ad (detached)
    {
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
          fromHexToByteBuffer(
              "a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3");
      ByteBuffer mac = fromHexToByteBuffer("00000000000000000000000000000000"); // perturbed
      ByteBuffer plain_text = ByteBuffer.allocateDirect(cipher_text.limit());

      int result = mc.crypto_aead_unlock(plain_text, mac, key, nonce, ad, cipher_text);

      assertEquals(result, -1);
    }
  }

  private static byte[] fromHexToByteArray(String hex) {
    int len = hex.length();
    if (len % 2 != 0) {
      throw new IllegalArgumentException("Hex string must have even length");
    }

    byte[] result = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
    }

    return result;
  }

  private static long fromHexLEToLong(String hex) {
    if (hex.length() != 16) {
      throw new IllegalArgumentException("Hex string must be exactly 16 characters for 8 bytes");
    }

    long result = 0;
    for (int i = 0; i < 8; i++) {
      int byteIndex = i * 2;
      int value = Integer.parseInt(hex.substring(byteIndex, byteIndex + 2), 16);
      result |= ((long) value & 0xFF) << (8 * i); // little-endian shift
    }

    return result;
  }

  private static String toHex(byte[] buffer) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < buffer.length; i++) {
      sb.append(String.format("%02x", buffer[i]));
    }
    return sb.toString();
  }

  @Test
  @Order(7)
  public void test_crypto_aead_init_x() throws NoSuchFieldException, IllegalAccessException {
    AEAD_ctx ctx = mc.new AEAD_ctx();
    byte[] key = new byte[32];
    byte[] nonce = new byte[24];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (byte) i;
    }

    mc.crypto_aead_init_x(ctx, key, nonce);

    Field counterField = AEAD_ctx.class.getDeclaredField("counter");
    Field keyField = AEAD_ctx.class.getDeclaredField("key");
    Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

    counterField.setAccessible(true);
    keyField.setAccessible(true);
    nonceField.setAccessible(true);

    long counter_actual = counterField.getLong(ctx);
    byte[] key_actual = (byte[]) keyField.get(ctx);
    byte[] nonce_actual = (byte[]) nonceField.get(ctx);

    long counter_expected = fromHexLEToLong("0000000000000000");
    byte[] key_expected =
        fromHexToByteArray("51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6");
    byte[] nonce_expected = fromHexToByteArray("1011121314151617");

    assertEquals(counter_expected, counter_actual, "Counter mismatch");
    assertArrayEquals(key_expected, key_actual, "Key mismatch");
    assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch");
  }

  @Test
  @Order(8)
  public void test_crypto_aead_init_djb() throws NoSuchFieldException, IllegalAccessException {
    AEAD_ctx ctx = mc.new AEAD_ctx();
    byte[] key = new byte[32];
    byte[] nonce = new byte[8];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (byte) i;
    }

    mc.crypto_aead_init_djb(ctx, key, nonce);

    Field counterField = AEAD_ctx.class.getDeclaredField("counter");
    Field keyField = AEAD_ctx.class.getDeclaredField("key");
    Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

    counterField.setAccessible(true);
    keyField.setAccessible(true);
    nonceField.setAccessible(true);

    long counter_actual = counterField.getLong(ctx);
    byte[] key_actual = (byte[]) keyField.get(ctx);
    byte[] nonce_actual = (byte[]) nonceField.get(ctx);

    long counter_expected = fromHexLEToLong("0000000000000000");
    byte[] key_expected =
        fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    byte[] nonce_expected = fromHexToByteArray("0001020304050607");

    assertEquals(counter_expected, counter_actual, "Counter mismatch");
    assertArrayEquals(key_expected, key_actual, "Key mismatch");
    assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch");
  }

  @Test
  @Order(9)
  public void test_crypto_aead_init_ietf() throws NoSuchFieldException, IllegalAccessException {
    AEAD_ctx ctx = mc.new AEAD_ctx();
    byte[] key = new byte[32];
    byte[] nonce = new byte[12];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (byte) i;
    }

    mc.crypto_aead_init_ietf(ctx, key, nonce);

    Field counterField = AEAD_ctx.class.getDeclaredField("counter");
    Field keyField = AEAD_ctx.class.getDeclaredField("key");
    Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

    counterField.setAccessible(true);
    keyField.setAccessible(true);
    nonceField.setAccessible(true);

    long counter_actual = counterField.getLong(ctx);
    byte[] key_actual = (byte[]) keyField.get(ctx);
    byte[] nonce_actual = (byte[]) nonceField.get(ctx);

    long counter_expected = fromHexLEToLong("0000000000010203");
    byte[] key_expected =
        fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    byte[] nonce_expected = fromHexToByteArray("0405060708090a0b");

    assertEquals(counter_expected, counter_actual, "Counter mismatch");
    assertArrayEquals(key_expected, key_actual, "Key mismatch");
    assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch");
  }

  @Test
  @Order(10)
  public void test_crypto_wipe_aead_ctx() throws NoSuchFieldException, IllegalAccessException {
    AEAD_ctx ctx = mc.new AEAD_ctx();
    byte[] key = new byte[32];
    byte[] nonce = new byte[12];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (byte) i;
    }

    mc.crypto_aead_init_ietf(ctx, key, nonce);

    Field counterField = AEAD_ctx.class.getDeclaredField("counter");
    Field keyField = AEAD_ctx.class.getDeclaredField("key");
    Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

    counterField.setAccessible(true);
    keyField.setAccessible(true);
    nonceField.setAccessible(true);

    long counter_actual = counterField.getLong(ctx);
    byte[] key_actual = (byte[]) keyField.get(ctx);
    byte[] nonce_actual = (byte[]) nonceField.get(ctx);

    long counter_expected = fromHexLEToLong("0000000000010203");
    byte[] key_expected =
        fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    byte[] nonce_expected = fromHexToByteArray("0405060708090a0b");

    assertEquals(counter_expected, counter_actual, "Counter mismatch before wipe");
    assertArrayEquals(key_expected, key_actual, "Key mismatch before wipe");
    assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch before wipe");

    mc.crypto_wipe(ctx);

    counter_actual = counterField.getLong(ctx);
    key_actual = (byte[]) keyField.get(ctx);
    nonce_actual = (byte[]) nonceField.get(ctx);

    counter_expected = fromHexLEToLong("0000000000000000");
    key_expected =
        fromHexToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
    nonce_expected = fromHexToByteArray("0000000000000000");

    assertEquals(counter_expected, counter_actual, "Counter mismatch after wipe");
    assertArrayEquals(key_expected, key_actual, "Key mismatch after wipe");
    assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch after wipe");
  }

  @Test
  @Order(11)
  public void test_crypto_aead_write() throws NoSuchFieldException, IllegalAccessException {
    // xchacha20 with ad (inplace)
    {
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
        int i = 0;
        tmp.position(0);
        while (tmp.hasRemaining()) tmp.put((byte) i++);
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

      AEAD_ctx ctx = mc.new AEAD_ctx();

      byte[] nonceArray = new byte[24];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      mc.crypto_aead_init_x(ctx, key, nonceArray);
      mc.crypto_aead_write(ctx, plain_text, mac, ad, plain_text);

      String expected =
          "000102030405060708090a0b0c0d0e0f10111213141516175318bc062203b6c214b24c1f98b84dfa424242424242424242424242424242424242424242424242dd814c3cd391ceed7007658d8811ebab08046be6be955ea83c597cf57eeeb61a1d45f5a702244a2796d6ed1a8c62102132f9a11a0437b85a44d8d07ecca407b7";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      Field counterField = AEAD_ctx.class.getDeclaredField("counter");
      Field keyField = AEAD_ctx.class.getDeclaredField("key");
      Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

      counterField.setAccessible(true);
      keyField.setAccessible(true);
      nonceField.setAccessible(true);

      long counter_actual = counterField.getLong(ctx);
      byte[] key_actual = (byte[]) keyField.get(ctx);
      byte[] nonce_actual = (byte[]) nonceField.get(ctx);

      long counter_expected = fromHexLEToLong("0000000000000000");
      byte[] key_expected =
          fromHexToByteArray("68fbee56c9c20c39960e595f3ea76c979804d08cfa728e66cb5f766b840ec61f");
      byte[] nonce_expected = fromHexToByteArray("1011121314151617");

      assertEquals(counter_expected, counter_actual, "Counter mismatch before wipe");
      assertArrayEquals(key_expected, key_actual, "Key mismatch before wipe");
      assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch before wipe");
    }

    // djb chacha20 (inplace)
    {
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
        int i = 0;
        tmp.position(0);
        while (tmp.hasRemaining()) tmp.put((byte) i++);
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

      AEAD_ctx ctx = mc.new AEAD_ctx();

      byte[] nonceArray = new byte[8];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      mc.crypto_aead_init_djb(ctx, key, nonceArray);
      mc.crypto_aead_write(ctx, plain_text, mac, ad, plain_text);

      String expected =
          "000102030405060708090a0b0c0d0e0f10111213141516175fa63e1182edfc77a9ea50eb8661f91a4242424242424242424242424242424242424242424242427b43c8d965ff76d75d6707543fc99d25ca9dd6650ac59a1bcab823ab056a8afed919885f825bfd157dfaf0e7e731bb6d4ae4a43b0a68156db4504dcb9ca37284";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      Field counterField = AEAD_ctx.class.getDeclaredField("counter");
      Field keyField = AEAD_ctx.class.getDeclaredField("key");
      Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

      counterField.setAccessible(true);
      keyField.setAccessible(true);
      nonceField.setAccessible(true);

      long counter_actual = counterField.getLong(ctx);
      byte[] key_actual = (byte[]) keyField.get(ctx);
      byte[] nonce_actual = (byte[]) nonceField.get(ctx);

      long counter_expected = fromHexLEToLong("0000000000000000");
      byte[] key_expected =
          fromHexToByteArray("34a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a");
      byte[] nonce_expected = fromHexToByteArray("0001020304050607");

      assertEquals(counter_expected, counter_actual, "Counter mismatch before wipe");
      assertArrayEquals(key_expected, key_actual, "Key mismatch before wipe");
      assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch before wipe");
    }

    // ietf chacha20 (inplace)
    {
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
        int i = 0;
        tmp.position(0);
        while (tmp.hasRemaining()) tmp.put((byte) i++);
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

      AEAD_ctx ctx = mc.new AEAD_ctx();

      byte[] nonceArray = new byte[12];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      mc.crypto_aead_init_ietf(ctx, key, nonceArray);
      mc.crypto_aead_write(ctx, plain_text, mac, ad, plain_text);

      String expected =
          "000102030405060708090a0b0c0d0e0f101112131415161779c5dd122dabf8d5e9d4a7f2110b3486424242424242424242424242424242424242424242424242cab84b436a54e603f4c07cb0db5e4d208a33f1a41237eefaa5d46c863683e57fafc36fb0a55df2db7471359b26d7cc603dc7ea37be6bfbd851fb9a44d30cdd95";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      Field counterField = AEAD_ctx.class.getDeclaredField("counter");
      Field keyField = AEAD_ctx.class.getDeclaredField("key");
      Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

      counterField.setAccessible(true);
      keyField.setAccessible(true);
      nonceField.setAccessible(true);

      long counter_actual = counterField.getLong(ctx);
      byte[] key_actual = (byte[]) keyField.get(ctx);
      byte[] nonce_actual = (byte[]) nonceField.get(ctx);

      long counter_expected = fromHexLEToLong("0000000000010203");
      byte[] key_expected =
          fromHexToByteArray("d5ff9a658dd52c708bef1f0f622b3747040fa3551300b1f293150a88620d5fed");
      byte[] nonce_expected = fromHexToByteArray("0405060708090a0b");

      assertEquals(counter_expected, counter_actual, "Counter mismatch before wipe");
      assertArrayEquals(key_expected, key_actual, "Key mismatch before wipe");
      assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch before wipe");
    }
  }

  @Test
  @Order(12)
  public void test_crypto_aead_read() throws NoSuchFieldException, IllegalAccessException {
    // xchacha20 with ad (inplace)
    {
      byte[] key = new byte[32];
      ByteBuffer encrypted_message =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f10111213141516175318bc062203b6c214b24c1f98b84dfa424242424242424242424242424242424242424242424242dd814c3cd391ceed7007658d8811ebab08046be6be955ea83c597cf57eeeb61a1d45f5a702244a2796d6ed1a8c62102132f9a11a0437b85a44d8d07ecca407b7");

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

      AEAD_ctx ctx = mc.new AEAD_ctx();

      byte[] nonceArray = new byte[24];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      mc.crypto_aead_init_x(ctx, key, nonceArray);
      int result = mc.crypto_aead_read(ctx, cipher_text, mac, ad, cipher_text);

      assertEquals(result, 0);

      String expected =
          "000102030405060708090a0b0c0d0e0f10111213141516175318bc062203b6c214b24c1f98b84dfa42424242424242424242424242424242424242424242424243434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      Field counterField = AEAD_ctx.class.getDeclaredField("counter");
      Field keyField = AEAD_ctx.class.getDeclaredField("key");
      Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

      counterField.setAccessible(true);
      keyField.setAccessible(true);
      nonceField.setAccessible(true);

      long counter_actual = counterField.getLong(ctx);
      byte[] key_actual = (byte[]) keyField.get(ctx);
      byte[] nonce_actual = (byte[]) nonceField.get(ctx);

      long counter_expected = fromHexLEToLong("0000000000000000");
      byte[] key_expected =
          fromHexToByteArray("68fbee56c9c20c39960e595f3ea76c979804d08cfa728e66cb5f766b840ec61f");
      byte[] nonce_expected = fromHexToByteArray("1011121314151617");

      assertEquals(counter_expected, counter_actual, "Counter mismatch before wipe");
      assertArrayEquals(key_expected, key_actual, "Key mismatch before wipe");
      assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch before wipe");
    }

    // djb with ad (inplace)
    {
      byte[] key = new byte[32];
      ByteBuffer encrypted_message =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f10111213141516175fa63e1182edfc77a9ea50eb8661f91a4242424242424242424242424242424242424242424242427b43c8d965ff76d75d6707543fc99d25ca9dd6650ac59a1bcab823ab056a8afed919885f825bfd157dfaf0e7e731bb6d4ae4a43b0a68156db4504dcb9ca37284");

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

      AEAD_ctx ctx = mc.new AEAD_ctx();

      byte[] nonceArray = new byte[8];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      mc.crypto_aead_init_djb(ctx, key, nonceArray);
      int result = mc.crypto_aead_read(ctx, cipher_text, mac, ad, cipher_text);

      assertEquals(result, 0);

      String expected =
          "000102030405060708090a0b0c0d0e0f10111213141516175fa63e1182edfc77a9ea50eb8661f91a42424242424242424242424242424242424242424242424243434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      Field counterField = AEAD_ctx.class.getDeclaredField("counter");
      Field keyField = AEAD_ctx.class.getDeclaredField("key");
      Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

      counterField.setAccessible(true);
      keyField.setAccessible(true);
      nonceField.setAccessible(true);

      long counter_actual = counterField.getLong(ctx);
      byte[] key_actual = (byte[]) keyField.get(ctx);
      byte[] nonce_actual = (byte[]) nonceField.get(ctx);

      long counter_expected = fromHexLEToLong("0000000000000000");
      byte[] key_expected =
          fromHexToByteArray("34a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a");
      byte[] nonce_expected = fromHexToByteArray("0001020304050607");

      assertEquals(counter_expected, counter_actual, "Counter mismatch before wipe");
      assertArrayEquals(key_expected, key_actual, "Key mismatch before wipe");
      assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch before wipe");
    }

    // ietf with ad (inplace)
    {
      byte[] key = new byte[32];
      ByteBuffer encrypted_message =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161779c5dd122dabf8d5e9d4a7f2110b3486424242424242424242424242424242424242424242424242cab84b436a54e603f4c07cb0db5e4d208a33f1a41237eefaa5d46c863683e57fafc36fb0a55df2db7471359b26d7cc603dc7ea37be6bfbd851fb9a44d30cdd95");

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

      AEAD_ctx ctx = mc.new AEAD_ctx();

      byte[] nonceArray = new byte[12];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      mc.crypto_aead_init_ietf(ctx, key, nonceArray);
      int result = mc.crypto_aead_read(ctx, cipher_text, mac, ad, cipher_text);

      assertEquals(result, 0);

      String expected =
          "000102030405060708090a0b0c0d0e0f101112131415161779c5dd122dabf8d5e9d4a7f2110b348642424242424242424242424242424242424242424242424243434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      Field counterField = AEAD_ctx.class.getDeclaredField("counter");
      Field keyField = AEAD_ctx.class.getDeclaredField("key");
      Field nonceField = AEAD_ctx.class.getDeclaredField("nonce");

      counterField.setAccessible(true);
      keyField.setAccessible(true);
      nonceField.setAccessible(true);

      long counter_actual = counterField.getLong(ctx);
      byte[] key_actual = (byte[]) keyField.get(ctx);
      byte[] nonce_actual = (byte[]) nonceField.get(ctx);

      long counter_expected = fromHexLEToLong("0000000000010203");
      byte[] key_expected =
          fromHexToByteArray("d5ff9a658dd52c708bef1f0f622b3747040fa3551300b1f293150a88620d5fed");
      byte[] nonce_expected = fromHexToByteArray("0405060708090a0b");

      assertEquals(counter_expected, counter_actual, "Counter mismatch before wipe");
      assertArrayEquals(key_expected, key_actual, "Key mismatch before wipe");
      assertArrayEquals(nonce_expected, nonce_actual, "Nonce mismatch before wipe");
    }

    // sad path: xchacha20 with ad (inplace)
    {
      byte[] key = new byte[32];
      ByteBuffer encrypted_message =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161700000000000000000000000000000000424242424242424242424242424242424242424242424242dd814c3cd391ceed7007658d8811ebab08046be6be955ea83c597cf57eeeb61a1d45f5a702244a2796d6ed1a8c62102132f9a11a0437b85a44d8d07ecca407b7"); // peturbed

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

      AEAD_ctx ctx = mc.new AEAD_ctx();

      byte[] nonceArray = new byte[24];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      mc.crypto_aead_init_x(ctx, key, nonceArray);
      int result = mc.crypto_aead_read(ctx, cipher_text, mac, ad, cipher_text);

      assertEquals(result, -1);
    }
  }

  @Test
  @Order(13)
  public void test_crypto_blake2b() {
    // blake2b with 1 byte hash
    {
      byte[] hash = new byte[1];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b(hash, message);

      String expected = "42";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with 32 byte hash
    {
      byte[] hash = new byte[32];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b(hash, message);

      String expected = "77065d25b622a8251094d869edf6b4e9ba0708a8db1f239cb68e4eeb45851621";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with 64 byte hash
    {
      byte[] hash = new byte[64];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b(hash, message);

      String expected =
          "e998e0dc03ec30eb99bb6bfaaf6618acc620320d7220b3af2b23d112d8e9cb1262f3c0d60d183b1ee7f096d12dae42c958418600214d04f5ed6f5e718be35566";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with 32 byte hash on empty message
    {
      byte[] hash = new byte[32];
      byte[] message = null;

      mc.crypto_blake2b(hash, message);

      String expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b with invalid hash size of 0
    {
      byte[] hash = new byte[0];
      byte[] message = null;

      try {
        mc.crypto_blake2b(hash, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must be an array of length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }

    // blake2b with invalid hash size of 65
    {
      byte[] hash = new byte[65];
      byte[] message = null;

      try {
        mc.crypto_blake2b(hash, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must be an array of length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }

    // blake2b with null hash object (exception thrown)
    {
      byte[] hash = null;
      byte[] message = null;

      try {
        mc.crypto_blake2b(hash, message);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }
  }

  @Test
  @Order(14)
  public void test_crypto_blake2b_keyed() {
    // blake2b keyed with 1 byte hash and 1 byte key
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(1);
      ByteBuffer key = fromHexToByteBuffer("00");
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      mc.crypto_blake2b_keyed(hash, key, message);

      String expected = "6a";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with 32 byte hash and 32 byte key
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(32);
      ByteBuffer key =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      mc.crypto_blake2b_keyed(hash, key, message);

      String expected = "04b80510e5e9ad383d1a354f2d7cfb7ada56caefa6de9e17989316701975b384";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with 64 byte hash and 64 byte key
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(64);
      ByteBuffer key =
          fromHexToByteBuffer(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      mc.crypto_blake2b_keyed(hash, key, message);

      String expected =
          "380beaf6ea7cc9365e270ef0e6f3a64fb902acae51dd5512f84259ad2c91f4bc4108db73192a5bbfb0cbcf71e46c3e21aee1c5e860dc96e8eb0b7b8426e6abe9";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with 32 byte hash and null key and message
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(32);
      ByteBuffer key = null;
      ByteBuffer message = null;

      mc.crypto_blake2b_keyed(hash, key, message);

      String expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with 32 byte hash and 32 byte key (inplace)
    {
      ByteBuffer hash =
          fromHexToByteBuffer("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      ByteBuffer message = fromHexToByteBuffer("0001020304050607");

      mc.crypto_blake2b_keyed(hash, hash, message);

      String expected = "04b80510e5e9ad383d1a354f2d7cfb7ada56caefa6de9e17989316701975b384";

      String actual = toHex(hash);

      assertEquals(expected, actual);
    }

    // blake2b keyed with invalid hash size of 0
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(0);
      ByteBuffer key = null;
      ByteBuffer message = null;

      try {
        mc.crypto_blake2b_keyed(hash, key, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must be a buffer of length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }

    // blake2b keyed with invalid hash size of 65
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(65);
      ByteBuffer key = null;
      ByteBuffer message = null;

      try {
        mc.crypto_blake2b_keyed(hash, key, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash must be a buffer of length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }

    // blake2b keyed with null hash object (exception thrown)
    {
      ByteBuffer hash = null;
      ByteBuffer key = null;
      ByteBuffer message = null;

      try {
        mc.crypto_blake2b_keyed(hash, key, message);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }

    // blake2b keyed with invalid key size object (exception thrown)
    {
      ByteBuffer hash = ByteBuffer.allocateDirect(64);
      ByteBuffer key = ByteBuffer.allocateDirect(65);
      ByteBuffer message = null;

      try {
        mc.crypto_blake2b_keyed(hash, key, message);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "key must be a buffer of length between (inclusive) 0 and 64 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(15)
  public void test_crypto_blake2b_init() throws NoSuchFieldException, IllegalAccessException {
    // blake2b init with 32 byte hash size
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();

      mc.crypto_blake2b_init(ctx, 32);

      Field hashField = Blake2b_ctx.class.getDeclaredField("hash");
      Field input_offsetField = Blake2b_ctx.class.getDeclaredField("input_offset");
      Field inputField = Blake2b_ctx.class.getDeclaredField("input");
      Field input_idxField = Blake2b_ctx.class.getDeclaredField("input_idx");
      Field hash_sizeField = Blake2b_ctx.class.getDeclaredField("hash_size");

      hashField.setAccessible(true);
      input_offsetField.setAccessible(true);
      inputField.setAccessible(true);
      input_idxField.setAccessible(true);
      hash_sizeField.setAccessible(true);

      long[] hash = (long[]) hashField.get(ctx);
      long[] input_offset = (long[]) input_offsetField.get(ctx);
      long[] input = (long[]) inputField.get(ctx);
      long input_idx = (long) input_idxField.get(ctx);
      long hash_size = (long) hash_sizeField.get(ctx);

      long[] hash_expected =
          new long[] {
            fromHexLEToLong("28c9bdf267e6096a"),
            fromHexLEToLong("3ba7ca8485ae67bb"),
            fromHexLEToLong("2bf894fe72f36e3c"),
            fromHexLEToLong("f1361d5f3af54fa5"),
            fromHexLEToLong("d182e6ad7f520e51"),
            fromHexLEToLong("1f6c3e2b8c68059b"),
            fromHexLEToLong("6bbd41fbabd9831f"),
            fromHexLEToLong("79217e1319cde05b"),
          };

      long[] input_offset_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"), fromHexLEToLong("0000000000000000"),
          };

      long[] input_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
          };

      long input_idx_expected = fromHexLEToLong("0000000000000000");
      long hash_size_expected = fromHexLEToLong("2000000000000000");

      assertArrayEquals(hash_expected, hash, "hash mismatch");
      assertArrayEquals(input_offset_expected, input_offset, "input_offset mismatch");
      assertArrayEquals(input_expected, input, "input mismatch");
      assertEquals(input_idx_expected, input_idx, "input_idx mismatch");
      assertEquals(hash_size_expected, hash_size, "hash_size mismatch");
    }

    // blake2b init with null ctx
    {
      Blake2b_ctx ctx = null;

      try {
        mc.crypto_blake2b_init(ctx, 32);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("ctx cannot be null", e.getMessage());
      }
    }

    // blake2b init with invalid hash size
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();

      try {
        mc.crypto_blake2b_init(ctx, 65);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals(
            "hash_size must be a length between (inclusive) 1 and 64 bytes", e.getMessage());
      }
    }
  }
}
