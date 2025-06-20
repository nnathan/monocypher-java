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

  @Test
  @Order(16)
  public void test_crypto_blake2b_update() throws NoSuchFieldException, IllegalAccessException {
    // blake2b update with 32 byte hash size and 256 byte message
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();
      byte[] message =
          fromHexToByteArray(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                  + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                  + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                  + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                  + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                  + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                  + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

      mc.crypto_blake2b_init(ctx, 32);
      mc.crypto_blake2b_update(ctx, message);

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
            fromHexLEToLong("21dccc8883c3da12"),
            fromHexLEToLong("d1e501e4b85be497"),
            fromHexLEToLong("eb58f03bd95088fa"),
            fromHexLEToLong("42d699ee4c933134"),
            fromHexLEToLong("92cbb67014beaa75"),
            fromHexLEToLong("368c5d990c25add4"),
            fromHexLEToLong("f775b1edbbb081a4"),
            fromHexLEToLong("97e2e005c5348f3d"),
          };

      long[] input_offset_expected =
          new long[] {
            fromHexLEToLong("8000000000000000"), fromHexLEToLong("0000000000000000"),
          };

      long[] input_expected =
          new long[] {
            fromHexLEToLong("8081828384858687"),
            fromHexLEToLong("88898a8b8c8d8e8f"),
            fromHexLEToLong("9091929394959697"),
            fromHexLEToLong("98999a9b9c9d9e9f"),
            fromHexLEToLong("a0a1a2a3a4a5a6a7"),
            fromHexLEToLong("a8a9aaabacadaeaf"),
            fromHexLEToLong("b0b1b2b3b4b5b6b7"),
            fromHexLEToLong("b8b9babbbcbdbebf"),
            fromHexLEToLong("c0c1c2c3c4c5c6c7"),
            fromHexLEToLong("c8c9cacbcccdcecf"),
            fromHexLEToLong("d0d1d2d3d4d5d6d7"),
            fromHexLEToLong("d8d9dadbdcdddedf"),
            fromHexLEToLong("e0e1e2e3e4e5e6e7"),
            fromHexLEToLong("e8e9eaebecedeeef"),
            fromHexLEToLong("f0f1f2f3f4f5f6f7"),
            fromHexLEToLong("f8f9fafbfcfdfeff"),
          };

      long input_idx_expected = fromHexLEToLong("8000000000000000");
      long hash_size_expected = fromHexLEToLong("2000000000000000");

      assertArrayEquals(hash_expected, hash, "hash mismatch");
      assertArrayEquals(input_offset_expected, input_offset, "input_offset mismatch");
      assertArrayEquals(input_expected, input, "input mismatch");
      assertEquals(input_idx_expected, input_idx, "input_idx mismatch");
      assertEquals(hash_size_expected, hash_size, "hash_size mismatch");
    }

    // blake2b update with null ctx
    {
      Blake2b_ctx ctx = null;

      try {
        mc.crypto_blake2b_update(ctx, null);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("ctx cannot be null", e.getMessage());
      }
    }
  }

  @Test
  @Order(17)
  public void test_crypto_blake2b_final() throws NoSuchFieldException, IllegalAccessException {
    // blake2b final with 32 byte hash size and 8 byte message
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();
      byte[] hash = new byte[32];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b_init(ctx, hash.length);
      mc.crypto_blake2b_update(ctx, message);
      mc.crypto_blake2b_final(ctx, hash);

      String expected = "77065d25b622a8251094d869edf6b4e9ba0708a8db1f239cb68e4eeb45851621";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");

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

      long[] hashArray = (long[]) hashField.get(ctx);
      long[] input_offset = (long[]) input_offsetField.get(ctx);
      long[] input = (long[]) inputField.get(ctx);
      long input_idx = (long) input_idxField.get(ctx);
      long hash_size = (long) hash_sizeField.get(ctx);

      long[] hash_expected =
          new long[] {
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
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
      long hash_size_expected = fromHexLEToLong("0000000000000000");

      assertArrayEquals(hash_expected, hashArray, "hash mismatch");
      assertArrayEquals(input_offset_expected, input_offset, "input_offset mismatch");
      assertArrayEquals(input_expected, input, "input mismatch");
      assertEquals(input_idx_expected, input_idx, "input_idx mismatch");
      assertEquals(hash_size_expected, hash_size, "hash_size mismatch");
    }

    // blake2b final with incorrect hash size
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();
      byte[] hash = new byte[32];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_blake2b_init(ctx, 2 * hash.length);
      mc.crypto_blake2b_update(ctx, message);

      try {
        mc.crypto_blake2b_final(ctx, hash);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("hash must be of length 64 bytes", e.getMessage());
      }
    }

    // blake2b final with null ctx
    {
      Blake2b_ctx ctx = null;
      byte[] hash = new byte[32];

      try {
        mc.crypto_blake2b_final(ctx, null);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("ctx cannot be null", e.getMessage());
      }
    }

    // blake2b final with null hash
    {
      Blake2b_ctx ctx = mc.new Blake2b_ctx();

      try {
        mc.crypto_blake2b_final(ctx, null);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }
  }

  @Test
  @Order(18)
  public void test_crypto_wipe_blake2b_ctx() throws NoSuchFieldException, IllegalAccessException {
    Blake2b_ctx ctx = mc.new Blake2b_ctx();

    mc.crypto_blake2b_init(ctx, 32);

    {
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

    mc.crypto_wipe(ctx);

    {
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
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
            fromHexLEToLong("0000000000000000"),
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
      long hash_size_expected = fromHexLEToLong("0000000000000000");

      assertArrayEquals(hash_expected, hash, "hash mismatch");
      assertArrayEquals(input_offset_expected, input_offset, "input_offset mismatch");
      assertArrayEquals(input_expected, input, "input mismatch");
      assertEquals(input_idx_expected, input_idx, "input_idx mismatch");
      assertEquals(hash_size_expected, hash_size, "hash_size mismatch");
    }
  }

  @Test
  @Order(19)
  public void test_crypto_argon2() {
    // argon2 happy path
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc
          .new Argon2_inputs(
              fromHexToByteArray("00010203040506070809"),
              fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext = mc.new Argon2_extras(null, null);

      byte[] hash = new byte[32];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "36ef27b9a646795126c9e41aa5bef66a50556bd8c84e73412856492529f8373a";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, empty password
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_I, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext = mc.new Argon2_extras(null, null);

      byte[] hash = new byte[32];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "4d0a33ee95d4dcd01cb8be2ad03c5babde3a20d4306a2348f7bceac3907c2b55";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, empty password, with key and ad
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[32];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "7ff21ad59ca877d7c2f78cd30b1d9ff2e2a23b65a058e2ea145d1770bfb638f9";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, 1 byte hash, empty password, with key and ad
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[1];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "b8";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 happy path, 0 byte hash, empty password, with key and ad
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[0];

      mc.crypto_argon2(hash, cfg, inp, ext);

      String expected = "";
      String actual = toHex(hash);

      assertEquals(expected, actual, "hash mismatch");
    }

    // argon2 sad path, null hash
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp =
          mc.new Argon2_inputs(null, fromHexToByteArray("000102030405060708090a0b0c0d0e0f"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = null;

      try {
        mc.crypto_argon2(hash, cfg, inp, ext);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("hash cannot be null", e.getMessage());
      }
    }
    //
    // argon2 sad path, null salt
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp = mc.new Argon2_inputs(null, null);
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[32];

      try {
        mc.crypto_argon2(hash, cfg, inp, ext);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("salt cannot be null", e.getMessage());
      }
    }

    // argon2 sad path, small salt
    {
      Argon2_config cfg = mc.new Argon2_config(Argon2_config.Algorithm_ARGON2_D, 10, 1, 1);
      Argon2_inputs inp = mc.new Argon2_inputs(null, fromHexToByteArray("00"));
      Argon2_extras ext =
          mc
          .new Argon2_extras(
              fromHexToByteArray("0001020304050607"), fromHexToByteArray("0001020304050607"));

      byte[] hash = new byte[32];

      try {
        mc.crypto_argon2(hash, cfg, inp, ext);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("salt needs to be at least 8 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(20)
  public void test_crypto_wipe_argon2_inputs() throws NoSuchFieldException, IllegalAccessException {
    Argon2_inputs input =
        mc.new Argon2_inputs(fromHexToByteArray("aabbccdd"), fromHexToByteArray("aabbccdd"));

    {
      Field passField = Argon2_inputs.class.getDeclaredField("pass");
      Field saltField = Argon2_inputs.class.getDeclaredField("salt");

      passField.setAccessible(true);
      saltField.setAccessible(true);

      byte[] pass = (byte[]) passField.get(input);
      byte[] salt = (byte[]) saltField.get(input);

      byte[] pass_expected = fromHexToByteArray("aabbccdd");
      byte[] salt_expected = fromHexToByteArray("aabbccdd");

      assertArrayEquals(pass_expected, pass, "pass mismatch");
      assertArrayEquals(salt_expected, salt, "salt mismatch");
    }

    mc.crypto_wipe(input);

    {
      Field passField = Argon2_inputs.class.getDeclaredField("pass");
      Field saltField = Argon2_inputs.class.getDeclaredField("salt");

      passField.setAccessible(true);
      saltField.setAccessible(true);

      byte[] pass = (byte[]) passField.get(input);
      byte[] salt = (byte[]) saltField.get(input);

      byte[] pass_expected = fromHexToByteArray("00000000");
      byte[] salt_expected = fromHexToByteArray("00000000");

      assertArrayEquals(pass_expected, pass, "pass mismatch");
      assertArrayEquals(salt_expected, salt, "salt mismatch");
    }
  }

  @Test
  @Order(21)
  public void test_crypto_wipe_argon2_extras() throws NoSuchFieldException, IllegalAccessException {
    Argon2_extras extra =
        mc.new Argon2_extras(fromHexToByteArray("aabbccdd"), fromHexToByteArray("aabbccdd"));

    {
      Field keyField = Argon2_extras.class.getDeclaredField("key");
      Field adField = Argon2_extras.class.getDeclaredField("ad");

      keyField.setAccessible(true);
      adField.setAccessible(true);

      byte[] key = (byte[]) keyField.get(extra);
      byte[] ad = (byte[]) adField.get(extra);

      byte[] key_expected = fromHexToByteArray("aabbccdd");
      byte[] ad_expected = fromHexToByteArray("aabbccdd");

      assertArrayEquals(key_expected, key, "key mismatch");
      assertArrayEquals(ad_expected, ad, "ad mismatch");
    }

    mc.crypto_wipe(extra);

    {
      Field keyField = Argon2_extras.class.getDeclaredField("key");
      Field adField = Argon2_extras.class.getDeclaredField("ad");

      keyField.setAccessible(true);
      adField.setAccessible(true);

      byte[] key = (byte[]) keyField.get(extra);
      byte[] ad = (byte[]) adField.get(extra);

      byte[] key_expected = fromHexToByteArray("00000000");
      byte[] ad_expected = fromHexToByteArray("00000000");

      assertArrayEquals(key_expected, key, "key mismatch");
      assertArrayEquals(ad_expected, ad, "ad mismatch");
    }
  }

  @Test
  @Order(22)
  public void test_crypto_x25519_public_key() {
    // crypto_x25519_public_key happy path
    {
      byte[] secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] public_key = new byte[32];

      mc.crypto_x25519_public_key(public_key, secret_key);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(public_key);

      assertEquals(expected, actual, "public_key mismatch");
    }

    // crypto_x25519_public_key sad path null secret key
    {
      byte[] secret_key = null;
      byte[] public_key = new byte[32];

      try {
        mc.crypto_x25519_public_key(public_key, secret_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("secret_key cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_public_key sad path null public key
    {
      byte[] secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] public_key = null;

      try {
        mc.crypto_x25519_public_key(public_key, secret_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("public_key cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_public_key secret_key invalid length
    {
      byte[] secret_key = fromHexToByteArray("00");
      byte[] public_key = new byte[32];

      try {
        mc.crypto_x25519_public_key(public_key, secret_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("secret_key must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519_public_key public_key invalid length
    {
      byte[] secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] public_key = new byte[1];

      try {
        mc.crypto_x25519_public_key(public_key, secret_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("public_key must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(23)
  public void test_crypto_x25519() {
    // crypto_x25519 happy path
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = new byte[32];

      mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);

      String expected = "df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64";
      String actual = toHex(raw_shared_secret);

      assertEquals(expected, actual, "raw_shared_secret mismatch");
    }

    // crypto_x25519 sad path null secret key
    {
      byte[] your_secret_key = null;
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = new byte[32];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("your_secret_key cannot be null", e.getMessage());
      }
    }

    // crypto_x25519 sad path null public key
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key = null;
      byte[] raw_shared_secret = new byte[32];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("their_public_key cannot be null", e.getMessage());
      }
    }
    //
    // crypto_x25519 sad path raw shared secret
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = null;

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("raw_shared_secret cannot be null", e.getMessage());
      }
    }

    // crypto_x25519 secret_key invalid length
    {
      byte[] your_secret_key = fromHexToByteArray("00");
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = new byte[32];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("your_secret_key must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519 public_key invalid length
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key = fromHexToByteArray("8f");
      byte[] raw_shared_secret = new byte[32];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("their_public_key must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519 public_key invalid length
    {
      byte[] your_secret_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] their_public_key =
          fromHexToByteArray("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
      byte[] raw_shared_secret = new byte[1];

      try {
        mc.crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("raw_shared_secret must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(24)
  public void test_crypto_x25519_to_eddsa() {
    // crypto_x25519_to_eddsa happy path
    {
      byte[] x25519 =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] eddsa = new byte[32];

      mc.crypto_x25519_to_eddsa(eddsa, x25519);

      String expected = "752f61d0e2d2e7577f2aafa6a92298b86bb32521d6d7f109dcd834fc41f2a72a";
      String actual = toHex(eddsa);

      assertEquals(expected, actual, "raw_shared_secret mismatch");
    }

    // crypto_x25519_to_eddsa sad path null x25519
    {
      byte[] x25519 = null;
      byte[] eddsa = new byte[32];

      try {
        mc.crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("x25519 cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_to_eddsa sad path null eddsa
    {
      byte[] x25519 =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] eddsa = null;

      try {
        mc.crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("eddsa cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_to_eddsa sad path small x25519
    {
      byte[] x25519 = fromHexToByteArray("df");
      byte[] eddsa = new byte[32];

      try {
        mc.crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("x25519 must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519_to_eddsa sad path small eddsa
    {
      byte[] x25519 =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] eddsa = new byte[1];

      try {
        mc.crypto_x25519_to_eddsa(eddsa, x25519);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("eddsa must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(25)
  public void test_crypto_x25519_inverse() {
    // crypto_x25519_inverse happy path
    {
      byte[] curve_point =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] private_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] blind_salt = new byte[32];

      mc.crypto_x25519_inverse(blind_salt, private_key, curve_point);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(blind_salt);

      assertEquals(expected, actual, "blind_salt mismatch");
    }

    // crypto_x25519_inverse sad path null blind_salt
    {
      byte[] curve_point =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] private_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] blind_salt = null;

      try {
        mc.crypto_x25519_inverse(blind_salt, private_key, curve_point);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("blind_salt cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_inverse sad path blind_salt invalid length
    {
      byte[] curve_point =
          fromHexToByteArray("df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64");
      byte[] private_key =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] blind_salt = new byte[1];

      try {
        mc.crypto_x25519_inverse(blind_salt, private_key, curve_point);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("blind_salt must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(26)
  public void test_crypto_x25519_dirty_small() {
    // crypto_x25519_dirty_small happy path
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = new byte[32];

      mc.crypto_x25519_dirty_small(pk, sk);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(pk);

      assertEquals(expected, actual, "pk mismatch");
    }

    // crypto_x25519_dirty_small sad path null secret key
    {
      byte[] sk = null;
      byte[] pk = new byte[32];

      try {
        mc.crypto_x25519_dirty_small(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("sk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_small sad path null public key
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = null;

      try {
        mc.crypto_x25519_dirty_small(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("pk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_small sk invalid length
    {
      byte[] sk = fromHexToByteArray("00");
      byte[] pk = new byte[32];

      try {
        mc.crypto_x25519_dirty_small(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("sk must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519_dirty_small pk invalid length
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = new byte[1];

      try {
        mc.crypto_x25519_dirty_small(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("pk must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(26)
  public void test_crypto_x25519_dirty_fast() {
    // crypto_x25519_dirty_fast happy path
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = new byte[32];

      mc.crypto_x25519_dirty_fast(pk, sk);

      String expected = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f";
      String actual = toHex(pk);

      assertEquals(expected, actual, "pk mismatch");
    }

    // crypto_x25519_dirty_fast sad path null secret key
    {
      byte[] sk = null;
      byte[] pk = new byte[32];

      try {
        mc.crypto_x25519_dirty_fast(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("sk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_fast sad path null public key
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = null;

      try {
        mc.crypto_x25519_dirty_fast(pk, sk);
        fail("Expected NullPointerException was not thrown");
      } catch (NullPointerException e) {
        assertEquals("pk cannot be null", e.getMessage());
      }
    }

    // crypto_x25519_dirty_fast sk invalid length
    {
      byte[] sk = fromHexToByteArray("00");
      byte[] pk = new byte[32];

      try {
        mc.crypto_x25519_dirty_fast(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("sk must be an array of length 32 bytes", e.getMessage());
      }
    }

    // crypto_x25519_dirty_fast pk invalid length
    {
      byte[] sk =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] pk = new byte[1];

      try {
        mc.crypto_x25519_dirty_fast(pk, sk);
        fail("Expected IllegalArgumentException was not thrown");
      } catch (IllegalArgumentException e) {
        assertEquals("pk must be an array of length 32 bytes", e.getMessage());
      }
    }
  }

  @Test
  @Order(27)
  public void test_crypto_eddsa_key_pair() {
    // crypto_eddsa_key_pair happy path
    {
      byte[] secret_key = new byte[64];
      byte[] public_key = new byte[32];
      byte[] seed =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

      mc.crypto_eddsa_key_pair(secret_key, public_key, seed);

      String expected, actual;

      expected =
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
              + "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b";
      actual = toHex(secret_key);

      assertEquals(expected, actual, "secret_key mismatch");

      expected = "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b";
      actual = toHex(public_key);

      assertEquals(expected, actual, "public_key mismatch");

      expected = "0000000000000000000000000000000000000000000000000000000000000000";
      actual = toHex(seed);

      assertEquals(expected, actual, "seed mismatch");
    }
  }

  @Test
  @Order(28)
  public void test_crypto_eddsa_sign() {
    // crypto_eddsa_sign happy path
    {
      byte[] secret_key =
          fromHexToByteArray(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature = new byte[64];
      byte[] message = null;

      mc.crypto_eddsa_sign(signature, secret_key, message);

      String expected, actual;

      expected =
          "d137e35f4da1beb4e6628c3af3eeeb335ea769c7ed8489e7aecfdd4fcd4b6207"
              + "5816f7bb8ae0687e6ce8cf4ae6af52ee5db55981d4ae664101fa32596c281f0d";
      actual = toHex(signature);

      assertEquals(expected, actual, "signature mismatch");
    }

    // crypto_eddsa_sign happy path
    {
      byte[] secret_key =
          fromHexToByteArray(
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                  + "f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature = new byte[64];
      byte[] message = fromHexToByteArray("0001020304050607");

      mc.crypto_eddsa_sign(signature, secret_key, message);

      String expected, actual;

      expected =
          "655434d6865d08dff59d21e4623e03fac0023e456b9110a01a1befddc6a4ab0e"
              + "b689e628815958b1ef75086c7d56575636b1eb5b58eb83c9e4fa6443f08ccc07";
      actual = toHex(signature);

      assertEquals(expected, actual, "signature mismatch");
    }
  }

  @Test
  @Order(29)
  public void test_crypto_eddsa_check() {
    // crypto_eddsa_check happy path
    {
      byte[] public_key =
          fromHexToByteArray("f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature =
          fromHexToByteArray(
              "d137e35f4da1beb4e6628c3af3eeeb335ea769c7ed8489e7aecfdd4fcd4b6207"
                  + "5816f7bb8ae0687e6ce8cf4ae6af52ee5db55981d4ae664101fa32596c281f0d");

      byte[] message = null;

      int result = mc.crypto_eddsa_check(signature, public_key, message);

      int expected = 0;

      assertEquals(expected, result, "signature verification failed");
    }

    // crypto_eddsa_check happy path
    {
      byte[] public_key =
          fromHexToByteArray("f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature =
          fromHexToByteArray(
              "655434d6865d08dff59d21e4623e03fac0023e456b9110a01a1befddc6a4ab0e"
                  + "b689e628815958b1ef75086c7d56575636b1eb5b58eb83c9e4fa6443f08ccc07");

      byte[] message = fromHexToByteArray("0001020304050607");

      int result = mc.crypto_eddsa_check(signature, public_key, message);

      int expected = 0;

      assertEquals(expected, result, "signature verification failed");
    }

    // crypto_eddsa_check happy path
    {
      byte[] public_key =
          fromHexToByteArray("f65333fa6303b6a23defd7de2af8aa461cb047ccbf12d4edd29ef3b1eba6706b");
      byte[] signature =
          fromHexToByteArray(
              "0000000000000000000000000000000000000000000000000000000000000000"
                  + "0000000000000000000000000000000000000000000000000000000000000000");

      byte[] message = fromHexToByteArray("0001020304050607");

      int result = mc.crypto_eddsa_check(signature, public_key, message);

      int expected = -1;

      assertEquals(expected, result, "signature verification should fail");
    }
  }

  @Test
  @Order(30)
  public void test_crypto_eddsa_to_x25519() {
    // crypto_eddsa_to_x25519 happy path
    {
      byte[] eddsa =
          fromHexToByteArray("752f61d0e2d2e7577f2aafa6a92298b86bb32521d6d7f109dcd834fc41f2a72a");
      byte[] x25519 = new byte[32];

      mc.crypto_eddsa_to_x25519(x25519, eddsa);

      String expected = "df6baf6f6a43b9744fc5ef9dea1122782f9f696dc4a0d15c03c1787ee6d15e64";
      String actual = toHex(x25519);

      assertEquals(expected, actual, "x25519 mismatch");
    }
  }

  @Test
  @Order(30)
  public void test_crypto_trim_scalar() {
    // crypto_trim_scalar happy path
    {
      byte[] in =
          fromHexToByteArray("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
      byte[] out = new byte[32];

      mc.crypto_eddsa_trim_scalar(out, in);

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
      byte[] expanded =
          fromHexToByteArray(
              "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                  + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
      byte[] reduced = new byte[32];
      ;

      mc.crypto_eddsa_reduce(reduced, expanded);

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
      byte[] a =
          fromHexToByteArray("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
      byte[] b =
          fromHexToByteArray("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
      byte[] c =
          fromHexToByteArray("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
      byte[] r = new byte[32];

      mc.crypto_eddsa_mul_add(r, a, b, c);

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
      byte[] scalar =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] point = new byte[32];

      mc.crypto_eddsa_scalarbase(point, scalar);

      String expected = "ca4a448c3fc4d04945da9fdf920976c05e9bbe3d8cebb1858ea44d587c5e63c3";
      String actual = toHex(point);

      assertEquals(expected, actual, "point mismatch");
    }
  }

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

  private static int fromHexLEToInt(String hex) {
    if (hex.length() != 8) {
      throw new IllegalArgumentException("Hex string must be exactly 8 characters for 4 bytes");
    }

    int result = 0;
    for (int i = 0; i < 4; i++) {
      int byteIndex = i * 2;
      int value = Integer.parseInt(hex.substring(byteIndex, byteIndex + 2), 16);
      result |= (value & 0xFF) << (8 * i); // little-endian shift
    }

    return result;
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

  @Test
  @Order(44)
  public void test_crypto_elligator_key_pair() {
    // crypto_elligator_key_pair happy path
    {
      byte[] seed =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] hidden = new byte[32];
      byte[] secret = new byte[32];

      mc.crypto_elligator_key_pair(hidden, secret, seed);

      String hidden_expected = "f7e4a52e7996ca06d6d6cb8f4d11f2a89e30ca7df2a30cdadce51e5c84cb009d";
      String hidden_actual = toHex(hidden);

      assertEquals(hidden_expected, hidden_actual, "hidden mismatch");

      String secret_expected = "9cacebfbb286731920ea82342050641ed065ea6431e85e1f3926028214e52507";
      String secret_actual = toHex(secret);

      assertEquals(secret_expected, secret_actual, "secret mismatch");

      String seed_expected = "0000000000000000000000000000000000000000000000000000000000000000";
      String seed_actual = toHex(seed);

      assertEquals(seed_expected, seed_actual, "seed mismatch");
    }
  }

  @Test
  @Order(45)
  public void test_crypto_elligator_rev() {
    // crypto_elligator_rev happy path
    {
      byte[] secret =
          fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      byte[] hidden = new byte[32];
      byte tweak = 0x00;

      {
        mc.crypto_x25519_dirty_small(hidden, secret);
        int result = mc.crypto_elligator_rev(hidden, hidden, tweak);
        int expected = -1;
        assertEquals(expected, result, "crypto_elligator_rev mismatch");
      }

      secret[0]++;

      {
        mc.crypto_x25519_dirty_small(hidden, secret);
        int result = mc.crypto_elligator_rev(hidden, hidden, tweak);
        int expected = 0;
        assertEquals(expected, result, "crypto_elligator_rev mismatch");

        String hidden_expected = "9e5a7fa6532ba0750540700e7d0420fc0ba61f0fc126c9732d5569636c683f24";
        String hidden_actual = toHex(hidden);
        assertEquals(hidden_expected, hidden_actual, "hidden mismatch");
      }
    }
  }

  @Test
  @Order(46)
  public void test_crypto_elligator_map() {
    // crypto_elligator_map happy path
    {
      byte[] hidden =
          fromHexToByteArray("9e5a7fa6532ba0750540700e7d0420fc0ba61f0fc126c9732d5569636c683f24");
      byte[] curve = new byte[32];

      mc.crypto_elligator_map(curve, hidden);

      String expected = "4bccf87523680f38820e85a5956f1dba2bd9564dc8a92bf395b8996f41ce724a";

      String actual = toHex(curve);

      assertEquals(expected, actual, "curve mismatch");
    }
  }
}
