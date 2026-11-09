import static org.junit.jupiter.api.Assertions.*;
import static net.lastninja.monocypher.Monocypher.*;
import static net.lastninja.monocypher.TestUtil.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import net.lastninja.monocypher.Monocypher;
import net.lastninja.monocypher.Monocypher.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(VerboseTestWatcher.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AeadTest {

  private static void assertAeadCtx(AEAD_ctx ctx, long counter, byte[] key, byte[] nonce) {
    ByteBuffer expected =
        ByteBuffer.allocate(48).order(ByteOrder.nativeOrder()).putLong(counter).put(key).put(nonce);
    assertTrue(ctxContains(ctx, expected.array()), "ctx does not hold the expected state");
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

      crypto_aead_lock(cipher_text, mac, direct(key), nonce, ad, plain_text);

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

      crypto_aead_lock(cipher_text, mac, direct(key), nonce, null, plain_text);

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

      crypto_aead_lock(plain_text, mac, direct(key), nonce, ad, plain_text);

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

      crypto_aead_lock(plain_text, mac, direct(key), nonce, ad, plain_text);

      String expected =
          "4141414141414141414141414141414141414141414141413c5d023efcae618eaee3bfcd2503ede5000000000000000000000000000000000000000000000000a9b575a2b4f903d98a2e96cff1ee0c38085fdf4de47fcfafbecd883596be8ed77179afc37aaa826a2995dc54eed427ea14431a0e87b43239f835caffef109ef3";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);
    }
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

      int result = crypto_aead_unlock(plain_text, mac, direct(key), nonce, ad, cipher_text);

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

      int result = crypto_aead_unlock(plain_text, mac, direct(key), nonce, null, cipher_text);

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

      crypto_aead_unlock(cipher_text, mac, direct(key), nonce, ad, cipher_text);

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

      crypto_aead_unlock(cipher_text, mac, direct(key), nonce, null, cipher_text);

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

      int result = crypto_aead_unlock(plain_text, mac, direct(key), nonce, ad, cipher_text);

      assertEquals(result, -1);
    }
  }

  @Test
  @Order(7)
  public void test_crypto_aead_init_x() {
    AEAD_ctx ctx = new AEAD_ctx();
    byte[] key = new byte[32];
    byte[] nonce = new byte[24];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (byte) i;
    }

    crypto_aead_init_x(ctx, direct(key), direct(nonce));

    long counter_expected = fromHexLEToLong("0000000000000000");
    byte[] key_expected =
        fromHexToByteArray("51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6");
    byte[] nonce_expected = fromHexToByteArray("1011121314151617");

    assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);
  }

  @Test
  @Order(8)
  public void test_crypto_aead_init_djb() {
    AEAD_ctx ctx = new AEAD_ctx();
    byte[] key = new byte[32];
    byte[] nonce = new byte[8];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (byte) i;
    }

    crypto_aead_init_djb(ctx, direct(key), direct(nonce));

    long counter_expected = fromHexLEToLong("0000000000000000");
    byte[] key_expected =
        fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    byte[] nonce_expected = fromHexToByteArray("0001020304050607");

    assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);
  }

  @Test
  @Order(9)
  public void test_crypto_aead_init_ietf() {
    AEAD_ctx ctx = new AEAD_ctx();
    byte[] key = new byte[32];
    byte[] nonce = new byte[12];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (byte) i;
    }

    crypto_aead_init_ietf(ctx, direct(key), direct(nonce));

    long counter_expected = fromHexLEToLong("0000000000010203");
    byte[] key_expected =
        fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    byte[] nonce_expected = fromHexToByteArray("0405060708090a0b");

    assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);
  }

  @Test
  @Order(10)
  public void test_crypto_wipe_aead_ctx() {
    AEAD_ctx ctx = new AEAD_ctx();
    byte[] key = new byte[32];
    byte[] nonce = new byte[12];

    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) i;
    }

    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = (byte) i;
    }

    crypto_aead_init_ietf(ctx, direct(key), direct(nonce));

    long counter_expected = fromHexLEToLong("0000000000010203");
    byte[] key_expected =
        fromHexToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    byte[] nonce_expected = fromHexToByteArray("0405060708090a0b");

    assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);

    crypto_wipe(ctx);

    assertTrue(ctxIsZero(ctx), "ctx not wiped");
  }

  @Test
  @Order(11)
  public void test_crypto_aead_write() {
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

      AEAD_ctx ctx = new AEAD_ctx();

      byte[] nonceArray = new byte[24];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      crypto_aead_init_x(ctx, direct(key), direct(nonceArray));
      crypto_aead_write(ctx, plain_text, mac, ad, plain_text);

      String expected =
          "000102030405060708090a0b0c0d0e0f10111213141516175318bc062203b6c214b24c1f98b84dfa424242424242424242424242424242424242424242424242dd814c3cd391ceed7007658d8811ebab08046be6be955ea83c597cf57eeeb61a1d45f5a702244a2796d6ed1a8c62102132f9a11a0437b85a44d8d07ecca407b7";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      long counter_expected = fromHexLEToLong("0000000000000000");
      byte[] key_expected =
          fromHexToByteArray("68fbee56c9c20c39960e595f3ea76c979804d08cfa728e66cb5f766b840ec61f");
      byte[] nonce_expected = fromHexToByteArray("1011121314151617");

      assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);
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

      AEAD_ctx ctx = new AEAD_ctx();

      byte[] nonceArray = new byte[8];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      crypto_aead_init_djb(ctx, direct(key), direct(nonceArray));
      crypto_aead_write(ctx, plain_text, mac, ad, plain_text);

      String expected =
          "000102030405060708090a0b0c0d0e0f10111213141516175fa63e1182edfc77a9ea50eb8661f91a4242424242424242424242424242424242424242424242427b43c8d965ff76d75d6707543fc99d25ca9dd6650ac59a1bcab823ab056a8afed919885f825bfd157dfaf0e7e731bb6d4ae4a43b0a68156db4504dcb9ca37284";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      long counter_expected = fromHexLEToLong("0000000000000000");
      byte[] key_expected =
          fromHexToByteArray("34a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a");
      byte[] nonce_expected = fromHexToByteArray("0001020304050607");

      assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);
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

      AEAD_ctx ctx = new AEAD_ctx();

      byte[] nonceArray = new byte[12];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      crypto_aead_init_ietf(ctx, direct(key), direct(nonceArray));
      crypto_aead_write(ctx, plain_text, mac, ad, plain_text);

      String expected =
          "000102030405060708090a0b0c0d0e0f101112131415161779c5dd122dabf8d5e9d4a7f2110b3486424242424242424242424242424242424242424242424242cab84b436a54e603f4c07cb0db5e4d208a33f1a41237eefaa5d46c863683e57fafc36fb0a55df2db7471359b26d7cc603dc7ea37be6bfbd851fb9a44d30cdd95";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      long counter_expected = fromHexLEToLong("0000000000010203");
      byte[] key_expected =
          fromHexToByteArray("d5ff9a658dd52c708bef1f0f622b3747040fa3551300b1f293150a88620d5fed");
      byte[] nonce_expected = fromHexToByteArray("0405060708090a0b");

      assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);
    }
  }

  @Test
  @Order(12)
  public void test_crypto_aead_read() {
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

      AEAD_ctx ctx = new AEAD_ctx();

      byte[] nonceArray = new byte[24];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      crypto_aead_init_x(ctx, direct(key), direct(nonceArray));
      int result = crypto_aead_read(ctx, cipher_text, mac, ad, cipher_text);

      assertEquals(result, 0);

      String expected =
          "000102030405060708090a0b0c0d0e0f10111213141516175318bc062203b6c214b24c1f98b84dfa42424242424242424242424242424242424242424242424243434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      long counter_expected = fromHexLEToLong("0000000000000000");
      byte[] key_expected =
          fromHexToByteArray("68fbee56c9c20c39960e595f3ea76c979804d08cfa728e66cb5f766b840ec61f");
      byte[] nonce_expected = fromHexToByteArray("1011121314151617");

      assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);
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

      AEAD_ctx ctx = new AEAD_ctx();

      byte[] nonceArray = new byte[8];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      crypto_aead_init_djb(ctx, direct(key), direct(nonceArray));
      int result = crypto_aead_read(ctx, cipher_text, mac, ad, cipher_text);

      assertEquals(result, 0);

      String expected =
          "000102030405060708090a0b0c0d0e0f10111213141516175fa63e1182edfc77a9ea50eb8661f91a42424242424242424242424242424242424242424242424243434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      long counter_expected = fromHexLEToLong("0000000000000000");
      byte[] key_expected =
          fromHexToByteArray("34a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a");
      byte[] nonce_expected = fromHexToByteArray("0001020304050607");

      assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);
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

      AEAD_ctx ctx = new AEAD_ctx();

      byte[] nonceArray = new byte[12];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      crypto_aead_init_ietf(ctx, direct(key), direct(nonceArray));
      int result = crypto_aead_read(ctx, cipher_text, mac, ad, cipher_text);

      assertEquals(result, 0);

      String expected =
          "000102030405060708090a0b0c0d0e0f101112131415161779c5dd122dabf8d5e9d4a7f2110b348642424242424242424242424242424242424242424242424243434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343";

      String actual = toHex(encrypted_message);

      assertEquals(expected, actual);

      long counter_expected = fromHexLEToLong("0000000000010203");
      byte[] key_expected =
          fromHexToByteArray("d5ff9a658dd52c708bef1f0f622b3747040fa3551300b1f293150a88620d5fed");
      byte[] nonce_expected = fromHexToByteArray("0405060708090a0b");

      assertAeadCtx(ctx, counter_expected, key_expected, nonce_expected);
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

      AEAD_ctx ctx = new AEAD_ctx();

      byte[] nonceArray = new byte[24];
      {
        ByteBuffer tmp = nonce.duplicate();
        tmp.get(nonceArray);
      }
      crypto_aead_init_x(ctx, direct(key), direct(nonceArray));
      int result = crypto_aead_read(ctx, cipher_text, mac, ad, cipher_text);

      assertEquals(result, -1);
    }
  }

  private static final int SHORT = 4;

  private static IllegalArgumentException assertIae(org.junit.jupiter.api.function.Executable e) {
    return assertThrows(IllegalArgumentException.class, e);
  }

  private static ByteBuffer buf(int len) {
    return ByteBuffer.allocateDirect(len);
  }

  private static AEAD_ctx readyCtx() {
    AEAD_ctx ctx = new AEAD_ctx();
    crypto_aead_init_x(ctx, buf(32), buf(24));
    return ctx;
  }

  @Test
  @Order(100)
  public void test_lock_rejects_cipher_text_shorter_than_plain_text() {
    IllegalArgumentException e =
        assertIae(() -> crypto_aead_lock(buf(SHORT), buf(16), buf(32), buf(24), null, buf(4096)));
    assertEquals("cipher_text must have the same length as plain_text", e.getMessage());
  }

  @Test
  @Order(101)
  public void test_unlock_rejects_plain_text_shorter_than_cipher_text() {
    IllegalArgumentException e =
        assertIae(() -> crypto_aead_unlock(buf(SHORT), buf(16), buf(32), buf(24), null, buf(4096)));
    assertEquals("plain_text must have the same length as cipher_text", e.getMessage());
  }

  @Test
  @Order(102)
  public void test_write_and_read_reject_mismatched_text() {
    AEAD_ctx ctx = readyCtx();
    assertIae(() -> crypto_aead_write(ctx, buf(SHORT), buf(16), null, buf(4096)));
    assertIae(() -> crypto_aead_read(ctx, buf(SHORT), buf(16), null, buf(4096)));
  }

  @Test
  @Order(103)
  public void test_rejects_wrong_key_nonce_and_mac_sizes() {
    assertIae(() -> crypto_aead_lock(buf(8), buf(15), buf(32), buf(24), null, buf(8)));
    assertIae(() -> crypto_aead_lock(buf(8), buf(16), buf(31), buf(24), null, buf(8)));
    assertIae(() -> crypto_aead_lock(buf(8), buf(16), buf(32), buf(23), null, buf(8)));
    assertIae(() -> crypto_aead_init_x(new AEAD_ctx(), buf(32), buf(12)));
    assertIae(() -> crypto_aead_init_djb(new AEAD_ctx(), buf(32), buf(12)));
    assertIae(() -> crypto_aead_init_ietf(new AEAD_ctx(), buf(32), buf(8)));
  }

  @Test
  @Order(104)
  public void test_rejects_null_heap_and_read_only_arguments() {
    assertThrows(
        NullPointerException.class,
        () -> crypto_aead_lock(null, buf(16), buf(32), buf(24), null, buf(8)));
    assertThrows(
        NullPointerException.class,
        () -> crypto_aead_lock(buf(8), buf(16), null, buf(24), null, buf(8)));
    assertIae(() -> crypto_aead_lock(buf(8), buf(16), ByteBuffer.allocate(32), buf(24), null, buf(8)));
    assertIae(() -> crypto_aead_lock(buf(8).asReadOnlyBuffer(), buf(16), buf(32), buf(24), null, buf(8)));
    assertIae(() -> crypto_aead_lock(buf(8), buf(16).asReadOnlyBuffer(), buf(32), buf(24), null, buf(8)));
  }

  private static ByteBuffer window(ByteBuffer base, int from, int to) {
    ByteBuffer view = base.duplicate();
    view.position(from).limit(to);
    return view.slice();
  }

  @Test
  @Order(105)
  public void test_rejects_overlap() {
    ByteBuffer m = buf(128);

    IllegalArgumentException e =
        assertIae(
            () ->
                crypto_aead_lock(
                    window(m, 0, 32), buf(16), buf(32), buf(24), null, window(m, 8, 40)));
    assertEquals("cipher_text must be the same memory as plain_text or not overlap it", e.getMessage());

    assertIae(
        () -> crypto_aead_lock(window(m, 0, 32), window(m, 0, 16), buf(32), buf(24), null, buf(32)));
    assertIae(
        () -> crypto_aead_lock(window(m, 0, 32), buf(16), window(m, 0, 32), buf(24), null, buf(32)));
    assertIae(
        () -> crypto_aead_lock(window(m, 0, 32), buf(16), buf(32), buf(24), window(m, 0, 8), buf(32)));
  }

  @Test
  @Order(106)
  public void test_in_place_matches_separate_buffers() {
    byte[] text = new byte[64];
    for (int i = 0; i < text.length; i++) text[i] = (byte) i;

    ByteBuffer separate = buf(64);
    ByteBuffer mac1 = buf(16);
    crypto_aead_lock(separate, mac1, buf(32), buf(24), null, direct(text));

    ByteBuffer inPlace = direct(text);
    ByteBuffer mac2 = buf(16);
    crypto_aead_lock(inPlace, mac2, buf(32), buf(24), null, inPlace);

    assertEquals(toHex(separate), toHex(inPlace));
    assertEquals(toHex(mac1), toHex(mac2));
  }

  @Test
  @Order(107)
  public void test_honours_position_and_leaves_it_alone() {
    byte[] text = new byte[32];
    for (int i = 0; i < text.length; i++) text[i] = (byte) i;

    ByteBuffer plain = buf(48);
    plain.position(8);
    plain.put(text);
    plain.position(8).limit(40);
    ByteBuffer cipher = buf(48);
    cipher.position(16).limit(48);
    ByteBuffer mac = buf(16);

    crypto_aead_lock(cipher, mac, buf(32), buf(24), null, plain);

    assertEquals(8, plain.position());
    assertEquals(16, cipher.position());

    ByteBuffer expected = buf(32);
    ByteBuffer expectedMac = buf(16);
    crypto_aead_lock(expected, expectedMac, buf(32), buf(24), null, direct(text));
    assertEquals(toHex(expected), toHex(cipher));
    assertEquals(toHex(expectedMac), toHex(mac));
  }

  @Test
  @Order(108)
  public void test_ctx_state_is_enforced() {
    AEAD_ctx ctx = new AEAD_ctx();
    assertThrows(
        IllegalStateException.class, () -> crypto_aead_write(ctx, buf(8), buf(16), null, buf(8)));

    crypto_aead_init_x(ctx, buf(32), buf(24));
    crypto_aead_write(ctx, buf(8), buf(16), null, buf(8));

    crypto_wipe(ctx);
    assertTrue(ctxIsZero(ctx), "ctx not wiped");
    assertThrows(
        IllegalStateException.class, () -> crypto_aead_read(ctx, buf(8), buf(16), null, buf(8)));

    assertThrows(NullPointerException.class, () -> crypto_aead_init_x(null, buf(32), buf(24)));
    crypto_wipe((AEAD_ctx) null);
  }

  @Test
  @Order(109)
  public void test_close_wipes_ctx() {
    AEAD_ctx leaked;
    try (AEAD_ctx ctx = readyCtx()) {
      leaked = ctx;
      assertFalse(ctxIsZero(ctx));
    }
    assertTrue(ctxIsZero(leaked), "close did not wipe");
  }

  @Test
  @Order(110)
  public void test_forgery_is_rejected_and_ctx_keeps_working() {
    byte[] text = new byte[16];
    ByteBuffer cipher = buf(16);
    ByteBuffer mac = buf(16);
    crypto_aead_lock(cipher, mac, buf(32), buf(24), null, direct(text));

    ByteBuffer plain = buf(16);
    plain.put(0, (byte) 0x7f);
    mac.put(0, (byte) (mac.get(0) ^ 1));
    assertEquals(-1, crypto_aead_unlock(plain, mac, buf(32), buf(24), null, cipher));
    assertEquals(0x7f, plain.get(0), "plain_text was written despite a bad mac");

    mac.put(0, (byte) (mac.get(0) ^ 1));
    assertEquals(0, crypto_aead_unlock(plain, mac, buf(32), buf(24), null, cipher));
    assertEquals(0, plain.get(0));
  }
}
