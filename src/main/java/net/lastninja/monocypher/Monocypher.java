package net.lastninja.monocypher;

import com.sun.jna.Platform;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class Monocypher {
  static {
    try {
      String lib = "";
      String suffix = "";

      if (Platform.isMac()) {
        if (Platform.isARM()) {
          suffix = ".dylib";
          lib = "/native/mac_arm/libmonocypher_jni.dylib";
        }
      }

      InputStream in = Monocypher.class.getResourceAsStream(lib);
      if (in == null) throw new UnsatisfiedLinkError("Native lib not found: " + lib);

      File temp = File.createTempFile("libmonocypher_jni", suffix);
      temp.deleteOnExit();

      try (OutputStream out = new FileOutputStream(temp)) {
        byte[] buf = new byte[4096];
        int len;
        while ((len = in.read(buf)) != -1) out.write(buf, 0, len);
      }

      System.load(temp.getAbsolutePath());
    } catch (IOException e) {
      throw new RuntimeException("Failed to load native library", e);
    }
  }

  public native int crypto_verify16(byte[] a, byte[] b);

  public native int crypto_verify32(byte[] a, byte[] b);

  public native int crypto_verify64(byte[] a, byte[] b);

  public native void crypto_wipe(byte[] buf);

  public native void crypto_aead_lock(
      ByteBuffer cipher_text,
      ByteBuffer mac,
      byte[] key,
      ByteBuffer nonce,
      ByteBuffer ad,
      ByteBuffer plain_text);

  public native int crypto_aead_unlock(
      ByteBuffer plain_text,
      ByteBuffer mac,
      byte[] key,
      ByteBuffer nonce,
      ByteBuffer ad,
      ByteBuffer cipher_text);
}
