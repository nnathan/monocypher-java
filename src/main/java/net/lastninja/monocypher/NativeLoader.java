package net.lastninja.monocypher;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

final class NativeLoader {
  private static final String LIBRARY_PATH_PROPERTY = "monocypher.library.path";

  private NativeLoader() {}

  static void load() {
    String override = System.getProperty(LIBRARY_PATH_PROPERTY);
    if (override != null) {
      System.load(override);
    } else if (isAndroid()) {
      System.loadLibrary("monocypher_jni");
    } else {
      System.load(extract("/native/" + target() + "/" + libraryName()));
    }
  }

  static String target() {
    String name = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    String arch = arch(System.getProperty("os.arch").toLowerCase(Locale.ROOT));
    if (name.startsWith("linux")) return "linux-" + arch + (isMusl() ? "-musl" : "");
    if (name.startsWith("mac")) return "macos-" + arch;
    if (name.startsWith("windows")) return "windows-" + arch;
    throw new UnsatisfiedLinkError("Unsupported platform: " + name + " " + arch);
  }

  private static String arch(String arch) {
    switch (arch) {
      case "amd64":
      case "x86_64":
        return "x86_64";
      case "aarch64":
      case "arm64":
        return "arm64";
      case "x86":
      case "i386":
      case "i686":
        return "x86";
      case "arm":
        return "armv6";
      default:
        return arch;
    }
  }

  private static String libraryName() {
    String name = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    if (name.startsWith("windows")) return "monocypher_jni.dll";
    if (name.startsWith("mac")) return "libmonocypher_jni.dylib";
    return "libmonocypher_jni.so";
  }

  private static boolean isAndroid() {
    return "Dalvik".equals(System.getProperty("java.vm.name"));
  }

  private static boolean isMusl() {
    try (BufferedReader maps = new BufferedReader(new FileReader("/proc/self/maps"))) {
      String line;
      while ((line = maps.readLine()) != null) {
        if (line.contains("/ld-musl-") || line.contains("/libc.musl-")) return true;
      }
    } catch (IOException e) {
      return false;
    }
    return false;
  }

  private static String extract(String resource) {
    try (InputStream in = NativeLoader.class.getResourceAsStream(resource)) {
      if (in == null) throw new UnsatisfiedLinkError("No native library for " + resource);

      String suffix = resource.substring(resource.lastIndexOf('.'));
      Path temp = Files.createTempFile("monocypher_jni", suffix);
      // Windows cannot delete a loaded DLL, so one small file stays behind there.
      temp.toFile().deleteOnExit();

      Files.copy(in, temp, StandardCopyOption.REPLACE_EXISTING);
      return temp.toAbsolutePath().toString();
    } catch (IOException e) {
      UnsatisfiedLinkError error = new UnsatisfiedLinkError("Cannot extract " + resource);
      error.initCause(e);
      throw error;
    }
  }
}
