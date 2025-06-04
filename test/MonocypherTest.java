import net.lastninja.monocypher.Monocypher;

public class MonocypherTest {
  public static void main(String[] args) {
    byte[] a = new byte[16];
    byte[] b = new byte[16];
    a[0] = 42;
    b[0] = 42;

    Monocypher mc = new Monocypher();
    int result = mc.crypto_verify16(a, b);
    System.out.println("Result: " + result); // Expected: non-zero
  }
}
