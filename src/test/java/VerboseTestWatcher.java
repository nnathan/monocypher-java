import java.util.Optional;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

public class VerboseTestWatcher implements TestWatcher {
  @Override
  public void testSuccessful(ExtensionContext context) {
    System.out.println("✓ " + context.getDisplayName());
  }

  @Override
  public void testFailed(ExtensionContext context, Throwable cause) {
    System.out.println("✗ " + context.getDisplayName() + " failed: " + cause);
  }

  @Override
  public void testDisabled(ExtensionContext context, Optional<String> reason) {
    System.out.println(
        "⚠ " + context.getDisplayName() + " disabled: " + reason.orElse("no reason"));
  }
}
