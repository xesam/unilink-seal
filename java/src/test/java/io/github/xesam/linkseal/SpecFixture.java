package io.github.xesam.linkseal;

import io.github.xesam.linkseal.model.LinkSealProtocol;
import io.github.xesam.linkseal.model.MissingPolicy;
import io.github.xesam.linkseal.model.PolicyConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the shared spec example so the Java SDK verifies the very signature the JavaScript
 * signer produced. A minimal reader is used to keep the SDK free of JSON dependencies.
 */
final class SpecFixture {
  private static final Path EXAMPLE = Path.of("../spec/examples/user-profile.signed.json");
  private static final Path EXPIRING = Path.of("../spec/examples/expiring-rotated.signed.json");
  private static final Path PUBLIC_KEY = Path.of("../spec/keys/test-public.pem");
  private static final Path PRIVATE_KEY = Path.of("../spec/keys/test-private.pem");

  private SpecFixture() {}

  static String publicKey() throws Exception {
    return Files.readString(PUBLIC_KEY);
  }

  static String privateKey() throws Exception {
    return Files.readString(PRIVATE_KEY);
  }

  static String signature() throws Exception {
    return field(Files.readString(EXAMPLE), "signature");
  }

  static LinkSealProtocol payload() throws Exception {
    String json = Files.readString(EXAMPLE);
    return new LinkSealProtocol(field(json, "version"), field(json, "template"), policy(json));
  }

  /** The expiring-rotated example carries expiresAt + kid; its signature was produced by the
   *  JavaScript signer, so reading it here pins cross-SDK agreement for the new fields. */
  static String expiringSignature() throws Exception {
    return field(Files.readString(EXPIRING), "signature");
  }

  static LinkSealProtocol expiringPayload() throws Exception {
    String json = Files.readString(EXPIRING);
    return new LinkSealProtocol(
        field(json, "version"), field(json, "template"), policy(json),
        field(json, "expiresAt"), field(json, "kid"));
  }

  private static String field(String json, String key) {
    Matcher matcher = Pattern.compile("\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
    if (!matcher.find()) {
      throw new IllegalStateException("Missing field in spec example: " + key);
    }
    return unescape(matcher.group(1));
  }

  private static PolicyConfig policy(String json) {
    Matcher block = Pattern.compile("\"policy\"\\s*:\\s*\\{([^}]*)}").matcher(json);
    if (!block.find()) {
      throw new IllegalStateException("Missing policy in spec example");
    }
    return new PolicyConfig(switch (field(block.group(1), "missing")) {
      case "error" -> MissingPolicy.ERROR;
      case "ignore" -> MissingPolicy.IGNORE;
      case "default" -> MissingPolicy.DEFAULT;
      default -> throw new IllegalStateException("Unknown missing policy in spec example");
    });
  }

  private static String unescape(String value) {
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch != '\\') {
        out.append(ch);
        continue;
      }
      char next = value.charAt(++i);
      switch (next) {
        case 'n' -> out.append('\n');
        case 'r' -> out.append('\r');
        case 't' -> out.append('\t');
        case 'b' -> out.append('\b');
        case 'f' -> out.append('\f');
        case 'u' -> {
          out.append((char) Integer.parseInt(value.substring(i + 1, i + 5), 16));
          i += 4;
        }
        default -> out.append(next);
      }
    }
    return out.toString();
  }
}
