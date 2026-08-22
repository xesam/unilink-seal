package io.github.xesam.linkseal;

import io.github.xesam.linkseal.model.LinkSealProtocol;
import io.github.xesam.linkseal.model.PolicyConfig;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Reference {@link JsonSerializer} covering the full v1 protocol ({@code version}, {@code template},
 * {@code policy} with optional {@code defaults}).
 *
 * <p>Ships a correct serializer by default so callers don't hand-roll one and accidentally drop a
 * field from the signature coverage. The serialized JSON need not be canonical — keys may appear
 * in any order — because {@link Canonicalizer} re-serializes it per RFC 8785. Callers who already
 * bind Jackson/Gson may inject that instead; this class is for those who want a zero-dependency
 * default.
 */
public final class DefaultJsonSerializer implements JsonSerializer {

  @Override
  public String serialize(LinkSealProtocol payload) {
    StringBuilder sb = new StringBuilder();
    sb.append('{');
    sb.append("\"version\":").append(quote(payload.version()));
    sb.append(",\"template\":").append(quote(payload.template()));
    sb.append(",\"policy\":").append(policyToJson(payload.policy()));
    if (payload.expiresAt() != null) {
      sb.append(",\"expiresAt\":").append(quote(payload.expiresAt()));
    }
    if (payload.kid() != null) {
      sb.append(",\"kid\":").append(quote(payload.kid()));
    }
    sb.append('}');
    return sb.toString();
  }

  private static String policyToJson(PolicyConfig policy) {
    StringBuilder sb = new StringBuilder().append('{');
    sb.append("\"missing\":").append(quote(policy.missing().wireValue()));
    Map<String, String> defaults = policy.defaults();
    if (!defaults.isEmpty()) {
      sb.append(",\"defaults\":").append(mapToJson(defaults));
    }
    sb.append('}');
    return sb.toString();
  }

  private static String mapToJson(Map<String, String> map) {
    List<String> keys = new ArrayList<>(map.keySet());
    Collections.sort(keys);
    StringBuilder sb = new StringBuilder().append('{');
    for (int i = 0; i < keys.size(); i++) {
      if (i > 0) {
        sb.append(',');
      }
      String key = keys.get(i);
      sb.append(quote(key)).append(':').append(quote(map.get(key)));
    }
    sb.append('}');
    return sb.toString();
  }

  private static String quote(String value) {
    StringBuilder out = new StringBuilder("\"");
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (ch < 0x20) {
            out.append(String.format("\\u%04x", (int) ch));
          } else {
            out.append(ch);
          }
        }
      }
    }
    return out.append('"').toString();
  }
}
