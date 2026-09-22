package io.github.xesam.unilink.seal;

import io.github.xesam.unilink.seal.model.LinkSealProtocol;
import io.github.xesam.unilink.seal.model.PolicyConfig;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Reference {@link JsonSerializer} covering the full v1 protocol ({@code version}, {@code template},
 * {@code policy} with optional {@code defaults}, {@code expiresAt}, {@code kid}).
 *
 * <p>This is a zero-dependency reference implementation. Callers who already bind Jackson/Gson
 * should inject that instead (e.g., {@code payload -> mapper.writeValueAsString(payload)}).
 *
 * <p><strong>CRITICAL</strong>: Any serializer MUST cover all protocol fields, including optional
 * ones when present. Fields omitted from serialization will <strong>not be protected by the
 * signature</strong> and can be tampered with.
 *
 * <p>The serialized JSON need not be canonical — keys may appear in any order — because
 * {@link Canonicalizer} re-serializes it per RFC 8785.
 *
 * <p><strong>Testing field coverage:</strong> When adding new protocol fields (e.g., v1.1 introduces
 * {@code nonce}), update {@link #serialize} and run {@link #assertFieldCoverage} in tests to verify
 * all fields are included.
 */
public final class ReferenceJsonSerializer implements JsonSerializer {

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
    String json = sb.toString();
    assertFieldCoverage(payload, json);
    return json;
  }

  /**
   * Guards this reference serializer against future field drift: every v1 payload field must
   * appear in the emitted JSON, because a field the serializer omits silently drops out of the
   * signature coverage. When a new protocol field is added, extend both {@code serialize} and
   * this check (see CONTRIBUTING.md).
   *
   * <p>This method should be called in unit tests to verify field coverage after protocol changes.
   */
  public static void assertFieldCoverage(LinkSealProtocol payload, String json) {
    for (String key : new String[] {"version", "template", "policy"}) {
      if (!json.contains("\"" + key + "\":")) {
        throw new IllegalStateException("ReferenceJsonSerializer dropped field '" + key + "' from the signature coverage");
      }
    }
    if (payload.expiresAt() != null && !json.contains("\"expiresAt\":")) {
      throw new IllegalStateException("ReferenceJsonSerializer dropped field 'expiresAt' from the signature coverage");
    }
    if (payload.kid() != null && !json.contains("\"kid\":")) {
      throw new IllegalStateException("ReferenceJsonSerializer dropped field 'kid' from the signature coverage");
    }
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
