package io.github.xesam.linkseal.resolver;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Expands the LinkSeal-supported subset of RFC 6570 URI templates.
 *
 * <p>Supported expressions (and only these):
 * <ul>
 *   <li>{@code {var}} — simple substitution (Level 1), one or more comma-separated names</li>
 *   <li>{@code {?var}} — form-style query start</li>
 *   <li>{@code {&amp;var}} — form-style query continuation</li>
 * </ul>
 *
 * <p>Unsupported RFC 6570 operators ({@code + # . / ;}) and modifiers (explode {@code *},
 * prefix {@code :N}) are <strong>rejected</strong> rather than silently mis-expanded, so this
 * SDK accepts and rejects the same template grammar as the JavaScript SDK. Variable names are
 * restricted to {@code [A-Za-z0-9_.]}.
 *
 * <p>Value encoding follows strict RFC 6570, which defers to RFC 3986 "unreserved":
 * {@code A-Za-z0-9-._~} pass through unchanged; every other byte is percent-encoded as its
 * UTF-8 octet. This is hand-rolled (not delegated to a library) so both SDKs emit byte-identical
 * output regardless of which URI-charset generation a library froze at.
 */
public final class TemplateEngine {
  /** Matches a supported expression: optional {@code ?}/{@code &} operator + comma-separated names. */
  private static final Pattern SUPPORTED =
      Pattern.compile("\\{([?&]?)([A-Za-z0-9_.]+(?:,[A-Za-z0-9_.]+)*)\\}");

  /** Matches any braced expression so unsupported ones can be flagged with a precise message. */
  private static final Pattern ANY_BRACE = Pattern.compile("\\{([^}]*)\\}");

  private static final String OPERATORS = "+#./;?&";
  private static final Pattern VARNAME = Pattern.compile("[A-Za-z0-9_.]+");

  public String expand(String template, Map<String, String> variables) {
    validate(template);

    Matcher matcher = SUPPORTED.matcher(template);
    StringBuffer out = new StringBuffer();
    while (matcher.find()) {
      String operator = matcher.group(1);
      String expression = matcher.group(2);
      String replacement = switch (operator) {
        case "?" -> expandQuery("?", expression, variables);
        case "&" -> expandQuery("&", expression, variables);
        default -> expandSimple(expression, variables);
      };
      matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
    }
    matcher.appendTail(out);
    return out.toString();
  }

  /** Placeholder names declared by the template — the basis for missing-variable detection. */
  public List<String> variableNames(String template) {
    validate(template);

    Matcher matcher = SUPPORTED.matcher(template);
    Set<String> names = new LinkedHashSet<>();
    while (matcher.find()) {
      for (String name : matcher.group(2).split(",")) {
        names.add(name);
      }
    }
    return List.copyOf(names);
  }

  private String expandSimple(String expression, Map<String, String> variables) {
    StringJoiner joiner = new StringJoiner(",");
    for (String name : expression.split(",")) {
      joiner.add(encode(variables.getOrDefault(name, "")));
    }
    return joiner.toString();
  }

  private String expandQuery(String prefix, String expression, Map<String, String> variables) {
    StringJoiner joiner = new StringJoiner("&");
    for (String name : expression.split(",")) {
      String value = variables.get(name);
      if (value != null) {
        joiner.add(encode(name) + "=" + encode(value));
      }
    }

    String query = joiner.toString();
    return query.isEmpty() ? "" : prefix + query;
  }

  /**
   * Rejects unsupported RFC 6570 operators and modifiers so both SDKs accept and reject the same
   * template grammar. A braced expression that isn't a supported form throws here, before any
   * expansion can produce a URL that differs from the JavaScript SDK.
   */
  private void validate(String template) {
    Matcher matcher = ANY_BRACE.matcher(template);
    while (matcher.find()) {
      String expr = matcher.group(1);
      String operator = "";
      int bodyStart = 0;
      if (!expr.isEmpty() && OPERATORS.indexOf(expr.charAt(0)) >= 0) {
        operator = expr.substring(0, 1);
        bodyStart = 1;
      }
      if (!operator.isEmpty() && !operator.equals("?") && !operator.equals("&")) {
        throw new IllegalArgumentException(
            "Unsupported RFC 6570 operator '{" + operator + "}' in template: " + template
                + " — LinkSeal supports only {}, {?}, and {&}");
      }
      for (String spec : expr.substring(bodyStart).split(",")) {
        String name = spec.trim();
        if (name.isEmpty()) {
          throw new IllegalArgumentException("Empty variable spec in template: " + template);
        }
        if (name.indexOf('*') >= 0 || name.indexOf(':') >= 0) {
          throw new IllegalArgumentException(
              "Unsupported modifier in '" + name + "': explode (*) and prefix (:N) are not supported");
        }
        if (!VARNAME.matcher(name).matches()) {
          throw new IllegalArgumentException(
              "Invalid variable name '" + name + "' in template: " + template);
        }
      }
    }
  }

  private static final char[] HEX = "0123456789ABCDEF".toCharArray();

  /** RFC 3986 unreserved (A-Za-z0-9-._~) passes through; all other bytes are %XX UTF-8. */
  private String encode(String value) {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    StringBuilder out = new StringBuilder(bytes.length);
    for (byte b : bytes) {
      int u = b & 0xFF;
      if ((u >= 0x30 && u <= 0x39) // 0-9
          || (u >= 0x41 && u <= 0x5A) // A-Z
          || (u >= 0x61 && u <= 0x7A) // a-z
          || u == 0x2D // -
          || u == 0x2E // .
          || u == 0x5F // _
          || u == 0x7E // ~
      ) {
        out.append((char) u);
      } else {
        out.append('%').append(HEX[u >>> 4]).append(HEX[u & 0x0F]);
      }
    }
    return out.toString();
  }
}
