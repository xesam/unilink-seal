package io.github.xesam.unilink.seal.resolver;

import io.github.xesam.unilink.seal.LinkSealErrorCode;
import io.github.xesam.unilink.seal.ResolutionException;
import io.github.xesam.unilink.seal.model.MissingPolicy;
import io.github.xesam.unilink.seal.model.PolicyConfig;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PolicyProcessor {
  private static final Pattern TEMPLATE_VAR_PATTERN = Pattern.compile("\\{([^}]+)\\}");

  public PolicyResult process(Map<String, String> variables, PolicyConfig config) {
    Map<String, String> defaults = config.defaults();
    Map<String, String> result = new LinkedHashMap<>();
    List<String> missing = new ArrayList<>();

    for (Map.Entry<String, String> entry : variables.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      if (value != null) {
        result.put(key, value);
      } else if (config.missing() == MissingPolicy.DEFAULT && defaults.containsKey(key)) {
        result.put(key, defaults.get(key));
      } else {
        missing.add(key);
      }
    }

    return new PolicyResult(result, missing);
  }

  public Map<String, String> applyMissingPolicy(
      String template, Map<String, String> variables, PolicyConfig config) {
    PolicyResult processed = process(variables, config);

    if (!processed.missing().isEmpty()) {
      if (config.missing() == MissingPolicy.ERROR) {
        throw new ResolutionException(
            LinkSealErrorCode.MISSING_VARIABLE,
            "Missing required variables: " + String.join(", ", processed.missing()));
      }

      if (config.missing() == MissingPolicy.IGNORE) {
        // Check if any missing variable is in a path segment
        Set<String> pathSegmentVars = extractPathSegmentVariables(template);
        List<String> missingInPath = new ArrayList<>();
        for (String missingVar : processed.missing()) {
          if (pathSegmentVars.contains(missingVar)) {
            missingInPath.add(missingVar);
          }
        }

        if (!missingInPath.isEmpty()) {
          throw new ResolutionException(
              LinkSealErrorCode.INVALID_TEMPLATE,
              "Policy \"ignore\" is unsafe for path-segment variables ["
                  + String.join(", ", missingInPath)
                  + "]. Use \"error\" or \"default\" policy for path variables.");
        }
      }
    }

    return processed.result();
  }

  /**
   * Extracts variable names that appear in path segments (not in query parts).
   * Path segment variables are those in {var} expressions before the '?' query separator
   * and not using query operators {?...} or {&...}.
   */
  private Set<String> extractPathSegmentVariables(String template) {
    Set<String> pathVars = new HashSet<>();

    // Split at '?' to get path part only
    String[] parts = template.split("\\?", 2);
    String pathPart = parts[0];

    Matcher matcher = TEMPLATE_VAR_PATTERN.matcher(pathPart);
    while (matcher.find()) {
      String expression = matcher.group(1);

      // Skip query operators
      if (expression.startsWith("?") || expression.startsWith("&")) {
        continue;
      }

      // Handle comma-separated variable lists (e.g., {x,y,z})
      String[] varNames = expression.split(",");
      for (String varName : varNames) {
        pathVars.add(varName.trim());
      }
    }

    return pathVars;
  }

  public record PolicyResult(Map<String, String> result, List<String> missing) {}
}
