package io.github.xesam.linkseal.resolver;

import io.github.xesam.linkseal.model.MissingPolicy;
import io.github.xesam.linkseal.model.PolicyConfig;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PolicyProcessor {
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

  public Map<String, String> applyMissingPolicy(Map<String, String> variables, PolicyConfig config) {
    PolicyResult processed = process(variables, config);
    if (config.missing() == MissingPolicy.ERROR && !processed.missing().isEmpty()) {
      throw new IllegalArgumentException("Missing required variables: " + String.join(", ", processed.missing()));
    }
    return processed.result();
  }

  public record PolicyResult(Map<String, String> result, List<String> missing) {}
}
