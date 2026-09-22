package io.github.xesam.unilink.seal.model;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class PolicyConfig {
  private final MissingPolicy missing;
  private final Map<String, String> defaults;

  public PolicyConfig(MissingPolicy missing) {
    this(missing, Map.of());
  }

  public PolicyConfig(MissingPolicy missing, Map<String, String> defaults) {
    this.missing = Objects.requireNonNull(missing, "missing");
    this.defaults = new LinkedHashMap<>(Objects.requireNonNull(defaults, "defaults"));
  }

  public MissingPolicy missing() {
    return missing;
  }

  public Map<String, String> defaults() {
    return Map.copyOf(defaults);
  }
}
