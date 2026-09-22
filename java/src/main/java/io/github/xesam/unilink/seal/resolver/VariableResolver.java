package io.github.xesam.unilink.seal.resolver;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public final class VariableResolver {
  private final Map<String, String> variables = new LinkedHashMap<>();
  private Function<String, String> provider;

  public void setVariables(Map<String, String> values) {
    variables.putAll(values);
  }

  /** Clears statically registered variables so the provider takes over for those names again.
   *  Use when a previously registered value (e.g. a stale token) must stop shadowing the lazy
   *  provider. {@code setVariables} merges and never removes, so this is the only way to unset. */
  public void clearVariables() {
    variables.clear();
  }

  public void setResolver(Function<String, String> provider) {
    this.provider = provider;
  }

  /** Registered values win; the provider is only consulted for names they don't cover. */
  public String resolveOne(String name) {
    String value = variables.get(name);
    if (value != null) {
      return value;
    }
    return provider == null ? null : provider.apply(name);
  }

  /** Unresolved names stay as null so PolicyProcessor can detect them. */
  public Map<String, String> resolve(List<String> names) {
    Map<String, String> resolved = new LinkedHashMap<>();
    for (String name : names) {
      resolved.put(name, resolveOne(name));
    }
    return resolved;
  }
}
