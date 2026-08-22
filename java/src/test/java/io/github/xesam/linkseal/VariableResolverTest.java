package io.github.xesam.linkseal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.xesam.linkseal.resolver.VariableResolver;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class VariableResolverTest {

  @Test
  void hasNoValuesBeforeAnyAreRegistered() {
    assertNull(new VariableResolver().resolveOne("userId"));
  }

  @Test
  void resolvesRegisteredValuesByPlaceholderName() {
    VariableResolver resolver = new VariableResolver();
    resolver.setVariables(Map.of("userId", "user_123", "token", "sess_abc"));
    assertEquals("user_123", resolver.resolveOne("userId"));
    assertEquals("sess_abc", resolver.resolveOne("token"));
  }

  @Test
  void returnsNullForUnregisteredName() {
    VariableResolver resolver = new VariableResolver();
    resolver.setVariables(Map.of("userId", "user_123"));
    assertNull(resolver.resolveOne("token"));
  }

  @Test
  void setVariablesMergesInsteadOfReplacing() {
    VariableResolver resolver = new VariableResolver();
    resolver.setVariables(Map.of("userId", "user_123"));
    resolver.setVariables(Map.of("token", "sess_abc"));
    assertEquals("user_123", resolver.resolveOne("userId"));
    assertEquals("sess_abc", resolver.resolveOne("token"));
  }

  @Test
  void setVariablesOverridesExistingValue() {
    VariableResolver resolver = new VariableResolver();
    resolver.setVariables(Map.of("userId", "first"));
    resolver.setVariables(Map.of("userId", "second"));
    assertEquals("second", resolver.resolveOne("userId"));
  }

  @Test
  void fallsBackToProviderWhenNameIsNotRegistered() {
    VariableResolver resolver = new VariableResolver();
    resolver.setResolver(name -> "token".equals(name) ? "fresh_token" : null);
    assertEquals("fresh_token", resolver.resolveOne("token"));
  }

  /** Registered values win, and the provider must not even be consulted for them. */
  @Test
  void prefersRegisteredValuesOverProvider() {
    List<String> calls = new ArrayList<>();
    VariableResolver resolver = new VariableResolver();
    resolver.setVariables(Map.of("userId", "user_123"));
    resolver.setResolver(name -> {
      calls.add(name);
      return "FROM_PROVIDER";
    });

    assertEquals("user_123", resolver.resolveOne("userId"));
    assertTrue(calls.isEmpty());
  }

  @Test
  void consultsProviderOnlyForNamesTheMapMisses() {
    List<String> calls = new ArrayList<>();
    VariableResolver resolver = new VariableResolver();
    resolver.setVariables(Map.of("userId", "user_123"));
    resolver.setResolver(name -> {
      calls.add(name);
      return "token".equals(name) ? "fresh" : null;
    });

    resolver.resolve(List.of("userId", "token"));

    assertEquals(List.of("token"), calls);
  }

  @Test
  void treatsProviderReturningNullAsMissing() {
    VariableResolver resolver = new VariableResolver();
    resolver.setResolver(name -> null);
    assertNull(resolver.resolveOne("token"));
  }

  @Test
  void setResolverNullClearsProvider() {
    VariableResolver resolver = new VariableResolver();
    resolver.setResolver(name -> "value");
    resolver.setResolver(null);
    assertNull(resolver.resolveOne("token"));
  }

  /** Unresolved names must survive as null, or PolicyProcessor cannot see them. */
  @Test
  void resolveKeepsUnresolvedNamesAsNull() {
    VariableResolver resolver = new VariableResolver();
    resolver.setVariables(Map.of("userId", "user_123"));

    Map<String, String> expected = new LinkedHashMap<>();
    expected.put("userId", "user_123");
    expected.put("token", null);
    expected.put("locale", null);

    assertEquals(expected, resolver.resolve(List.of("userId", "token", "locale")));
  }

  @Test
  void resolveReturnsEntryForEveryRequestedName() {
    Map<String, String> result = new VariableResolver().resolve(List.of("a", "b"));
    assertEquals(List.of("a", "b"), new ArrayList<>(result.keySet()));
  }

  @Test
  void resolveOnEmptyNameListReturnsEmptyMap() {
    assertEquals(Map.of(), new VariableResolver().resolve(List.of()));
  }
}
