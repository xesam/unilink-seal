package io.github.xesam.unilink.seal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.xesam.unilink.seal.ResolutionException;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.xesam.unilink.seal.model.MissingPolicy;
import io.github.xesam.unilink.seal.model.PolicyConfig;
import io.github.xesam.unilink.seal.resolver.PolicyProcessor;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class PolicyProcessorTest {

  private final PolicyProcessor processor = new PolicyProcessor();

  private static Map<String, String> vars(String... keyValues) {
    Map<String, String> map = new LinkedHashMap<>();
    for (int i = 0; i < keyValues.length; i += 2) {
      map.put(keyValues[i], keyValues[i + 1]);
    }
    return map;
  }

  @Test
  void passesThroughResolvedVariables() {
    var result = processor.process(vars("token", "abc"), new PolicyConfig(MissingPolicy.ERROR));
    assertEquals(Map.of("token", "abc"), result.result());
    assertEquals(List.of(), result.missing());
  }

  /** Regression: missing was derived from resolved keys only, so it was always empty. */
  @Test
  void reportsNullVariablesAsMissing() {
    var result = processor.process(
        vars("userId", "user_123", "token", null),
        new PolicyConfig(MissingPolicy.ERROR)
    );
    assertEquals(List.of("token"), result.missing());
    assertEquals(Map.of("userId", "user_123"), result.result());
  }

  @Test
  void defaultModeFillsNullVariables() {
    var result = processor.process(
        vars("locale", null),
        new PolicyConfig(MissingPolicy.DEFAULT, Map.of("locale", "zh-CN"))
    );
    assertEquals(Map.of("locale", "zh-CN"), result.result());
    assertEquals(List.of(), result.missing());
  }

  @Test
  void defaultModeStillReportsMissingWithoutMatchingDefault() {
    var result = processor.process(
        vars("locale", null, "token", null),
        new PolicyConfig(MissingPolicy.DEFAULT, Map.of("locale", "zh-CN"))
    );
    assertEquals(Map.of("locale", "zh-CN"), result.result());
    assertEquals(List.of("token"), result.missing());
  }

  @Test
  void resolvedVariablesTakePrecedenceOverDefaults() {
    var result = processor.process(
        vars("locale", "en-US"),
        new PolicyConfig(MissingPolicy.DEFAULT, Map.of("locale", "zh-CN"))
    );
    assertEquals(Map.of("locale", "en-US"), result.result());
  }

  @Test
  void ignoreModeDoesNotApplyDefaults() {
    var result = processor.process(
        vars("locale", null),
        new PolicyConfig(MissingPolicy.IGNORE, Map.of("locale", "zh-CN"))
    );
    assertEquals(Map.of(), result.result());
    assertEquals(List.of("locale"), result.missing());
  }

  @Test
  void errorModeThrowsWhenMissing() {
    var error = assertThrows(
        ResolutionException.class,
        () -> processor.applyMissingPolicy(
            "https://example.com/path",
            vars("token", null),
            new PolicyConfig(MissingPolicy.ERROR))
    );
    assertTrue(error.getMessage().contains("token"));
  }

  @Test
  void errorModeSucceedsWhenAllPresent() {
    assertDoesNotThrow(() -> processor.applyMissingPolicy(
        "https://example.com/path",
        vars("token", "abc", "locale", "en"),
        new PolicyConfig(MissingPolicy.ERROR)
    ));
  }

  @Test
  void ignoreModeOmitsMissingWithoutThrowing() {
    Map<String, String> result = processor.applyMissingPolicy(
        "https://example.com{?userId,token}",
        vars("userId", "user_123", "token", null),
        new PolicyConfig(MissingPolicy.IGNORE)
    );
    assertEquals(Map.of("userId", "user_123"), result);
  }

  @Test
  void defaultModeUsesProvidedDefaults() {
    Map<String, String> result = processor.applyMissingPolicy(
        "https://example.com/path",
        vars("theme", "light", "lang", null),
        new PolicyConfig(MissingPolicy.DEFAULT, Map.of("theme", "dark", "lang", "en"))
    );
    assertEquals(Map.of("theme", "light", "lang", "en"), result);
  }

  @Test
  void emptyVariableSetIsNotAnError() {
    Map<String, String> result = processor.applyMissingPolicy(
        "https://example.com/path",
        Map.of(),
        new PolicyConfig(MissingPolicy.ERROR));
    assertEquals(Map.of(), result);
  }

  /** Regression: policy.missing = "ignore" + path-segment variable missing → malformed URL */
  @Test
  void rejectsIgnorePolicyForMissingPathSegmentVariables() {
    var error = assertThrows(
        ResolutionException.class,
        () -> processor.applyMissingPolicy(
            "https://api.example.com/users/{userId}/profile",
            vars("userId", null),
            new PolicyConfig(MissingPolicy.IGNORE))
    );
    assertTrue(error.getMessage().contains("unsafe for path-segment"));
    assertTrue(error.getMessage().contains("userId"));
    assertEquals(LinkSealErrorCode.INVALID_TEMPLATE, error.code());
  }

  @Test
  void allowsIgnorePolicyForMissingQueryVariables() {
    Map<String, String> result = processor.applyMissingPolicy(
        "https://api.example.com/profile{?userId,tab}",
        vars("userId", null, "tab", null),
        new PolicyConfig(MissingPolicy.IGNORE)
    );
    assertEquals(Map.of(), result);
  }

  @Test
  void allowsIgnorePolicyWhenPathVariablesAreProvided() {
    Map<String, String> result = processor.applyMissingPolicy(
        "https://api.example.com/users/{userId}/profile{?tab}",
        vars("userId", "USER123", "tab", null),
        new PolicyConfig(MissingPolicy.IGNORE)
    );
    assertEquals(Map.of("userId", "USER123"), result);
  }

  @Test
  void detectsMultipleMissingPathSegmentVariables() {
    var error = assertThrows(
        ResolutionException.class,
        () -> processor.applyMissingPolicy(
            "https://api.example.com/users/{userId}/posts/{postId}",
            vars("userId", null, "postId", null),
            new PolicyConfig(MissingPolicy.IGNORE))
    );
    assertTrue(error.getMessage().contains("userId"));
    assertTrue(error.getMessage().contains("postId"));
  }
}
