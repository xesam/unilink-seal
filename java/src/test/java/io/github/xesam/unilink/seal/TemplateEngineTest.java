package io.github.xesam.unilink.seal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.xesam.unilink.seal.ResolutionException;

import io.github.xesam.unilink.seal.resolver.TemplateEngine;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class TemplateEngineTest {

  private final TemplateEngine engine = new TemplateEngine();

  @Test
  void expandsSimpleVariableSubstitution() {
    assertEquals(
        "https://example.com/users/user_123",
        engine.expand("https://example.com/users/{userId}", Map.of("userId", "user_123"))
    );
  }

  @Test
  void expandsMultipleSimpleSubstitutions() {
    assertEquals(
        "/myorg/myrepo/issues/42",
        engine.expand("/{org}/{repo}/issues/{id}", Map.of("org", "myorg", "repo", "myrepo", "id", "42"))
    );
  }

  @Test
  void expandsQueryStartOperator() {
    assertEquals(
        "https://api.example.com/users/user_123?token=sess_abc&locale=en-US",
        engine.expand(
            "https://api.example.com/users/{userId}{?token,locale}",
            Map.of("userId", "user_123", "token", "sess_abc", "locale", "en-US")
        )
    );
  }

  @Test
  void expandsQueryContinuationOperator() {
    assertEquals(
        "https://api.example.com/users/user_123?source=app&token=sess_abc&locale=en-US",
        engine.expand(
            "https://api.example.com/users/{userId}?source=app{&token,locale}",
            Map.of("userId", "user_123", "token", "sess_abc", "locale", "en-US")
        )
    );
  }

  @Test
  void skipsMissingVariablesInQueryExpansion() {
    assertEquals(
        "/search?q=test",
        engine.expand("/search{?q,page}", Map.of("q", "test"))
    );
  }

  @Test
  void returnsEmptyWhenAllQueryVariablesMissing() {
    assertEquals("/search", engine.expand("/search{?q,page}", Map.of()));
  }

  @Test
  void simpleVariableMissingUsesEmptyString() {
    assertEquals("/users/", engine.expand("/users/{id}", Map.of()));
  }

  @Test
  void encodesSpecialCharacters() {
    assertEquals(
        "/search?q=hello%20world",
        engine.expand("/search{?q}", Map.of("q", "hello world"))
    );
  }

  // Mirrored byte-for-byte by the JavaScript SDK; these expected strings are the parity pin.
  // RFC 3986 unreserved = A-Za-z0-9-._~ passes through; everything else is %XX UTF-8.
  @Test
  void encodesFormStyleValuesPerRfc3986Unreserved() {
    assertEquals("/x?q=~", engine.expand("/x{?q}", Map.of("q", "~")));
    assertEquals("/x?q=%28", engine.expand("/x{?q}", Map.of("q", "(")));
    assertEquals("/x?q=%29", engine.expand("/x{?q}", Map.of("q", ")")));
    assertEquals("/x?q=%27", engine.expand("/x{?q}", Map.of("q", "'")));
    assertEquals("/x?q=%2A", engine.expand("/x{?q}", Map.of("q", "*")));
    assertEquals("/x?q=%2F", engine.expand("/x{?q}", Map.of("q", "/")));
    assertEquals("/x?q=%3F", engine.expand("/x{?q}", Map.of("q", "?")));
    assertEquals("/x?q=%23", engine.expand("/x{?q}", Map.of("q", "#")));
    assertEquals("/x?q=%21", engine.expand("/x{?q}", Map.of("q", "!")));
    assertEquals("/x?q=%24", engine.expand("/x{?q}", Map.of("q", "$")));
    assertEquals("/x?q=%26", engine.expand("/x{?q}", Map.of("q", "&")));
    assertEquals("/x?q=%2C", engine.expand("/x{?q}", Map.of("q", ",")));
    assertEquals("/x?q=%3B", engine.expand("/x{?q}", Map.of("q", ";")));
    assertEquals("/x?q=%3D", engine.expand("/x{?q}", Map.of("q", "=")));
    assertEquals("/x?q=%20", engine.expand("/x{?q}", Map.of("q", " ")));
    assertEquals("/x?q=%E4%B8%AD", engine.expand("/x{?q}", Map.of("q", "中")));
    assertEquals("/x?q=-._~", engine.expand("/x{?q}", Map.of("q", "-._~")));
    assertEquals("/x?q=a%20b%2Fc%28d%29e%2Af%27g", engine.expand("/x{?q}", Map.of("q", "a b/c(d)e*f'g")));
  }

  @Test
  void simpleExpansionUsesSameRfc3986Encoder() {
    assertEquals("/p/a%2Ab", engine.expand("/p/{v}", Map.of("v", "a*b")));
    assertEquals("/p/a~b", engine.expand("/p/{v}", Map.of("v", "a~b")));
    assertEquals("/p/%E4%B8%AD", engine.expand("/p/{v}", Map.of("v", "中")));
  }

  @Test
  void encodesDefinedEmptyValueAsNameEquals() {
    assertEquals("/x?q=", new TemplateEngine().expand("/x{?q}", Map.of("q", "")));
  }

  @Test
  void variableNamesExtractsSimplePlaceholders() {
    assertEquals(List.of("org", "repo", "id"), engine.variableNames("/{org}/{repo}/issues/{id}"));
  }

  @Test
  void variableNamesExtractsAcrossQueryOperators() {
    assertEquals(
        List.of("userId", "token", "locale"),
        engine.variableNames("https://api.example.com/users/{userId}?source=app{&token,locale}")
    );
  }

  @Test
  void variableNamesExtractsFromQueryStartOperator() {
    assertEquals(List.of("q", "page"), engine.variableNames("/search{?q,page}"));
  }

  @Test
  void variableNamesReturnsEmptyForTemplateWithoutPlaceholders() {
    assertEquals(List.of(), engine.variableNames("https://example.com/static"));
  }

  @Test
  void variableNamesDeduplicatesRepeatedName() {
    assertEquals(List.of("id"), engine.variableNames("/{id}/detail/{id}"));
  }

  @Test
  void variableNamesYieldsExactlyWhatExpandConsumes() {
    String template = "https://api.example.com/users/{userId}?source=app{&token,locale}";
    Map<String, String> values = new LinkedHashMap<>();
    for (String name : engine.variableNames(template)) {
      values.put(name, "x");
    }

    assertEquals("https://api.example.com/users/x?source=app&token=x&locale=x", engine.expand(template, values));
  }

  @Test
  void expandsCommaJoinedSimpleSubstitution() {
    assertEquals("foo,bar", engine.expand("{a,b}", Map.of("a", "foo", "b", "bar")));
  }

  // --- rejects unsupported RFC 6570 features (mirrored in the JS SDK) ---

  @Test
  void rejectsReservedExpansionOperator() {
    assertThrows(ResolutionException.class, () -> engine.expand("{+path}", Map.of("path", "/x")));
  }

  @Test
  void rejectsFragmentExpansionOperator() {
    assertThrows(ResolutionException.class, () -> engine.expand("{#frag}", Map.of("frag", "x")));
  }

  @Test
  void rejectsLabelExpansionOperator() {
    assertThrows(ResolutionException.class, () -> engine.expand("{.x}", Map.of("x", "1")));
  }

  @Test
  void rejectsPathExpansionOperator() {
    assertThrows(ResolutionException.class, () -> engine.expand("{/x}", Map.of("x", "1")));
  }

  @Test
  void rejectsPathStyleParameterOperator() {
    assertThrows(ResolutionException.class, () -> engine.expand("{;x}", Map.of("x", "1")));
  }

  @Test
  void rejectsExplodeModifier() {
    assertThrows(ResolutionException.class, () -> engine.expand("{?list*}", Map.of("list", "x")));
  }

  @Test
  void rejectsPrefixModifier() {
    assertThrows(ResolutionException.class, () -> engine.expand("{?x:3}", Map.of("x", "abcdef")));
  }

  @Test
  void rejectsUnsupportedOperatorInVariableNames() {
    assertThrows(ResolutionException.class, () -> engine.variableNames("{+path}"));
  }

  // --- rejects whitespace in variable specs (mirrored in the JS SDK) ---

  @Test
  void rejectsSpacesAroundVariableName() {
    assertThrows(ResolutionException.class, () -> engine.expand("{ userId }", Map.of("userId", "x")));
  }

  @Test
  void rejectsSpaceAfterCommaInMultiVariableSpec() {
    assertThrows(ResolutionException.class, () -> engine.expand("{a, b}", Map.of("a", "1", "b", "2")));
  }

  @Test
  void rejectsSpacesInQueryExpression() {
    assertThrows(ResolutionException.class, () -> engine.expand("{?a, b}", Map.of("a", "1", "b", "2")));
  }

  @Test
  void rejectsSpacesInVariableNames() {
    assertThrows(ResolutionException.class, () -> engine.variableNames("{ userId }"));
  }

  // --- rejects unbalanced braces (mirrored in the JS SDK) ---

  @Test
  void rejectsUnclosedBrace() {
    assertThrows(ResolutionException.class, () -> engine.expand("https://x.com/{", Map.of("a", "1")));
  }

  @Test
  void rejectsUnmatchedClosingBrace() {
    assertThrows(ResolutionException.class, () -> engine.expand("https://x.com/}", Map.of("a", "1")));
  }

  @Test
  void rejectsNestedBraces() {
    assertThrows(ResolutionException.class, () -> engine.expand("https://x.com/{{a}}", Map.of("a", "1")));
  }

  @Test
  void rejectsUnbalancedBracesInVariableNames() {
    assertThrows(ResolutionException.class, () -> engine.variableNames("https://x.com/{"));
  }
}
