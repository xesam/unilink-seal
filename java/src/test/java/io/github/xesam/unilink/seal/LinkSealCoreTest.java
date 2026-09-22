package io.github.xesam.unilink.seal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.xesam.unilink.seal.model.LinkSealProtocol;
import io.github.xesam.unilink.seal.model.MissingPolicy;
import io.github.xesam.unilink.seal.model.PolicyConfig;
import io.github.xesam.unilink.seal.model.SignedProtocol;
import io.github.xesam.unilink.seal.LinkSealErrorCode;
import io.github.xesam.unilink.seal.TrustException;
import io.github.xesam.unilink.seal.resolver.LinkSealCore;
import io.github.xesam.unilink.seal.signer.ProtocolSigner;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class LinkSealCoreTest {
  private static final String EXPECTED_URL =
      "https://api.example.com/users/user_123?source=app&token=sess_abc&locale=en-US";

  private static final JsonSerializer SERIALIZER = new ReferenceJsonSerializer();

  private static LinkSealCore core() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(Map.of("userId", "user_123", "token", "sess_abc", "locale", "en-US"));
    return core;
  }

  private static SignedProtocol signed() throws Exception {
    return new SignedProtocol(SpecFixture.payload(), SpecFixture.signature());
  }

  /** Sign a custom payload with the test private key so its signature verifies, isolating
   *  expiry/kid/host checks from signature failures. */
  private static SignedProtocol signCustom(String template, String expiresAt, String kid)
      throws Exception {
    ProtocolSigner signer = new ProtocolSigner(SERIALIZER);
    signer.setPrivateKey(SpecFixture.privateKey());
    LinkSealProtocol payload = new LinkSealProtocol(
        "1.0", template, new PolicyConfig(MissingPolicy.ERROR), expiresAt, kid);
    return signer.signProtocol(payload);
  }

  /** Sign a custom payload with the test private key so its signature verifies, isolating the
   *  trust check from signature failures — only a validly-signed URL reaches assertTrustedUrl. */
  private static SignedProtocol signCustom(String template) throws Exception {
    return signCustom(template, null, null);
  }

  private static Map<String, String> vars(String... keyValues) {
    Map<String, String> map = new LinkedHashMap<>();
    for (int i = 0; i < keyValues.length; i += 2) {
      map.put(keyValues[i], keyValues[i + 1]);
    }
    return map;
  }

  @Test
  void constructorRequiresAllowedHosts() {
    assertThrows(IllegalStateException.class, () -> new LinkSealCore(null));
    assertThrows(IllegalStateException.class, () -> new LinkSealCore(List.of()));
  }

  /** Null is not an enforcement switch: both allowlist setters reject it, and an empty
   *  scheme allowlist is a configuration error rather than a silent reject-everything. */
  @Test
  void allowlistSettersRejectNullAndEmptySchemes() {
    LinkSealCore core = new LinkSealCore(List.of("api.example.com"));
    assertThrows(
        IllegalArgumentException.class,
        () -> core.setAllowedHosts(null));
    assertThrows(
        IllegalArgumentException.class,
        () -> core.setAllowedSchemes(null));
    assertThrows(
        IllegalArgumentException.class,
        () -> core.setAllowedSchemes(List.of()));
  }

  /** Cross-language pin: an opaque URL (no {@code //} authority) has no host —
   *  {@code URI.getHost()} returns null — so it is rejected under a configured allowlist,
   *  and neither SDK mistakes the path for a hostname. */
  @Test
  void treatsAuthorityLessUrlAsHostlessMirroringJavascript() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("api.example.com"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(vars("userId", "user_123"));

    var error = assertThrows(
        TrustException.class,
        () -> core.generateUrl(signCustom("https:evil.com/users/{userId}")));
    assertTrue(error.getMessage().contains("Untrusted URL host"));
  }

  /** Regression: the constructor parameter must actually be enforced, not just validated. */
  @Test
  void constructorSuppliedHostsAreEnforced() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("api.example.com"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(vars("userId", "user_123"));

    assertThrows(
        TrustException.class,
        () -> core.generateUrl(signCustom("https://evil.com/users/{userId}")));
    assertEquals(
        "https://api.example.com/users/user_123",
        core.generateUrl(signCustom("https://api.example.com/users/{userId}")));
  }

  @Test
  void constructorWildcardExplicitlyDisablesHostEnforcement() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(vars("userId", "user_123"));

    assertEquals(
        "https://evil.com/users/user_123",
        core.generateUrl(signCustom("https://evil.com/users/{userId}"))
    );
  }

  @Test
  void generatesUrlFromSpecSignedProtocol() throws Exception {
    assertEquals(EXPECTED_URL, core().generateUrl(signed()));
  }

  @Test
  void resolvesPlaceholdersThroughLazyProvider() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(Map.of("userId", "user_123"));
    core.setResolver(name -> switch (name) {
      case "token" -> "sess_abc";
      case "locale" -> "en-US";
      default -> null;
    });

    assertEquals(EXPECTED_URL, core.generateUrl(signed()));
  }

  @Test
  void prefersRegisteredVariablesOverProvider() throws Exception {
    List<String> calls = new ArrayList<>();
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(Map.of("userId", "user_123", "token", "sess_abc", "locale", "en-US"));
    core.setResolver(name -> {
      calls.add(name);
      return "FROM_PROVIDER";
    });

    assertEquals(EXPECTED_URL, core.generateUrl(signed()));
    assertTrue(calls.isEmpty());
  }

  @Test
  void clearVariablesReleasesStaticValuesSoProviderTakesOver() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(Map.of("userId", "user_123", "token", "STATIC", "locale", "en-US"));

    // Static token shadows any provider.
    assertEquals(
        "https://api.example.com/users/user_123?source=app&token=STATIC&locale=en-US",
        core.generateUrl(signed()));

    // After clearing, the provider supplies token; re-register only userId.
    core.clearVariables();
    core.setVariables(Map.of("userId", "user_123"));
    core.setResolver(name -> switch (name) {
      case "token" -> "FRESH";
      case "locale" -> "en-US";
      default -> null;
    });

    assertEquals(
        "https://api.example.com/users/user_123?source=app&token=FRESH&locale=en-US",
        core.generateUrl(signed()));
  }

  @Test
  void throwsOnMalformedSignature() throws Exception {
    LinkSealCore core = core();
    SignedProtocol bad = new SignedProtocol(SpecFixture.payload(), "AAAA");
    assertThrows(VerificationException.class, () -> core.generateUrl(bad));
  }

  @Test
  void throwsOnTamperedSignature() throws Exception {
    LinkSealCore core = core();
    SignedProtocol bad =
        new SignedProtocol(SpecFixture.payload(), SpecFixture.signature().replace('B', 'C'));
    assertThrows(VerificationException.class, () -> core.generateUrl(bad));
  }

  @Test
  void throwsWhenTemplateIsRedirected() throws Exception {
    LinkSealCore core = core();
    LinkSealProtocol original = SpecFixture.payload();
    SignedProtocol tampered = new SignedProtocol(
        new LinkSealProtocol(original.version(), "https://evil.com/{userId}", original.policy()),
        SpecFixture.signature()
    );

    assertThrows(VerificationException.class, () -> core.generateUrl(tampered));
  }

  @Test
  void throwsWhenPolicyIsDowngraded() throws Exception {
    LinkSealCore core = core();
    LinkSealProtocol original = SpecFixture.payload();
    SignedProtocol tampered = new SignedProtocol(
        new LinkSealProtocol(
            original.version(),
            original.template(),
            new PolicyConfig(MissingPolicy.IGNORE)
        ),
        SpecFixture.signature()
    );

    assertThrows(VerificationException.class, () -> core.generateUrl(tampered));
  }

  /** Regression: missing detection never fired, so this silently produced a partial URL. */
  @Test
  void throwsWhenRequiredVariableCannotBeResolved() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(Map.of("userId", "user_123", "locale", "en-US"));

    SignedProtocol signed = signed();
    var error = assertThrows(ResolutionException.class, () -> core.generateUrl(signed));
    assertTrue(error.getMessage().contains("token"));
    assertEquals(LinkSealErrorCode.MISSING_VARIABLE, error.code());
  }

  @Test
  void throwsWhenProviderDeclinesRequiredVariable() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(Map.of("userId", "user_123", "locale", "en-US"));
    core.setResolver(name -> null);

    SignedProtocol signed = signed();
    var error = assertThrows(ResolutionException.class, () -> core.generateUrl(signed));
    assertTrue(error.getMessage().contains("token"));
  }

  @Test
  void doesNotFallBackToBuiltInPlaceholderValues() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);

    SignedProtocol signed = signed();
    var error = assertThrows(ResolutionException.class, () -> core.generateUrl(signed));
    assertTrue(error.getMessage().contains("Missing required variables"));
    assertEquals(LinkSealErrorCode.MISSING_VARIABLE, error.code());
  }

  // URL trust enforcement — see LinkSealCore.assertTrustedUrl.

  @Test
  void rejectsHttpTemplateByDefault() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(vars("userId", "user_123"));

    var error = assertThrows(
        TrustException.class,
        () -> core.generateUrl(signCustom("http://api.example.com/users/{userId}"))
    );
    assertTrue(error.getMessage().contains("Untrusted URL scheme 'http'"));
  }

  @Test
  void acceptsHttpWhenSchemeAllowlistIncludesIt() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setAllowedSchemes(List.of("http", "https"));
    core.setVariables(vars("userId", "user_123"));

    assertEquals(
        "http://api.example.com/users/user_123",
        core.generateUrl(signCustom("http://api.example.com/users/{userId}"))
    );
  }

  @Test
  void disablesSchemeEnforcementViaExplicitWildcard() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setAllowedSchemes(List.of("*"));
    core.setVariables(vars("userId", "user_123"));

    assertEquals(
        "javascript://alert(1)/user_123",
        core.generateUrl(signCustom("javascript://alert(1)/{userId}"))
    );
  }

  @Test
  void rejectsSyntacticallyMalformedScheme() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setAllowedSchemes(List.of("*"));
    core.setVariables(vars("userId", "user_123"));

    var error = assertThrows(
        TrustException.class,
        () -> core.generateUrl(signCustom("1abc://api.example.com/users/{userId}"))
    );
    assertTrue(error.getMessage().toLowerCase().contains("scheme"));
  }

  @Test
  void acceptsCustomSchemeContainingPlus() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setAllowedSchemes(List.of("web+action"));
    core.setVariables(vars("userId", "user_123"));

    assertEquals(
        "web+action://open/users/user_123",
        core.generateUrl(signCustom("web+action://open/users/{userId}"))
    );
  }

  @Test
  void rejectsHostOutsideAllowlistEvenWithValidSignature() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setAllowedHosts(List.of("api.example.com"));
    core.setVariables(vars("userId", "user_123"));

    var error = assertThrows(
        TrustException.class,
        () -> core.generateUrl(signCustom("https://evil.com/users/{userId}"))
    );
    assertTrue(error.getMessage().contains("Untrusted URL host 'evil.com'"));
  }

  @Test
  void acceptsHostInsideAllowlist() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setAllowedHosts(List.of("evil.com"));
    core.setVariables(vars("userId", "user_123"));

    assertEquals(
        "https://evil.com/users/user_123",
        core.generateUrl(signCustom("https://evil.com/users/{userId}"))
    );
  }

  /** Proves the host check runs on the expanded URL: a variable can fill the host position. */
  @Test
  void rejectsUntrustedHostSuppliedViaVariable() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setAllowedHosts(List.of("api.example.com"));
    core.setVariables(vars("host", "evil.com", "userId", "user_123"));

    var error = assertThrows(
        TrustException.class,
        () -> core.generateUrl(signCustom("https://{host}/users/{userId}"))
    );
    assertTrue(error.getMessage().contains("Untrusted URL host 'evil.com'"));
  }

  @Test
  void acceptsSpecUrlWithHostAllowlistConfigured() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setAllowedHosts(List.of("api.example.com"));
    core.setVariables(vars("userId", "user_123", "token", "sess_abc", "locale", "en-US"));

    assertEquals(EXPECTED_URL, core.generateUrl(signed()));
  }

  // --- expiry (expiresAt) ---

  @Test
  void throwsWhenProtocolIsExpired() throws Exception {
    LinkSealCore core = core();
    SignedProtocol expired =
        signCustom("https://api.example.com/users/{userId}", "2000-01-01T00:00:00Z", null);
    core.setVariables(vars("userId", "user_123"));

    var error = assertThrows(VerificationException.class, () -> core.generateUrl(expired));
    assertEquals(LinkSealErrorCode.PROTOCOL_EXPIRED, error.code());
    assertTrue(error.getMessage().contains("Protocol expired"));
  }

  @Test
  void acceptsFutureExpiry() throws Exception {
    LinkSealCore core = core();
    SignedProtocol future =
        signCustom("https://api.example.com/users/{userId}", "2099-12-31T23:59:59Z", null);
    core.setVariables(vars("userId", "user_123"));

    assertEquals("https://api.example.com/users/user_123", core.generateUrl(future));
  }

  @Test
  void throwsOnMalformedExpiresAt() throws Exception {
    LinkSealCore core = core();
    SignedProtocol malformed =
        signCustom("https://api.example.com/users/{userId}", "not-a-date", null);
    core.setVariables(vars("userId", "user_123"));

    var error = assertThrows(VerificationException.class, () -> core.generateUrl(malformed));
    assertEquals(LinkSealErrorCode.MALFORMED_EXPIRES_AT, error.code());
    assertTrue(error.getMessage().contains("Malformed expiresAt"));
  }

  // Cross-language pin: a bare date (no time/offset) is rejected on both ends — matches the JS
  // SDK, which is strict about this so JS's lenient Date.parse can't accept what Java's
  // Instant.parse rejects.
  @Test
  void rejectsBareDateExpiresAt() throws Exception {
    LinkSealCore core = core();
    SignedProtocol bareDate =
        signCustom("https://api.example.com/users/{userId}", "2026-08-07", null);
    core.setVariables(vars("userId", "user_123"));

    var error = assertThrows(VerificationException.class, () -> core.generateUrl(bareDate));
    assertEquals(LinkSealErrorCode.MALFORMED_EXPIRES_AT, error.code());
    assertTrue(error.getMessage().contains("Malformed expiresAt"));
  }

  // --- key rotation (kid) ---

  @Test
  void verifiesWithKidKey() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.expiringPayload().kid(), SpecFixture.publicKey());
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(vars("userId", "user_123", "token", "sess_abc", "locale", "en-US"));

    assertEquals(EXPECTED_URL, core.generateUrl(
        new SignedProtocol(SpecFixture.expiringPayload(), SpecFixture.expiringSignature())));
  }

  @Test
  void throwsWhenKidNotRegistered() throws Exception {
    LinkSealCore core = new LinkSealCore(List.of("*"));
    core.setPublicKey(SpecFixture.publicKey()); // default key only, no kid registered
    core.setJsonSerializer(SERIALIZER);
    core.setVariables(vars("userId", "user_123", "token", "sess_abc", "locale", "en-US"));

    var error = assertThrows(IllegalStateException.class, () -> core.generateUrl(
        new SignedProtocol(SpecFixture.expiringPayload(), SpecFixture.expiringSignature())));
    assertTrue(error.getMessage().contains("test-key-1"));
  }
}
