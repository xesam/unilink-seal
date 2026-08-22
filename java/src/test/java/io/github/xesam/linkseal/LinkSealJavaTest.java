package io.github.xesam.linkseal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.xesam.linkseal.model.LinkSealProtocol;
import io.github.xesam.linkseal.model.MissingPolicy;
import io.github.xesam.linkseal.model.PolicyConfig;
import io.github.xesam.linkseal.model.SignedProtocol;
import io.github.xesam.linkseal.resolver.LinkSealCore;
import io.github.xesam.linkseal.resolver.SignatureVerifier;
import io.github.xesam.linkseal.resolver.TemplateEngine;
import io.github.xesam.linkseal.signer.ProtocolSigner;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class LinkSealJavaTest {

  private static final JsonSerializer SERIALIZER = new DefaultJsonSerializer();

  private static SignatureVerifier verifier() throws Exception {
    SignatureVerifier verifier = new SignatureVerifier();
    verifier.setPublicKey(SpecFixture.publicKey());
    verifier.setJsonSerializer(SERIALIZER);
    return verifier;
  }

  @Test
  void verifiesSpecSignedProtocolAndGeneratesUrl() throws Exception {
    LinkSealCore linkSeal = new LinkSealCore();
    linkSeal.setPublicKey(SpecFixture.publicKey());
    linkSeal.setJsonSerializer(SERIALIZER);
    linkSeal.setVariables(Map.of("userId", "user_123", "token", "sess_abc", "locale", "en-US"));

    String url = linkSeal.generateUrl(new SignedProtocol(SpecFixture.payload(), SpecFixture.signature()));

    assertEquals("https://api.example.com/users/user_123?source=app&token=sess_abc&locale=en-US", url);
  }

  /** The spec signature is produced by the JavaScript signer, so this pins cross-SDK agreement. */
  @Test
  void verifiesSignatureProducedByJavascriptSigner() throws Exception {
    assertTrue(verifier().verify(SpecFixture.payload(), SpecFixture.signature()));
  }

  @Test
  void reproducesTheJavascriptSignatureByteForByte() throws Exception {
    ProtocolSigner signer = new ProtocolSigner();
    signer.setPrivateKey(SpecFixture.privateKey());
    signer.setJsonSerializer(SERIALIZER);

    assertEquals(SpecFixture.signature(), signer.signPayload(SpecFixture.payload()));
  }

  @Test
  void signsAndVerifiesProtocol() throws Exception {
    ProtocolSigner signer = new ProtocolSigner();
    signer.setPrivateKey(SpecFixture.privateKey());
    signer.setJsonSerializer(SERIALIZER);
    SignedProtocol signed = signer.signProtocol(SpecFixture.payload());

    assertTrue(verifier().verify(signed.payload(), signed.signature()));
  }

  @Test
  void rejectsInvalidSignature() throws Exception {
    byte[] signature = Base64.getDecoder().decode(SpecFixture.signature());
    signature[0] ^= 0x01;

    assertFalse(verifier().verify(SpecFixture.payload(), Base64.getEncoder().encodeToString(signature)));
  }

  @Test
  void rejectsTamperedTemplate() throws Exception {
    LinkSealProtocol original = SpecFixture.payload();
    LinkSealProtocol tampered =
        new LinkSealProtocol(original.version(), "https://evil.com/{userId}", original.policy());

    assertFalse(verifier().verify(tampered, SpecFixture.signature()));
  }

  /** Regression: canonicalization once emitted policy as {}, so tampering went undetected. */
  @Test
  void rejectsTamperedPolicy() throws Exception {
    LinkSealProtocol original = SpecFixture.payload();
    LinkSealProtocol tampered = new LinkSealProtocol(
        original.version(),
        original.template(),
        new PolicyConfig(MissingPolicy.IGNORE)
    );

    assertFalse(verifier().verify(tampered, SpecFixture.signature()));
  }

  @Test
  void rejectsInjectedPolicyDefaults() throws Exception {
    LinkSealProtocol original = SpecFixture.payload();
    LinkSealProtocol tampered = new LinkSealProtocol(
        original.version(),
        original.template(),
        new PolicyConfig(MissingPolicy.ERROR, Map.of("token", "attacker"))
    );

    assertFalse(verifier().verify(tampered, SpecFixture.signature()));
  }

  @Test
  void expandsQueryStartAndContinuation() {
    TemplateEngine engine = new TemplateEngine();

    assertEquals(
        "https://api.example.com/users/user_123?token=sess_abc&locale=en-US",
        engine.expand(
            "https://api.example.com/users/{userId}{?token,locale}",
            Map.of("userId", "user_123", "token", "sess_abc", "locale", "en-US")
        )
    );
    assertEquals(
        "https://api.example.com/users/user_123?source=app&token=sess_abc&locale=en-US",
        engine.expand(
            "https://api.example.com/users/{userId}?source=app{&token,locale}",
            Map.of("userId", "user_123", "token", "sess_abc", "locale", "en-US")
        )
    );
  }

  @Test
  void requiresKeysBeforeSigningOrVerifying() throws Exception {
    LinkSealProtocol payload = SpecFixture.payload();
    assertThrows(IllegalStateException.class, () -> new ProtocolSigner().signPayload(payload));
    assertThrows(
        IllegalStateException.class,
        () -> new SignatureVerifier().verify(payload, SpecFixture.signature())
    );

    ProtocolSigner signerWithKey = new ProtocolSigner();
    signerWithKey.setPrivateKey(SpecFixture.privateKey());
    assertThrows(IllegalStateException.class, () -> signerWithKey.signPayload(payload));

    SignatureVerifier verifierWithKey = new SignatureVerifier();
    verifierWithKey.setPublicKey(SpecFixture.publicKey());
    assertThrows(
        IllegalStateException.class,
        () -> verifierWithKey.verify(payload, SpecFixture.signature())
    );
  }

  @Test
  void canonicalizationMatchesSpecForm() throws Exception {
    assertEquals(
        "{\"policy\":{\"missing\":\"error\"},"
            + "\"template\":\"https://api.example.com/users/{userId}?source=app{&token,locale}\","
            + "\"version\":\"1.0\"}",
        Canonicalizer.canonicalize(SpecFixture.payload(), SERIALIZER)
    );
  }

  @Test
  void canonicalizationDistinguishesTemplateDifferences() throws Exception {
    LinkSealProtocol original = SpecFixture.payload();

    assertNotEquals(
        Canonicalizer.canonicalize(original, SERIALIZER),
        Canonicalizer.canonicalize(
            new LinkSealProtocol(original.version(), "https://evil.com/{userId}", original.policy()),
            SERIALIZER
        )
    );
  }

  @Test
  void canonicalizationIncludesPolicyDefaults() throws Exception {
    LinkSealProtocol withDefaults = new LinkSealProtocol(
        "1.0",
        "https://x.com/{a}",
        new PolicyConfig(MissingPolicy.DEFAULT, Map.of("a", "fallback"))
    );

    assertEquals(
        "{\"policy\":{\"defaults\":{\"a\":\"fallback\"},\"missing\":\"default\"},"
            + "\"template\":\"https://x.com/{a}\",\"version\":\"1.0\"}",
        Canonicalizer.canonicalize(withDefaults, SERIALIZER)
    );
  }

  /** Pins cross-SDK byte agreement for the expiresAt + kid fields: the expiring-rotated example
   *  was signed by the JavaScript signer; the Java verifier must accept it. */
  @Test
  void verifiesExpiringRotatedSignatureFromJavascriptSigner() throws Exception {
    SignatureVerifier v = new SignatureVerifier();
    v.setPublicKey(SpecFixture.expiringPayload().kid(), SpecFixture.publicKey());
    v.setJsonSerializer(SERIALIZER);
    assertTrue(v.verify(SpecFixture.expiringPayload(), SpecFixture.expiringSignature()));
  }

  @Test
  void reproducesExpiringRotatedSignatureByteForByte() throws Exception {
    ProtocolSigner signer = new ProtocolSigner();
    signer.setPrivateKey(SpecFixture.privateKey());
    signer.setJsonSerializer(SERIALIZER);
    assertEquals(SpecFixture.expiringSignature(), signer.signPayload(SpecFixture.expiringPayload()));
  }

  @Test
  void canonicalizationIncludesExpiresAtAndKid() throws Exception {
    assertEquals(
        "{\"expiresAt\":\"2099-12-31T23:59:59Z\",\"kid\":\"test-key-1\","
            + "\"policy\":{\"missing\":\"error\"},"
            + "\"template\":\"https://api.example.com/users/{userId}?source=app{&token,locale}\","
            + "\"version\":\"1.0\"}",
        Canonicalizer.canonicalize(SpecFixture.expiringPayload(), SERIALIZER)
    );
  }
}
