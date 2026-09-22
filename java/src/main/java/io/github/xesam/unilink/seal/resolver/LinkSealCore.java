package io.github.xesam.unilink.seal.resolver;

import io.github.xesam.unilink.seal.JsonSerializer;
import io.github.xesam.unilink.seal.LinkSealErrorCode;
import io.github.xesam.unilink.seal.TrustException;
import io.github.xesam.unilink.seal.VerificationException;
import io.github.xesam.unilink.seal.model.SignedProtocol;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

public final class LinkSealCore {
  private final TemplateEngine templateEngine;
  private final VariableResolver variableResolver;
  private final PolicyProcessor policyProcessor;
  private final SignatureVerifier signatureVerifier;

  /**
   * Schemes the resolver will emit by default. Restricted to {@code https} so a signed template
   * cannot produce a {@code javascript:}/{@code http:}/{@code intent:} URL — the signature only
   * proves the template is un-tampered, not that its scheme is safe to load. Override with
   * {@link #setAllowedSchemes(Collection)}, or pass the explicit wildcard {@code List.of("*")}
   * to disable scheme enforcement (tests only).
   */
  private Set<String> allowedSchemes = Set.of("https");

  /**
   * Hosts the resolver is allowed to emit, matched by hostname (without port). A signature only
   * proves the template bytes are un-tampered, not that its host is trusted for this resolver,
   * so the trusted-host boundary must be an explicit constructor decision. {@code "*"} is the
   * explicit wildcard; {@link #setAllowedHosts(Collection)} can change it later.
   */
  private Set<String> allowedHosts = null;

  /**
   * @param allowedHosts hosts this resolver may emit (lower-cased, hostname without port);
   *      a single {@code "*"} entry explicitly disables host enforcement
   * @throws IllegalStateException if {@code allowedHosts} is null or empty
   */
  public LinkSealCore(Collection<String> allowedHosts) {
    if (allowedHosts == null || allowedHosts.isEmpty()) {
      throw new IllegalStateException(
          "LinkSealCore requires allowedHosts: pass the hosts this resolver may emit "
              + "(e.g. List.of(\"api.example.com\")), or List.of(\"*\") to explicitly disable "
              + "host enforcement");
    }
    this.templateEngine = new TemplateEngine();
    this.variableResolver = new VariableResolver();
    this.policyProcessor = new PolicyProcessor();
    this.signatureVerifier = new SignatureVerifier();
    setAllowedHosts(allowedHosts);
  }

  public void setPublicKey(String keyPem) {
    signatureVerifier.setPublicKey(keyPem);
  }

  /** Register a public key under a {@code kid} for key rotation. */
  public void setPublicKey(String kid, String keyPem) {
    signatureVerifier.setPublicKey(kid, keyPem);
  }

  public void setJsonSerializer(JsonSerializer jsonSerializer) {
    signatureVerifier.setJsonSerializer(jsonSerializer);
  }

  public void setVariables(Map<String, String> values) {
    variableResolver.setVariables(values);
  }

  /** Clears statically registered variables so the lazy provider takes over for those names. */
  public void clearVariables() {
    variableResolver.clearVariables();
  }

  public void setResolver(Function<String, String> provider) {
    variableResolver.setResolver(provider);
  }

  /**
   * Restrict emitted URL schemes (lower-cased). Neither {@code null} nor an empty collection
   * is accepted: an empty scheme allowlist would make every generateUrl call fail. To disable
   * scheme enforcement, pass the explicit wildcard {@code List.of("*")}. Throws on null/empty.
   */
  public void setAllowedSchemes(Collection<String> schemes) {
    if (schemes == null) {
      throw new IllegalArgumentException(
          "setAllowedSchemes does not accept null — pass a scheme list, or List.of(\"*\") to "
              + "explicitly disable scheme enforcement");
    }
    if (schemes.isEmpty()) {
      throw new IllegalArgumentException(
          "setAllowedSchemes does not accept an empty list — an empty scheme allowlist would "
              + "reject every URL. Pass List.of(\"*\") to explicitly disable scheme enforcement");
    }
    List<String> lowered = schemes.stream().map(String::toLowerCase).toList();
    this.allowedSchemes = lowered.contains("*") ? null : Set.copyOf(lowered);
  }

  /**
   * Restrict emitted URL hosts (lower-cased, matched by hostname without port). Neither
   * {@code null} nor undefined is accepted — host enforcement is an explicit decision, so the
   * only way to disable it is the explicit wildcard {@code List.of("*")}. An empty collection
   * is valid and rejects every host (fail-closed). The host is checked on the expanded URL so
   * a variable filling the host position is covered.
   */
  public void setAllowedHosts(Collection<String> hosts) {
    if (hosts == null) {
      throw new IllegalArgumentException(
          "setAllowedHosts does not accept null — pass a host list, an empty list to reject "
              + "every host, or List.of(\"*\") to explicitly disable host enforcement");
    }
    List<String> lowered = hosts.stream().map(String::toLowerCase).toList();
    this.allowedHosts = lowered.contains("*") ? null : Set.copyOf(lowered);
  }

  public String generateUrl(SignedProtocol signedProtocol) {
    boolean valid = signatureVerifier.verify(signedProtocol.payload(), signedProtocol.signature());
    if (!valid) {
      throw new VerificationException(LinkSealErrorCode.INVALID_SIGNATURE, "Protocol signature verification failed");
    }

    assertNotExpired(signedProtocol.payload().expiresAt());

    String template = signedProtocol.payload().template();
    List<String> declared = templateEngine.variableNames(template);
    Map<String, String> resolved = variableResolver.resolve(declared);
    Map<String, String> variables =
        policyProcessor.applyMissingPolicy(template, resolved, signedProtocol.payload().policy());

    String url = templateEngine.expand(template, variables);
    assertTrustedUrl(url);
    return url;
  }

  /**
   * Defense against a validly-signed-but-untrusted URL: a compromised signer key, a malicious
   * signer, or a lazy provider returning an untrusted host. The signature only covers the
   * template bytes; it says nothing about whether this resolver should trust the resulting
   * scheme/host. Checked on the expanded URL because variables can fill the host position.
   */
  private void assertTrustedUrl(String url) {
    URI uri;
    try {
      uri = new URI(url);
    } catch (URISyntaxException e) {
      throw new TrustException("Untrusted URL: malformed or no scheme (" + url + ")", e);
    }
    String scheme = uri.getScheme();
    if (scheme == null) {
      throw new TrustException("Untrusted URL: no scheme (" + url + ")");
    }
    scheme = scheme.toLowerCase();
    if (allowedSchemes != null && !allowedSchemes.contains(scheme)) {
      throw new TrustException(
          "Untrusted URL scheme '" + scheme + "': not in allowed schemes");
    }
    if (allowedHosts != null) {
      String host = uri.getHost();
      if (host == null || !allowedHosts.contains(host.toLowerCase())) {
        throw new TrustException(
            "Untrusted URL host '" + host + "': not in allowed hosts");
      }
    }
  }


  /** Rejects a payload past its {@code expiresAt}. Checked after verify so only signed expiry
   *  claims are honored — an attacker can't strip expiry without invalidating the signature.
   *  The value must be ISO-8601 with an offset or {@code Z}; a bare local-time string is rejected
   *  to avoid cross-language parse divergence. */
  private void assertNotExpired(String expiresAt) {
    if (expiresAt == null || expiresAt.isEmpty()) {
      return;
    }
    java.time.Instant expiry;
    try {
      expiry = java.time.Instant.parse(expiresAt);
    } catch (java.time.format.DateTimeParseException e) {
      throw new VerificationException(LinkSealErrorCode.MALFORMED_EXPIRES_AT, "Malformed expiresAt: '" + expiresAt + "'", e);
    }
    if (java.time.Instant.now().isAfter(expiry)) {
      throw new VerificationException(LinkSealErrorCode.PROTOCOL_EXPIRED, "Protocol expired at " + expiresAt);
    }
  }
}
