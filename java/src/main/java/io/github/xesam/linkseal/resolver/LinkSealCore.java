package io.github.xesam.linkseal.resolver;

import io.github.xesam.linkseal.JsonSerializer;
import io.github.xesam.linkseal.model.SignedProtocol;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class LinkSealCore {
  private final TemplateEngine templateEngine;
  private final VariableResolver variableResolver;
  private final PolicyProcessor policyProcessor;
  private final SignatureVerifier signatureVerifier;

  /**
   * Schemes the resolver will emit by default. Restricted to {@code https} so a signed template
   * cannot produce a {@code javascript:}/{@code http:}/{@code intent:} URL — the signature only
   * proves the template is un-tampered, not that its scheme is safe to load. Override with
   * {@link #setAllowedSchemes(Collection)}, or pass {@code null} to disable (tests only).
   */
  private Set<String> allowedSchemes = Set.of("https");

  /**
   * Hosts the resolver will emit, matched by hostname without port. {@code null} (default)
   * disables host enforcement. Set via {@link #setAllowedHosts(Collection)}. The host is
   * checked on the expanded URL so a variable filling the host position is covered.
   */
  private Set<String> allowedHosts = null;

  public LinkSealCore() {
    this.templateEngine = new TemplateEngine();
    this.variableResolver = new VariableResolver();
    this.policyProcessor = new PolicyProcessor();
    this.signatureVerifier = new SignatureVerifier();
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

  /** Restrict emitted URL schemes (lower-cased). Pass {@code null} to disable scheme enforcement. */
  public void setAllowedSchemes(Collection<String> schemes) {
    this.allowedSchemes = schemes == null ? null : toLowerSet(schemes);
  }

  /**
   * Restrict emitted URL hosts (lower-cased, matched by hostname without port). Pass {@code null}
   * to disable host enforcement (the default). The host is checked on the expanded URL so a
   * variable filling the host position (e.g. {@code https://{host}/...}) is covered.
   */
  public void setAllowedHosts(Collection<String> hosts) {
    this.allowedHosts = hosts == null ? null : toLowerSet(hosts);
  }

  public String generateUrl(SignedProtocol signedProtocol) {
    boolean valid = signatureVerifier.verify(signedProtocol.payload(), signedProtocol.signature());
    if (!valid) {
      throw new IllegalArgumentException("Protocol signature verification failed");
    }

    assertNotExpired(signedProtocol.payload().expiresAt());

    String template = signedProtocol.payload().template();
    List<String> declared = templateEngine.variableNames(template);
    Map<String, String> resolved = variableResolver.resolve(declared);
    Map<String, String> variables =
        policyProcessor.applyMissingPolicy(resolved, signedProtocol.payload().policy());

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
      throw new IllegalArgumentException("Untrusted URL: malformed or no scheme (" + url + ")", e);
    }
    String scheme = uri.getScheme();
    if (scheme == null) {
      throw new IllegalArgumentException("Untrusted URL: no scheme (" + url + ")");
    }
    scheme = scheme.toLowerCase();
    if (allowedSchemes != null && !allowedSchemes.contains(scheme)) {
      throw new IllegalArgumentException(
          "Untrusted URL scheme '" + scheme + "': not in allowed schemes");
    }
    if (allowedHosts != null) {
      String host = uri.getHost();
      if (host == null || !allowedHosts.contains(host.toLowerCase())) {
        throw new IllegalArgumentException(
            "Untrusted URL host '" + host + "': not in allowed hosts");
      }
    }
  }

  private static Set<String> toLowerSet(Collection<String> values) {
    return values.stream().map(String::toLowerCase).collect(Collectors.toUnmodifiableSet());
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
      throw new IllegalArgumentException("Malformed expiresAt: '" + expiresAt + "'", e);
    }
    if (java.time.Instant.now().isAfter(expiry)) {
      throw new IllegalArgumentException("Protocol expired at " + expiresAt);
    }
  }
}
