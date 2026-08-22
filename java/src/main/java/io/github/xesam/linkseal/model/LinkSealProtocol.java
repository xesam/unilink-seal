package io.github.xesam.linkseal.model;

import java.util.Objects;

public final class LinkSealProtocol {
  private final String version;
  private final String template;
  private final PolicyConfig policy;
  private final String expiresAt;
  private final String kid;

  public LinkSealProtocol(String version, String template, PolicyConfig policy) {
    this(version, template, policy, null, null);
  }

  /** Full constructor carrying optional expiry and key id. Null means absent — the field is
   *  omitted from serialization and not covered by the signature. */
  public LinkSealProtocol(
      String version, String template, PolicyConfig policy, String expiresAt, String kid) {
    this.version = Objects.requireNonNull(version, "version");
    this.template = Objects.requireNonNull(template, "template");
    this.policy = Objects.requireNonNull(policy, "policy");
    this.expiresAt = expiresAt;
    this.kid = kid;
  }

  public String version() {
    return version;
  }

  public String template() {
    return template;
  }

  public PolicyConfig policy() {
    return policy;
  }

  /** Optional ISO-8601 expiry string, or null if absent. */
  public String expiresAt() {
    return expiresAt;
  }

  /** Optional key id, or null if absent. */
  public String kid() {
    return kid;
  }
}
