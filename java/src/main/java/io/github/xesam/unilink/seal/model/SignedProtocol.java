package io.github.xesam.unilink.seal.model;

import java.util.Objects;

public final class SignedProtocol {
  private final LinkSealProtocol payload;
  private final String signature;

  public SignedProtocol(LinkSealProtocol payload, String signature) {
    this.payload = Objects.requireNonNull(payload, "payload");
    this.signature = Objects.requireNonNull(signature, "signature");
  }

  public LinkSealProtocol payload() {
    return payload;
  }

  public String signature() {
    return signature;
  }
}
