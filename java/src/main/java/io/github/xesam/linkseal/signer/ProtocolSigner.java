package io.github.xesam.linkseal.signer;

import io.github.xesam.linkseal.Canonicalizer;
import io.github.xesam.linkseal.JsonSerializer;
import io.github.xesam.linkseal.PemKeys;
import io.github.xesam.linkseal.model.LinkSealProtocol;
import io.github.xesam.linkseal.model.SignedProtocol;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

public final class ProtocolSigner {
  private PrivateKey privateKey;
  private JsonSerializer jsonSerializer;

  public void setPrivateKey(String keyPem) {
    this.privateKey = PemKeys.parsePrivateKey(keyPem);
  }

  public void setJsonSerializer(JsonSerializer jsonSerializer) {
    this.jsonSerializer = jsonSerializer;
  }

  public String signPayload(LinkSealProtocol payload) {
    if (privateKey == null) {
      throw new IllegalStateException("Private key not set");
    }
    if (jsonSerializer == null) {
      throw new IllegalStateException("JSON serializer not set");
    }

    try {
      Signature signer = Signature.getInstance("SHA256withRSA");
      signer.initSign(privateKey);
      signer.update(Canonicalizer.canonicalize(payload, jsonSerializer).getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(signer.sign());
    } catch (Exception error) {
      throw new IllegalArgumentException("Protocol signing failed", error);
    }
  }

  public SignedProtocol signProtocol(LinkSealProtocol payload) {
    return new SignedProtocol(payload, signPayload(payload));
  }
}
