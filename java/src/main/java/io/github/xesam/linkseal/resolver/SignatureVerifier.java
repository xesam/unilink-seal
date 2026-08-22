package io.github.xesam.linkseal.resolver;

import io.github.xesam.linkseal.Canonicalizer;
import io.github.xesam.linkseal.JsonSerializer;
import io.github.xesam.linkseal.PemKeys;
import io.github.xesam.linkseal.model.LinkSealProtocol;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;

public final class SignatureVerifier {
  private PublicKey defaultKey;
  private final Map<String, PublicKey> keysByKid = new HashMap<>();
  private JsonSerializer jsonSerializer;

  /** Set the default public key, used when a payload carries no {@code kid}. */
  public void setPublicKey(String keyPem) {
    this.defaultKey = PemKeys.parsePublicKey(keyPem);
  }

  /** Register a public key under a {@code kid}, used when a payload carries that {@code kid}. */
  public void setPublicKey(String kid, String keyPem) {
    keysByKid.put(kid, PemKeys.parsePublicKey(keyPem));
  }

  public void setJsonSerializer(JsonSerializer jsonSerializer) {
    this.jsonSerializer = jsonSerializer;
  }

  public boolean verify(LinkSealProtocol payload, String signature) {
    PublicKey publicKey = selectKey(payload.kid());
    if (publicKey == null) {
      throw new IllegalStateException(
          payload.kid() != null ? "No public key registered for kid '" + payload.kid() + "'"
                                : "Public key not set");
    }
    if (jsonSerializer == null) {
      throw new IllegalStateException("JSON serializer not set");
    }

    String canonical;
    try {
      canonical = Canonicalizer.canonicalize(payload, jsonSerializer);
    } catch (Exception error) {
      throw new IllegalArgumentException("Payload canonicalization failed", error);
    }

    try {
      Signature verifier = Signature.getInstance("SHA256withRSA");
      verifier.initVerify(publicKey);
      verifier.update(canonical.getBytes(StandardCharsets.UTF_8));
      return verifier.verify(Base64.getDecoder().decode(signature));
    } catch (SignatureException error) {
      return false;
    } catch (GeneralSecurityException error) {
      throw new IllegalArgumentException("Protocol signature verification failed", error);
    }
  }

  private PublicKey selectKey(String kid) {
    if (kid != null && !kid.isEmpty()) {
      return keysByKid.get(kid);
    }
    return defaultKey;
  }
}
