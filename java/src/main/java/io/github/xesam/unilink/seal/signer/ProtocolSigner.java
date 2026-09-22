package io.github.xesam.unilink.seal.signer;

import io.github.xesam.unilink.seal.Canonicalizer;
import io.github.xesam.unilink.seal.JsonSerializer;
import io.github.xesam.unilink.seal.PemKeys;
import io.github.xesam.unilink.seal.model.LinkSealProtocol;
import io.github.xesam.unilink.seal.model.SignedProtocol;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Signs {@link LinkSealProtocol} payloads with Ed25519.
 *
 * <p><strong>CRITICAL</strong>: A {@link JsonSerializer} must be injected at construction time.
 * The serializer MUST cover all protocol fields, including optional ones when present. Fields
 * omitted from serialization will <strong>not be protected by the signature</strong> and can be
 * tampered with.
 *
 * <p><strong>Quick start (zero-dependency):</strong>
 * <pre>{@code
 * ProtocolSigner signer = new ProtocolSigner(new ReferenceJsonSerializer());
 * signer.setPrivateKey(privatePem);
 * SignedProtocol signed = signer.signProtocol(payload);
 * }</pre>
 *
 * <p><strong>Production (with Jackson):</strong>
 * <pre>{@code
 * ObjectMapper mapper = new ObjectMapper();
 * ProtocolSigner signer = new ProtocolSigner(payload -> mapper.writeValueAsString(payload));
 * signer.setPrivateKey(privatePem);
 * SignedProtocol signed = signer.signProtocol(payload);
 * }</pre>
 *
 * <p><strong>Production (with Gson):</strong>
 * <pre>{@code
 * Gson gson = new Gson();
 * ProtocolSigner signer = new ProtocolSigner(payload -> gson.toJson(payload));
 * signer.setPrivateKey(privatePem);
 * SignedProtocol signed = signer.signProtocol(payload);
 * }</pre>
 */
public final class ProtocolSigner {
  private PrivateKey privateKey;
  private final JsonSerializer jsonSerializer;

  /**
   * Constructs a signer with the given serializer.
   *
   * @param jsonSerializer serializer covering all protocol fields; use {@link ReferenceJsonSerializer}
   *                       for zero-dependency setup, or provide your own (Jackson/Gson/etc).
   * @throws IllegalArgumentException if serializer is null
   */
  public ProtocolSigner(JsonSerializer jsonSerializer) {
    if (jsonSerializer == null) {
      throw new IllegalArgumentException(
        "JsonSerializer is required. Use ReferenceJsonSerializer for zero-dependency setup, " +
        "or provide your own (Jackson/Gson/etc)."
      );
    }
    this.jsonSerializer = jsonSerializer;
  }

  public void setPrivateKey(String keyPem) {
    this.privateKey = PemKeys.parsePrivateKey(keyPem);
  }

  public String signPayload(LinkSealProtocol payload) {
    if (privateKey == null) {
      throw new IllegalStateException("Private key not set");
    }

    try {
      Signature signer = Signature.getInstance("Ed25519");
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
