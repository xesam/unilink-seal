package io.github.xesam.unilink.seal;

import io.github.xesam.unilink.seal.model.LinkSealProtocol;
import org.erdtman.jcs.JsonCanonicalizer;

/**
 * Canonicalizes a payload per RFC 8785 (JSON Canonicalization Scheme) via {@link JsonCanonicalizer}.
 *
 * <p>The payload is first serialized to JSON by the injected {@link JsonSerializer}, then
 * re-serialized canonically. The SDK binds no serializer itself, so every field the serializer
 * emits is covered by the signature; conversely, a field the serializer omits is not covered.
 */
public final class Canonicalizer {
  private Canonicalizer() {}

  public static String canonicalize(LinkSealProtocol payload, JsonSerializer serializer) throws Exception {
    return new JsonCanonicalizer(serializer.serialize(payload)).getEncodedString();
  }
}
