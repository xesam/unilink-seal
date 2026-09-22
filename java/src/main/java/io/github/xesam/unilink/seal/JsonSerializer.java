package io.github.xesam.unilink.seal;

import io.github.xesam.unilink.seal.model.LinkSealProtocol;

/**
 * Converts a {@link LinkSealProtocol} to a JSON string prior to canonicalization.
 *
 * <p>The SDK does not bundle an implementation. Callers must inject one (backed by Jackson, Gson,
 * a hand-rolled writer, or whatever they configure) before signing or verifying; doing so without
 * a serializer throws {@link IllegalStateException}. The serialized JSON need not be canonical —
 * keys may appear in any order — because {@link Canonicalizer} re-serializes it per RFC 8785.
 */
@FunctionalInterface
public interface JsonSerializer {
  String serialize(LinkSealProtocol payload) throws Exception;
}
