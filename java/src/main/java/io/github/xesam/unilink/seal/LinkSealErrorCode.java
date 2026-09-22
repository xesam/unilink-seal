package io.github.xesam.unilink.seal;

/**
 * Fine-grained failure reason, mirrored by the JavaScript SDK's {@code LinkSealErrorCode}.
 * Hosts branch on this instead of parsing exception messages.
 */
public enum LinkSealErrorCode {
  INVALID_SIGNATURE,
  MALFORMED_EXPIRES_AT,
  PROTOCOL_EXPIRED,
  MISSING_VARIABLE,
  UNSUPPORTED_TEMPLATE,
  INVALID_TEMPLATE,
  UNTRUSTED_URL
}
