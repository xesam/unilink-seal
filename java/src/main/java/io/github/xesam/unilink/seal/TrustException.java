package io.github.xesam.unilink.seal;

/** The expanded URL is not trusted for this resolver (scheme/host allowlists). */
public final class TrustException extends LinkSealException {
  public TrustException(String message) {
    super(LinkSealErrorCode.UNTRUSTED_URL, message);
  }

  public TrustException(String message, Throwable cause) {
    super(LinkSealErrorCode.UNTRUSTED_URL, message, cause);
  }
}
