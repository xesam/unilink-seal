package io.github.xesam.unilink.seal;

/** The signed protocol itself is not acceptable (signature, expiry). */
public final class VerificationException extends LinkSealException {
  public VerificationException(LinkSealErrorCode code, String message) {
    super(code, message);
  }

  public VerificationException(LinkSealErrorCode code, String message, Throwable cause) {
    super(code, message, cause);
  }
}
