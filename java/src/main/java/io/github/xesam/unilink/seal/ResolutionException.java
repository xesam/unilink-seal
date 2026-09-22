package io.github.xesam.unilink.seal;

/** The signed protocol is fine but could not be resolved (variables, template grammar). */
public final class ResolutionException extends LinkSealException {
  public ResolutionException(LinkSealErrorCode code, String message) {
    super(code, message);
  }
}
