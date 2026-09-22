package io.github.xesam.unilink.seal;

/**
 * Base of the typed error hierarchy for the resolver pipeline, mirrored by the JavaScript
 * SDK's {@code LinkSealError}. Subclasses split the pipeline's failure modes:
 *
 * <ul>
 *   <li>{@link VerificationException} — the signed protocol itself is not acceptable
 *       (bad signature, malformed/past {@code expiresAt})</li>
 *   <li>{@link ResolutionException} — the signed protocol is fine but could not be resolved
 *       (missing variable, template outside the supported subset, invalid template)</li>
 *   <li>{@link TrustException} — the expanded URL is not trusted for this resolver
 *       (scheme/host outside the allowlists)</li>
 * </ul>
 */
public class LinkSealException extends RuntimeException {
  private final LinkSealErrorCode code;

  public LinkSealException(LinkSealErrorCode code, String message) {
    super(message);
    this.code = code;
  }

  public LinkSealException(LinkSealErrorCode code, String message, Throwable cause) {
    super(message, cause);
    this.code = code;
  }

  /** Fine-grained reason, identical on both SDKs. */
  public LinkSealErrorCode code() {
    return code;
  }
}
