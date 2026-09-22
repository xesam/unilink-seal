/**
 * Typed error hierarchy for the resolver pipeline, mirrored by the Java SDK
 * (`LinkSealException` + `LinkSealErrorCode`).
 *
 * Three high-level classes split the pipeline's failure modes; the `code` field
 * carries the fine-grained reason so hosts can branch without string matching:
 *
 * - {@link VerificationError} — the signed protocol itself is not acceptable
 *   (bad signature, malformed/past `expiresAt`)
 * - {@link ResolutionError} — the signed protocol is fine but could not be resolved
 *   (missing variable, template outside the supported subset, invalid template)
 * - {@link TrustError} — the expanded URL is not trusted for this resolver
 *   (scheme/host outside the allowlists)
 */

export type LinkSealErrorCode =
  | 'INVALID_SIGNATURE'
  | 'MALFORMED_EXPIRES_AT'
  | 'PROTOCOL_EXPIRED'
  | 'MISSING_VARIABLE'
  | 'UNSUPPORTED_TEMPLATE'
  | 'INVALID_TEMPLATE'
  | 'UNTRUSTED_URL';

export class LinkSealError extends Error {
  /**
   * Fine-grained reason, identical on both SDKs. **Branch on this field, not on
   * `error.name` / `instanceof`-by-constructor-name** — minifiers rewrite subclass
   * constructor names, but `code` survives bundling unchanged.
   */
  readonly code: LinkSealErrorCode;

  constructor(code: LinkSealErrorCode, message: string) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
  }
}

/** The signed protocol itself is not acceptable (signature, expiry). */
export class VerificationError extends LinkSealError {
  constructor(code: 'INVALID_SIGNATURE' | 'MALFORMED_EXPIRES_AT' | 'PROTOCOL_EXPIRED', message: string) {
    super(code, message);
  }
}

/** The signed protocol is fine but could not be resolved (variables, template grammar). */
export class ResolutionError extends LinkSealError {
  constructor(code: 'MISSING_VARIABLE' | 'UNSUPPORTED_TEMPLATE' | 'INVALID_TEMPLATE', message: string) {
    super(code, message);
  }
}

/** The expanded URL is not trusted for this resolver (scheme/host allowlists). */
export class TrustError extends LinkSealError {
  constructor(message: string) {
    super('UNTRUSTED_URL', message);
  }
}
