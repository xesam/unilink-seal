/**
 * Pluggable signature backend — the single platform-dependent seam in the resolver.
 *
 * The default implementation (`WebCryptoSignatureBackend`) uses the Web Crypto API
 * (`crypto.subtle`) and works in browsers and Node.js ≥ 18. For environments without
 * Web Crypto (e.g. WeChat / Alipay mini-programs), provide an alternative implementation
 * such as `unilink-seal-crypto-minimal` (backed by `@noble/ed25519`, pure JS, no platform
 * API dependency).
 *
 * `verify` receives the **already-canonicalized** payload string (RFC 8785 JCS).
 * Canonicalization stays in the resolver core so it is done exactly once,
 * independent of which backend is plugged in.
 */
export interface SignatureBackend {
  /** Set the default public key (used when a payload carries no `kid`). */
  setPublicKey(keyPem: string): Promise<void>;
  /** Register a public key under a `kid` (for key rotation). */
  setPublicKey(kid: string, keyPem: string): Promise<void>;

  /**
   * Verify a canonicalized payload against a base64-encoded signature.
   *
   * @param canonicalPayload  RFC 8785 canonicalized JSON string
   * @param signatureBase64   base64-encoded Ed25519 signature
   * @param kid               optional key id selecting which registered key to use
   * @returns `true` if the signature is valid, `false` otherwise
   */
  verify(canonicalPayload: string, signatureBase64: string, kid?: string): Promise<boolean>;
}
