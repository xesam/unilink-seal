export type MissingPolicy = 'error' | 'ignore' | 'default';

export interface PolicyConfig {
  missing: MissingPolicy;
  defaults?: Record<string, string>;
}

export interface LinkSealProtocol {
  version: string;
  template: string;
  policy: PolicyConfig;
  /**
   * Optional expiry as an ISO-8601 string (e.g. "2026-08-07T16:00:00Z"). When present, the
   * resolver rejects the protocol after this instant. Kept as a string (not an epoch number)
   * so the payload stays all-strings and avoids cross-language number-formatting divergence
   * under RFC 8785 — see spec/PROTOCOL.md §5.2.
   */
  expiresAt?: string;
  /** Optional key id identifying which signing key produced the signature, for rotation. */
  kid?: string;
}

export interface SignedProtocol {
  payload: LinkSealProtocol;
  signature: string;
}
