import canonicalize from 'canonicalize';

/**
 * Canonicalize a payload per RFC 8785 (JSON Canonicalization Scheme).
 * The same spec is implemented by the Java SDK via `org.erdtman.jcs.JsonCanonicalizer`,
 * so both sides emit byte-identical canonical bytes for the same payload.
 */
export function canonicalizePayload(payload: unknown): string {
  const result = canonicalize(payload);
  if (result === undefined) {
    throw new Error('Cannot canonicalize payload (unsupported value)');
  }
  return result;
}
