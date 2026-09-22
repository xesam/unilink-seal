import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { WebCryptoSignatureBackend } from '../WebCryptoSignatureBackend.js';
import { canonicalizePayload } from 'unilink-seal';
import type { LinkSealProtocol, SignedProtocol } from 'unilink-seal';

const spec = JSON.parse(
  readFileSync(new URL('../../../../../spec/examples/user-profile.signed.json', import.meta.url), 'utf8')
) as { publicKey: string; signedProtocol: SignedProtocol };

const PUBLIC_KEY_PEM = spec.publicKey;
const SPEC_PAYLOAD = spec.signedProtocol.payload;
const SPEC_SIGNATURE = spec.signedProtocol.signature;
const SPEC_CANONICAL = canonicalizePayload(SPEC_PAYLOAD);

async function backend(): Promise<WebCryptoSignatureBackend> {
  const b = new WebCryptoSignatureBackend();
  await b.setPublicKey(PUBLIC_KEY_PEM);
  return b;
}

describe('WebCryptoSignatureBackend', () => {
  it('throws when verifying without setting a public key', async () => {
    const b = new WebCryptoSignatureBackend();
    await expect(b.verify(SPEC_CANONICAL, 'AAA')).rejects.toThrow('Public key not set');
  });

  it('throws on invalid PEM key', async () => {
    const b = new WebCryptoSignatureBackend();
    await expect(b.setPublicKey('not-a-key')).rejects.toThrow();
  });

  it('accepts the spec signature for the spec payload', async () => {
    expect(await (await backend()).verify(SPEC_CANONICAL, SPEC_SIGNATURE)).toBe(true);
  });

  it('rejects a malformed signature', async () => {
    expect(await (await backend()).verify(SPEC_CANONICAL, 'AAAA')).toBe(false);
  });

  // The template is now the sole carrier of which variables get filled,
  // so redirecting it is the primary tampering vector.
  it('rejects a redirected template host', async () => {
    const tampered: LinkSealProtocol = { ...SPEC_PAYLOAD, template: 'https://evil.com/{userId}' };
    expect(await (await backend()).verify(canonicalizePayload(tampered), SPEC_SIGNATURE)).toBe(false);
  });

  it('rejects an added template placeholder', async () => {
    const tampered: LinkSealProtocol = {
      ...SPEC_PAYLOAD,
      template: `${SPEC_PAYLOAD.template}{&injected}`,
    };
    expect(await (await backend()).verify(canonicalizePayload(tampered), SPEC_SIGNATURE)).toBe(false);
  });

  it('rejects a tampered version', async () => {
    const tampered: LinkSealProtocol = { ...SPEC_PAYLOAD, version: '2.0' };
    expect(await (await backend()).verify(canonicalizePayload(tampered), SPEC_SIGNATURE)).toBe(false);
  });

  // Regression: canonicalization once dropped nested keys, so these tampered
  // payloads verified successfully against the original signature.
  it('rejects a downgraded missing policy', async () => {
    const tampered: LinkSealProtocol = { ...SPEC_PAYLOAD, policy: { missing: 'ignore' } };
    expect(await (await backend()).verify(canonicalizePayload(tampered), SPEC_SIGNATURE)).toBe(false);
  });

  it('rejects injected policy defaults', async () => {
    const tampered: LinkSealProtocol = {
      ...SPEC_PAYLOAD,
      policy: { missing: 'error', defaults: { token: 'attacker' } },
    };
    expect(await (await backend()).verify(canonicalizePayload(tampered), SPEC_SIGNATURE)).toBe(false);
  });

  it('accepts the payload regardless of key insertion order', async () => {
    const reordered: LinkSealProtocol = {
      policy: SPEC_PAYLOAD.policy,
      template: SPEC_PAYLOAD.template,
      version: SPEC_PAYLOAD.version,
    };
    expect(await (await backend()).verify(canonicalizePayload(reordered), SPEC_SIGNATURE)).toBe(true);
  });
});
