import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { LinkSealCore } from '../LinkSealCore.js';
import { VerificationError, ResolutionError, TrustError } from '../errors.js';
import { WebCryptoSignatureBackend } from '../WebCryptoSignatureBackend.js';
import { canonicalizePayload } from 'unilink-seal';
import { ProtocolSigner } from 'unilink-seal-signer';
import type { LinkSealProtocol, SignedProtocol } from 'unilink-seal';

const spec = JSON.parse(
  readFileSync(new URL('../../../../../spec/examples/user-profile.signed.json', import.meta.url), 'utf8')
) as { publicKey: string; signedProtocol: SignedProtocol };

const expiring = JSON.parse(
  readFileSync(new URL('../../../../../spec/examples/expiring-rotated.signed.json', import.meta.url), 'utf8')
) as { publicKey: string; signedProtocol: SignedProtocol };

const PUBLIC_KEY_PEM = spec.publicKey;
const PRIVATE_KEY_PEM = readFileSync(
  new URL('../../../../../spec/keys/test-private.pem', import.meta.url),
  'utf8'
);
const EXPECTED_URL =
  'https://api.example.com/users/user_123?source=app&token=sess_abc&locale=en-US';

function signedProtocol(): SignedProtocol {
  return JSON.parse(JSON.stringify(spec.signedProtocol)) as SignedProtocol;
}

async function core(): Promise<LinkSealCore> {
  const c = new LinkSealCore({ allowedHosts: ['*'] });
  await c.setPublicKey(PUBLIC_KEY_PEM);
  c.setVariables({ userId: 'user_123', token: 'sess_abc', locale: 'en-US' });
  return c;
}

/** Sign a custom payload with the test private key so its signature verifies, isolating the
 *  trust check from signature failures — only a validly-signed URL reaches assertTrustedUrl. */
async function signCustom(payload: LinkSealProtocol): Promise<SignedProtocol> {
  const signer = new ProtocolSigner();
  await signer.setPrivateKey(PRIVATE_KEY_PEM);
  return signer.signProtocol(payload);
}

describe('LinkSealCore', () => {
  describe('constructor requires the trusted-host boundary (mirrored in the Java SDK)', () => {
    it('rejects construction without allowedHosts', () => {
      expect(() => new (LinkSealCore as any)()).toThrow(/requires allowedHosts/);
    });

    it('rejects construction with an empty allowedHosts list', () => {
      expect(() => new LinkSealCore({ allowedHosts: [] })).toThrow(/requires allowedHosts/);
    });

    it('enforces constructor-supplied hosts (regression)', async () => {
      const c = new LinkSealCore({ allowedHosts: ['api.example.com'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setVariables({ userId: 'user_123' });
      const evil = await signCustom({
        version: '1.0',
        template: 'https://evil.com/users/{userId}',
        policy: { missing: 'error' },
      });
      const error = await c.generateUrl(evil).catch((e) => e);
      expect(error).toBeInstanceOf(TrustError);
      expect(error.code).toBe('UNTRUSTED_URL');

      const trusted = await signCustom({
        version: '1.0',
        template: 'https://api.example.com/users/{userId}',
        policy: { missing: 'error' },
      });
      expect(await c.generateUrl(trusted)).toBe('https://api.example.com/users/user_123');
    });

    it("treats ['*'] as the explicit wildcard and emits any host", async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https://evil.com/users/{userId}',
        policy: { missing: 'error' },
      });
      expect(await c.generateUrl(signed)).toBe('https://evil.com/users/user_123');
    });
  });

  it('generates URL from spec signed protocol', async () => {
    expect(await (await core()).generateUrl(signedProtocol())).toBe(EXPECTED_URL);
  });

  it('resolves placeholders through a lazy provider', async () => {
    const c = new LinkSealCore({ allowedHosts: ['*'] });
    await c.setPublicKey(PUBLIC_KEY_PEM);
    c.setVariables({ userId: 'user_123' });
    c.setResolver((name) => {
      if (name === 'token') return 'sess_abc';
      if (name === 'locale') return 'en-US';
      return null;
    });

    expect(await c.generateUrl(signedProtocol())).toBe(EXPECTED_URL);
  });

  it('prefers registered variables over the provider', async () => {
    const provider = vi.fn(() => 'FROM_PROVIDER');
    const c = new LinkSealCore({ allowedHosts: ['*'] });
    await c.setPublicKey(PUBLIC_KEY_PEM);
    c.setVariables({ userId: 'user_123', token: 'sess_abc', locale: 'en-US' });
    c.setResolver(provider);

    expect(await c.generateUrl(signedProtocol())).toBe(EXPECTED_URL);
    expect(provider).not.toHaveBeenCalled();
  });

  it('clearVariables releases static values so the provider takes over', async () => {
    const c = new LinkSealCore({ allowedHosts: ['*'] });
    await c.setPublicKey(PUBLIC_KEY_PEM);
    c.setVariables({ userId: 'user_123', token: 'STATIC', locale: 'en-US' });

    // Static token shadows any provider.
    expect(await c.generateUrl(signedProtocol())).toBe(
      'https://api.example.com/users/user_123?source=app&token=STATIC&locale=en-US'
    );

    // After clearing, the provider supplies token; re-register only userId.
    c.clearVariables();
    c.setVariables({ userId: 'user_123' });
    c.setResolver((name) => (name === 'token' ? 'FRESH' : name === 'locale' ? 'en-US' : null));

    expect(await c.generateUrl(signedProtocol())).toBe(
      'https://api.example.com/users/user_123?source=app&token=FRESH&locale=en-US'
    );
  });

  it('throws on malformed signature (typed as VerificationError/INVALID_SIGNATURE)', async () => {
    const c = await core();
    const error = await c.generateUrl({ ...signedProtocol(), signature: 'AAAA' }).catch((e) => e);
    expect(error).toBeInstanceOf(VerificationError);
    expect(error.code).toBe('INVALID_SIGNATURE');
    expect(error.message).toBe('Protocol signature verification failed');
  });

  it('throws on tampered signature', async () => {
    const c = await core();
    const protocol = signedProtocol();
    await expect(
      c.generateUrl({ ...protocol, signature: protocol.signature.replace(/^./, 'Z') })
    ).rejects.toThrow('Protocol signature verification failed');
  });

  it('throws when the template is redirected', async () => {
    const c = await core();
    const protocol = signedProtocol();
    protocol.payload.template = 'https://evil.com/{userId}';
    await expect(c.generateUrl(protocol)).rejects.toThrow(
      'Protocol signature verification failed'
    );
  });

  it('throws when policy is downgraded', async () => {
    const c = await core();
    const protocol = signedProtocol();
    protocol.payload.policy = { missing: 'ignore' };
    await expect(c.generateUrl(protocol)).rejects.toThrow(
      'Protocol signature verification failed'
    );
  });

  // Regression: missing detection never fired, so this silently produced a partial URL.
  it('throws when a required variable cannot be resolved', async () => {
    const c = new LinkSealCore({ allowedHosts: ['*'] });
    await c.setPublicKey(PUBLIC_KEY_PEM);
    c.setVariables({ userId: 'user_123', locale: 'en-US' });

    const error = await c.generateUrl(signedProtocol()).catch((e) => e);
    expect(error).toBeInstanceOf(ResolutionError);
    expect(error.code).toBe('MISSING_VARIABLE');
    expect(error.message).toBe('Missing required variables: token');
  });

  it('throws when the provider declines a required variable', async () => {
    const c = new LinkSealCore({ allowedHosts: ['*'] });
    await c.setPublicKey(PUBLIC_KEY_PEM);
    c.setVariables({ userId: 'user_123', locale: 'en-US' });
    c.setResolver(() => null);

    await expect(c.generateUrl(signedProtocol())).rejects.toThrow(
      'Missing required variables: token'
    );
  });

  it('does not fall back to built-in placeholder values', async () => {
    const c = new LinkSealCore({ allowedHosts: ['*'] });
    await c.setPublicKey(PUBLIC_KEY_PEM);

    await expect(c.generateUrl(signedProtocol())).rejects.toThrow('Missing required variables');
  });

  describe('URL trust enforcement', () => {
    it('rejects an http template by default (only https allowed)', async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'http://api.example.com/users/{userId}',
        policy: { missing: 'error' },
      });

      await expect(c.generateUrl(signed)).rejects.toThrow(/Untrusted URL scheme 'http'/);
    });

    it('accepts http when the scheme allowlist includes it', async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedSchemes(['http', 'https']);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'http://api.example.com/users/{userId}',
        policy: { missing: 'error' },
      });

      expect(await c.generateUrl(signed)).toBe('http://api.example.com/users/user_123');
    });

    it("disables scheme enforcement via the explicit wildcard ['*'] (mirrored in the Java SDK)", async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedSchemes(['*']);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'javascript://alert(1)/{userId}',
        policy: { missing: 'error' },
      });

      await expect(c.generateUrl(signed)).resolves.toBe('javascript://alert(1)/user_123');
    });

    it("rejects a syntactically malformed scheme even under the ['*'] wildcard (mirrored in the Java SDK)", async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedSchemes(['*']);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: '1abc://api.example.com/users/{userId}',
        policy: { missing: 'error' },
      });

      await expect(c.generateUrl(signed)).rejects.toThrow(/malformed scheme '1abc'/);
    });

    it('accepts a custom scheme containing + (e.g. web+action)', async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedSchemes(['web+action']);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'web+action://open/users/{userId}',
        policy: { missing: 'error' },
      });

      expect(await c.generateUrl(signed)).toBe('web+action://open/users/user_123');
    });

    it('rejects a host outside the allowlist even with a valid signature', async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedHosts(['api.example.com']);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https://evil.com/users/{userId}',
        policy: { missing: 'error' },
      });

      const error = await c.generateUrl(signed).catch((e) => e);
      expect(error).toBeInstanceOf(TrustError);
      expect(error.code).toBe('UNTRUSTED_URL');
      expect(error.message).toMatch(/Untrusted URL host 'evil.com'/);
    });

    // Cross-language pin: an opaque URL (no `//` authority) has no host — Java's
    // URI.getHost() returns null and the JS parser yields '' — so both ends reject
    // it under a configured allowlist and neither mistakes the path for a hostname.
    it('rejects setAllowedHosts(null) and setAllowedSchemes(null)/([]) — null is not an enforcement switch (mirrored in the Java SDK)', () => {
      const c = new LinkSealCore({ allowedHosts: ['api.example.com'] });
      expect(() => c.setAllowedHosts(null as unknown as string[])).toThrow(/setAllowedHosts does not accept null/);
      expect(() => c.setAllowedSchemes(null as unknown as string[])).toThrow(/setAllowedSchemes does not accept null/);
      expect(() => c.setAllowedSchemes([])).toThrow(/setAllowedSchemes does not accept an empty list/);
    });

    it('treats an authority-less URL as hostless, mirroring Java (opaque URL)', async () => {
      const c = new LinkSealCore({ allowedHosts: ['api.example.com'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https:evil.com/users/{userId}',
        policy: { missing: 'error' },
      });
      const error = await c.generateUrl(signed).catch((e) => e);
      expect(error).toBeInstanceOf(TrustError);
      expect(error.code).toBe('UNTRUSTED_URL');
      expect(error.message).toMatch(/Untrusted URL host/);
    });

    it('accepts a host inside the allowlist', async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedHosts(['evil.com']);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https://evil.com/users/{userId}',
        policy: { missing: 'error' },
      });

      expect(await c.generateUrl(signed)).toBe('https://evil.com/users/user_123');
    });

    // Proves the host check runs on the expanded URL: a variable can fill the host position,
    // so checking the template's literal host would miss it.
    it('rejects an untrusted host supplied via a variable', async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedHosts(['api.example.com']);
      c.setVariables({ host: 'evil.com', userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https://{host}/users/{userId}',
        policy: { missing: 'error' },
      });

      await expect(c.generateUrl(signed)).rejects.toThrow(/Untrusted URL host 'evil.com'/);
    });

    it('still accepts the spec URL with host allowlist configured', async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedHosts(['api.example.com']);
      c.setVariables({ userId: 'user_123', token: 'sess_abc', locale: 'en-US' });

      expect(await c.generateUrl(signedProtocol())).toBe(EXPECTED_URL);
    });
  });

  describe('expiry (expiresAt)', () => {
    it('throws when the protocol is expired', async () => {
      const c = await core();
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https://api.example.com/users/{userId}',
        policy: { missing: 'error' },
        expiresAt: '2000-01-01T00:00:00Z',
      });

      const error = await c.generateUrl(signed).catch((e) => e);
      expect(error).toBeInstanceOf(VerificationError);
      expect(error.code).toBe('PROTOCOL_EXPIRED');
      expect(error.message).toMatch(/Protocol expired/);
    });

    it('accepts a future expiry', async () => {
      const c = await core();
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https://api.example.com/users/{userId}',
        policy: { missing: 'error' },
        expiresAt: '2099-12-31T23:59:59Z',
      });

      expect(await c.generateUrl(signed)).toBe('https://api.example.com/users/user_123');
    });

    it('throws on a malformed expiresAt', async () => {
      const c = await core();
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https://api.example.com/users/{userId}',
        policy: { missing: 'error' },
        expiresAt: 'not-a-date',
      });

      const error = await c.generateUrl(signed).catch((e) => e);
      expect(error).toBeInstanceOf(VerificationError);
      expect(error.code).toBe('MALFORMED_EXPIRES_AT');
      expect(error.message).toMatch(/Malformed expiresAt/);
    });

    // Cross-language pin: a bare date (no time/offset) is rejected on both ends — JS's lenient
    // Date.parse would otherwise accept it while Java's Instant.parse rejects it.
    it('rejects a bare-date expiresAt that Date.parse would accept', async () => {
      const c = await core();
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https://api.example.com/users/{userId}',
        policy: { missing: 'error' },
        expiresAt: '2026-08-07',
      });

      const error = await c.generateUrl(signed).catch((e) => e);
      expect(error).toBeInstanceOf(VerificationError);
      expect(error.code).toBe('MALFORMED_EXPIRES_AT');
      expect(error.message).toMatch(/Malformed expiresAt/);
    });
  });

  describe('key rotation (kid)', () => {
    // The expiring-rotated example was signed by the JS signer with kid="test-key-1".
    // Verifying it here AND in the Java SDK pins cross-language byte agreement for the new fields.
    it('verifies the committed expiring-rotated signature under the registered kid', async () => {
      const backend = new WebCryptoSignatureBackend();
      await backend.setPublicKey(expiring.signedProtocol.payload.kid!, expiring.publicKey);
      const canonical = canonicalizePayload(expiring.signedProtocol.payload);
      expect(await backend.verify(canonical, expiring.signedProtocol.signature, expiring.signedProtocol.payload.kid)).toBe(true);
    });

    it('generates the URL from the expiring-rotated example using the kid key', async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(expiring.signedProtocol.payload.kid!, expiring.publicKey);
      c.setVariables({ userId: 'user_123', token: 'sess_abc', locale: 'en-US' });

      expect(await c.generateUrl(expiring.signedProtocol)).toBe(EXPECTED_URL);
    });

    it('throws when the kid has no registered key', async () => {
      const c = new LinkSealCore({ allowedHosts: ['*'] });
      await c.setPublicKey(PUBLIC_KEY_PEM); // default key only, no kid registered
      c.setVariables({ userId: 'user_123', token: 'sess_abc', locale: 'en-US' });

      await expect(c.generateUrl(expiring.signedProtocol)).rejects.toThrow(/test-key-1/);
    });
  });
});
