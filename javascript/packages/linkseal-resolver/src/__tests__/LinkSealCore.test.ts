import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { LinkSealCore } from '../LinkSealCore.js';
import { SignatureVerifier } from '../SignatureVerifier.js';
import { ProtocolSigner } from 'linkseal-signer';
import type { LinkSealProtocol, SignedProtocol } from 'linkseal';

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
  const c = new LinkSealCore();
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
  it('generates URL from spec signed protocol', async () => {
    expect(await (await core()).generateUrl(signedProtocol())).toBe(EXPECTED_URL);
  });

  it('resolves placeholders through a lazy provider', async () => {
    const c = new LinkSealCore();
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
    const c = new LinkSealCore();
    await c.setPublicKey(PUBLIC_KEY_PEM);
    c.setVariables({ userId: 'user_123', token: 'sess_abc', locale: 'en-US' });
    c.setResolver(provider);

    expect(await c.generateUrl(signedProtocol())).toBe(EXPECTED_URL);
    expect(provider).not.toHaveBeenCalled();
  });

  it('clearVariables releases static values so the provider takes over', async () => {
    const c = new LinkSealCore();
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

  it('throws on malformed signature', async () => {
    const c = await core();
    await expect(c.generateUrl({ ...signedProtocol(), signature: 'AAAA' })).rejects.toThrow(
      'Protocol signature verification failed'
    );
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
    const c = new LinkSealCore();
    await c.setPublicKey(PUBLIC_KEY_PEM);
    c.setVariables({ userId: 'user_123', locale: 'en-US' });

    await expect(c.generateUrl(signedProtocol())).rejects.toThrow(
      'Missing required variables: token'
    );
  });

  it('throws when the provider declines a required variable', async () => {
    const c = new LinkSealCore();
    await c.setPublicKey(PUBLIC_KEY_PEM);
    c.setVariables({ userId: 'user_123', locale: 'en-US' });
    c.setResolver(() => null);

    await expect(c.generateUrl(signedProtocol())).rejects.toThrow(
      'Missing required variables: token'
    );
  });

  it('does not fall back to built-in placeholder values', async () => {
    const c = new LinkSealCore();
    await c.setPublicKey(PUBLIC_KEY_PEM);

    await expect(c.generateUrl(signedProtocol())).rejects.toThrow('Missing required variables');
  });

  describe('URL trust enforcement', () => {
    it('rejects an http template by default (only https allowed)', async () => {
      const c = new LinkSealCore();
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
      const c = new LinkSealCore();
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

    it('disables scheme enforcement when setAllowedSchemes(null)', async () => {
      const c = new LinkSealCore();
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedSchemes(null);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'javascript://alert(1)/{userId}',
        policy: { missing: 'error' },
      });

      await expect(c.generateUrl(signed)).resolves.toBe('javascript://alert(1)/user_123');
    });

    it('rejects a host outside the allowlist even with a valid signature', async () => {
      const c = new LinkSealCore();
      await c.setPublicKey(PUBLIC_KEY_PEM);
      c.setAllowedHosts(['api.example.com']);
      c.setVariables({ userId: 'user_123' });
      const signed = await signCustom({
        version: '1.0',
        template: 'https://evil.com/users/{userId}',
        policy: { missing: 'error' },
      });

      await expect(c.generateUrl(signed)).rejects.toThrow(/Untrusted URL host 'evil.com'/);
    });

    it('accepts a host inside the allowlist', async () => {
      const c = new LinkSealCore();
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
      const c = new LinkSealCore();
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
      const c = new LinkSealCore();
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

      await expect(c.generateUrl(signed)).rejects.toThrow(/Protocol expired/);
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

      await expect(c.generateUrl(signed)).rejects.toThrow(/Malformed expiresAt/);
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

      await expect(c.generateUrl(signed)).rejects.toThrow(/Malformed expiresAt/);
    });
  });

  describe('key rotation (kid)', () => {
    // The expiring-rotated example was signed by the JS signer with kid="test-key-1".
    // Verifying it here AND in the Java SDK pins cross-language byte agreement for the new fields.
    it('verifies the committed expiring-rotated signature under the registered kid', async () => {
      const v = new SignatureVerifier();
      await v.setPublicKey(expiring.signedProtocol.payload.kid!, expiring.publicKey);
      expect(await v.verify(expiring.signedProtocol.payload, expiring.signedProtocol.signature)).toBe(true);
    });

    it('generates the URL from the expiring-rotated example using the kid key', async () => {
      const c = new LinkSealCore();
      await c.setPublicKey(expiring.signedProtocol.payload.kid!, expiring.publicKey);
      c.setVariables({ userId: 'user_123', token: 'sess_abc', locale: 'en-US' });

      expect(await c.generateUrl(expiring.signedProtocol)).toBe(EXPECTED_URL);
    });

    it('throws when the kid has no registered key', async () => {
      const c = new LinkSealCore();
      await c.setPublicKey(PUBLIC_KEY_PEM); // default key only, no kid registered
      c.setVariables({ userId: 'user_123', token: 'sess_abc', locale: 'en-US' });

      await expect(c.generateUrl(expiring.signedProtocol)).rejects.toThrow(/test-key-1/);
    });
  });
});
