import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { MinimalSignatureBackend } from '../MinimalSignatureBackend.js';
import { WebCryptoSignatureBackend, type SignatureBackend } from 'unilink-seal-resolver';
import { canonicalizePayload } from 'unilink-seal';
import { ProtocolSigner } from 'unilink-seal-signer';
import type { LinkSealProtocol, SignedProtocol } from 'unilink-seal';

// --- spec fixtures ---

const spec = JSON.parse(
  readFileSync(new URL('../../../../../spec/examples/user-profile.signed.json', import.meta.url), 'utf8'),
) as { publicKey: string; signedProtocol: SignedProtocol };

const expiring = JSON.parse(
  readFileSync(new URL('../../../../../spec/examples/expiring-rotated.signed.json', import.meta.url), 'utf8'),
) as { publicKey: string; signedProtocol: SignedProtocol };

const PRIVATE_KEY_PEM = readFileSync(
  new URL('../../../../../spec/keys/test-private.pem', import.meta.url),
  'utf8',
);

const PUBLIC_KEY_PEM = spec.publicKey;

const SPEC_PAYLOAD = spec.signedProtocol.payload;
const SPEC_SIGNATURE = spec.signedProtocol.signature;
const SPEC_CANONICAL = canonicalizePayload(SPEC_PAYLOAD);

const EXPIRING_PAYLOAD = expiring.signedProtocol.payload;
const EXPIRING_SIGNATURE = expiring.signedProtocol.signature;
const EXPIRING_CANONICAL = canonicalizePayload(EXPIRING_PAYLOAD);
const EXPIRING_KID = EXPIRING_PAYLOAD.kid!;

// --- helpers ---

async function minimalBackend(): Promise<MinimalSignatureBackend> {
  const b = new MinimalSignatureBackend();
  await b.setPublicKey(PUBLIC_KEY_PEM);
  return b;
}

async function signCustom(payload: LinkSealProtocol): Promise<SignedProtocol> {
  const signer = new ProtocolSigner();
  await signer.setPrivateKey(PRIVATE_KEY_PEM);
  return signer.signProtocol(payload);
}

// --- MinimalSignatureBackend unit tests ---

describe('MinimalSignatureBackend', () => {
  it('throws when verifying without setting a public key', async () => {
    const b = new MinimalSignatureBackend();
    await expect(b.verify(SPEC_CANONICAL, 'AAA')).rejects.toThrow('Public key not set');
  });

  it('accepts the spec signature for the spec payload', async () => {
    expect(await (await minimalBackend()).verify(SPEC_CANONICAL, SPEC_SIGNATURE)).toBe(true);
  });

  it('rejects a malformed signature', async () => {
    expect(await (await minimalBackend()).verify(SPEC_CANONICAL, 'AAAA')).toBe(false);
  });

  it('rejects an empty signature', async () => {
    expect(await (await minimalBackend()).verify(SPEC_CANONICAL, '')).toBe(false);
  });

  it('rejects a tampered payload', async () => {
    const tampered = canonicalizePayload({ ...SPEC_PAYLOAD, template: 'https://evil.com/{userId}' });
    expect(await (await minimalBackend()).verify(tampered, SPEC_SIGNATURE)).toBe(false);
  });

  it('rejects a tampered signature', async () => {
    // Ed25519 signatures are 64 bytes → 88 base64 chars; tamper at a position inside the string.
    const pos = 10;
    const tamperedSig =
      SPEC_SIGNATURE.slice(0, pos) +
      (SPEC_SIGNATURE[pos] === 'A' ? 'B' : 'A') +
      SPEC_SIGNATURE.slice(pos + 1);
    expect(await (await minimalBackend()).verify(SPEC_CANONICAL, tamperedSig)).toBe(false);
  });

  it('supports kid-based key selection', async () => {
    const b = new MinimalSignatureBackend();
    await b.setPublicKey(EXPIRING_KID, expiring.publicKey);
    expect(await b.verify(EXPIRING_CANONICAL, EXPIRING_SIGNATURE, EXPIRING_KID)).toBe(true);
  });

  it('throws when kid is set but no key registered for it', async () => {
    const b = new MinimalSignatureBackend();
    await b.setPublicKey(PUBLIC_KEY_PEM);
    await expect(b.verify(SPEC_CANONICAL, SPEC_SIGNATURE, 'unknown-kid')).rejects.toThrow(
      "No public key registered for kid 'unknown-kid'",
    );
  });

  it('accepts a dynamically-signed payload', async () => {
    const payload: LinkSealProtocol = {
      version: '1.0',
      template: 'https://test.example.com/path/{id}',
      policy: { missing: 'error' },
    };
    const signed = await signCustom(payload);
    const canonical = canonicalizePayload(signed.payload);
    expect(await (await minimalBackend()).verify(canonical, signed.signature)).toBe(true);
  });

  it('verifies a non-ASCII (UTF-8) payload', async () => {
    const payload: LinkSealProtocol = {
      version: '1.0',
      template: 'https://example.com/用户/{id}',
      policy: { missing: 'error' },
    };
    const signed = await signCustom(payload);
    const canonical = canonicalizePayload(signed.payload);
    expect(await (await minimalBackend()).verify(canonical, signed.signature)).toBe(true);
  });
});

// --- cross-backend consistency ---

describe('Cross-backend consistency (Minimal / WebCrypto)', () => {
  const backends: { name: string; create: () => SignatureBackend }[] = [
    { name: 'Minimal', create: () => new MinimalSignatureBackend() },
    { name: 'WebCrypto', create: () => new WebCryptoSignatureBackend() },
  ];

  for (const { name, create } of backends) {
    describe(`${name} backend`, () => {
      it('accepts the spec signature', async () => {
        const b = create();
        await b.setPublicKey(PUBLIC_KEY_PEM);
        expect(await b.verify(SPEC_CANONICAL, SPEC_SIGNATURE)).toBe(true);
      });

      it('accepts the expiring-rotated signature', async () => {
        const b = create();
        await b.setPublicKey(EXPIRING_KID, expiring.publicKey);
        expect(await b.verify(EXPIRING_CANONICAL, EXPIRING_SIGNATURE, EXPIRING_KID)).toBe(true);
      });

      it('rejects a tampered payload', async () => {
        const b = create();
        await b.setPublicKey(PUBLIC_KEY_PEM);
        const tampered = canonicalizePayload({ ...SPEC_PAYLOAD, template: 'https://evil.com/{userId}' });
        expect(await b.verify(tampered, SPEC_SIGNATURE)).toBe(false);
      });

      it('rejects a tampered signature', async () => {
        const b = create();
        await b.setPublicKey(PUBLIC_KEY_PEM);
        const pos = 10;
        const tamperedSig =
          SPEC_SIGNATURE.slice(0, pos) +
          (SPEC_SIGNATURE[pos] === 'A' ? 'B' : 'A') +
          SPEC_SIGNATURE.slice(pos + 1);
        expect(await b.verify(SPEC_CANONICAL, tamperedSig)).toBe(false);
      });

      it('accepts a dynamically-signed payload', async () => {
        const payload: LinkSealProtocol = {
          version: '1.0',
          template: 'https://cross.example.com/users/{userId}{?token,locale}',
          policy: { missing: 'error' },
        };
        const signed = await signCustom(payload);
        const canonical = canonicalizePayload(signed.payload);

        const b = create();
        await b.setPublicKey(PUBLIC_KEY_PEM);
        expect(await b.verify(canonical, signed.signature)).toBe(true);
      });
    });
  }
});
