import { describe, it, expect } from 'vitest';
import { ProtocolSigner } from '../ProtocolSigner.js';
import type { LinkSealProtocol } from 'unilink-seal';

const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+92Iz1vrAnmEvfhUxRWFJaPXG6Ab6atUnKam4Z/rmt
-----END PRIVATE KEY-----`;

const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5ej5JRGzS94uvAm7LRBLwPMBBxtT7JL4b+U6zAyuzUs=
-----END PUBLIC KEY-----`;

function makePayload(): LinkSealProtocol {
  return {
    version: '1.0',
    template: 'https://api.example.com/users/{userId}{?token}',
    policy: { missing: 'error' },
  };
}

describe('ProtocolSigner', () => {
  it('throws when signing without setting a private key', async () => {
    const signer = new ProtocolSigner();
    await expect(signer.signPayload(makePayload())).rejects.toThrow('Private key not set');
  });

  it('produces a base64 signature', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);
    const signature = await signer.signPayload(makePayload());
    expect(signature).toBeTruthy();
    expect(typeof signature).toBe('string');
    // Should be valid base64
    expect(() => atob(signature)).not.toThrow();
  });

  it('signProtocol returns payload with signature', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);
    const signed = await signer.signProtocol(makePayload());
    expect(signed.payload).toEqual(makePayload());
    expect(signed.signature).toBeTruthy();
  });

  it('produces deterministic signatures for the same payload', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);
    const sig1 = await signer.signPayload(makePayload());
    const sig2 = await signer.signPayload(makePayload());
    expect(sig1).toBe(sig2);
  });

  it('throws on invalid PEM key', async () => {
    const signer = new ProtocolSigner();
    await expect(signer.setPrivateKey('not-a-valid-key')).rejects.toThrow();
  });

  it('signs different payloads differently', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);

    const a = makePayload();
    const b = { ...makePayload(), template: 'https://other.com/{id}' };
    const sigA = await signer.signPayload(a);
    const sigB = await signer.signPayload(b);
    expect(sigA).not.toBe(sigB);
  });

  // Regression: canonicalization once ignored nested keys, so payloads
  // differing only inside policy shared a signature.
  it('signs payloads differing only in policy differently', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);

    const base = await signer.signPayload(makePayload());
    const downgraded = await signer.signPayload({
      ...makePayload(),
      policy: { missing: 'ignore' },
    });
    expect(base).not.toBe(downgraded);
  });

  it('signs payloads differing only in policy defaults differently', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);

    const a = await signer.signPayload({
      ...makePayload(),
      policy: { missing: 'default', defaults: { userId: 'anon' } },
    });
    const b = await signer.signPayload({
      ...makePayload(),
      policy: { missing: 'default', defaults: { userId: 'admin' } },
    });
    expect(a).not.toBe(b);
  });

  it('is insensitive to key insertion order', async () => {
    const signer = new ProtocolSigner();
    await signer.setPrivateKey(PRIVATE_KEY_PEM);

    const base = await signer.signPayload(makePayload());
    const reordered = await signer.signPayload({
      policy: { missing: 'error' },
      template: 'https://api.example.com/users/{userId}{?token}',
      version: '1.0',
    });
    expect(base).toBe(reordered);
  });
});
