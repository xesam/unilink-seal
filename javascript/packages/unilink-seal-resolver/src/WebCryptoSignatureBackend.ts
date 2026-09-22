import type { SignatureBackend } from './SignatureBackend.js';
import { utf8Encode } from './shared/utf8.js';

/**
 * Default {@link SignatureBackend} backed by the Web Crypto API (`crypto.subtle`).
 *
 * Works in browsers and Node.js ≥ 18. For runtimes without `crypto.subtle`
 * (e.g. mini-programs), use an alternative backend such as
 * `unilink-seal-crypto-minimal` (backed by `@noble/ed25519`).
 */
export class WebCryptoSignatureBackend implements SignatureBackend {
  private defaultKey: CryptoKey | null = null;
  private readonly keysByKid = new Map<string, CryptoKey>();

  async setPublicKey(keyPem: string): Promise<void>;
  async setPublicKey(kid: string, keyPem: string): Promise<void>;
  async setPublicKey(arg1: string, arg2?: string): Promise<void> {
    const key = await this.importKey(arg2 ?? arg1);
    if (arg2 === undefined) {
      this.defaultKey = key;
    } else {
      this.keysByKid.set(arg1, key);
    }
  }

  async verify(canonicalPayload: string, signatureBase64: string, kid?: string): Promise<boolean> {
    const publicKey = this.selectKey(kid);
    if (!publicKey) {
      throw new Error(kid ? `No public key registered for kid '${kid}'` : 'Public key not set');
    }

    const dataBuffer = utf8Encode(canonicalPayload);
    const signatureBuffer = this.base64ToArrayBuffer(signatureBase64);

    return await crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      signatureBuffer,
      dataBuffer
    );
  }

  private selectKey(kid: string | undefined): CryptoKey | null {
    if (kid !== undefined && kid !== null && kid !== '') {
      return this.keysByKid.get(kid) ?? null;
    }
    return this.defaultKey;
  }

  private async importKey(keyPem: string): Promise<CryptoKey> {
    const keyBuffer = this.pemToArrayBuffer(keyPem);
    return await crypto.subtle.importKey(
      'spki',
      keyBuffer,
      { name: 'Ed25519' },
      true,
      ['verify']
    );
  }

  private pemToArrayBuffer(pem: string): ArrayBuffer {
    const label = 'PUBLIC KEY';
    const begin = `-----BEGIN ${label}-----`;
    const end = `-----END ${label}-----`;
    if (!pem.includes(begin)) {
      const wrongLabel = pem.match(/-----BEGIN ([A-Z ]+)-----/)?.[1];
      if (wrongLabel) {
        throw new Error(
          `Unsupported PEM label '-----BEGIN ${wrongLabel}-----': LinkSeal accepts only ` +
            `PKCS#8 '-----BEGIN ${label}-----' (SPKI).` +
            (wrongLabel.includes('RSA')
              ? ` LinkSeal uses Ed25519; regenerate from the private key with: openssl pkey -in <private.pem> -pubout -out <public.spki.pem>`
              : ``)
        );
      }
      throw new Error(`Missing PEM header '-----BEGIN ${label}-----'`);
    }
    const b64 = pem.replace(begin, '').replace(end, '').replace(/\s/g, '');
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
