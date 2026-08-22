import type { LinkSealProtocol } from 'linkseal';
import { canonicalizePayload } from 'linkseal';

export class SignatureVerifier {
  private defaultKey: CryptoKey | null = null;
  private readonly keysByKid = new Map<string, CryptoKey>();

  /** Set the default public key, used when a payload carries no `kid`. */
  async setPublicKey(keyPem: string): Promise<void>;
  /** Register a public key under a `kid`, used when a payload carries that `kid`. */
  async setPublicKey(kid: string, keyPem: string): Promise<void>;
  async setPublicKey(arg1: string, arg2?: string): Promise<void> {
    const key = await this.importKey(arg2 ?? arg1);
    if (arg2 === undefined) {
      this.defaultKey = key;
    } else {
      this.keysByKid.set(arg1, key);
    }
  }

  async verify(payload: LinkSealProtocol, signature: string): Promise<boolean> {
    const publicKey = this.selectKey(payload.kid);
    if (!publicKey) {
      throw new Error(
        payload.kid ? `No public key registered for kid '${payload.kid}'` : 'Public key not set'
      );
    }

    const dataBuffer = new TextEncoder().encode(canonicalizePayload(payload));
    const signatureBuffer = this.base64ToArrayBuffer(signature);

    return await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
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
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
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
              ? ` Regenerate from the private key with: openssl rsa -in <private.p8.pem> -pubout -out <public.spki.pem>`
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
