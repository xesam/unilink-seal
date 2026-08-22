import type { LinkSealProtocol, SignedProtocol } from 'linkseal';
import { canonicalizePayload } from 'linkseal';

export class ProtocolSigner {
  private privateKey: CryptoKey | null = null;

  async setPrivateKey(keyPem: string): Promise<void> {
    const keyBuffer = pemToArrayBuffer(keyPem, 'PRIVATE KEY');

    this.privateKey = await crypto.subtle.importKey(
      'pkcs8',
      keyBuffer,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );
  }

  async signPayload(payload: LinkSealProtocol): Promise<string> {
    if (!this.privateKey) {
      throw new Error('Private key not set');
    }

    const dataBuffer = new TextEncoder().encode(canonicalizePayload(payload));
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      this.privateKey,
      dataBuffer
    );

    return arrayBufferToBase64(signature);
  }

  async signProtocol(payload: LinkSealProtocol): Promise<SignedProtocol> {
    return {
      payload,
      signature: await this.signPayload(payload),
    };
  }
}

function pemToArrayBuffer(pem: string, label: string): ArrayBuffer {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  if (!pem.includes(begin)) {
    const wrongLabel = pem.match(/-----BEGIN ([A-Z ]+)-----/)?.[1];
    if (wrongLabel) {
      throw new Error(
        `Unsupported PEM label '-----BEGIN ${wrongLabel}-----': LinkSeal accepts only PKCS#8 ` +
          `'-----BEGIN ${label}-----'.` +
          (wrongLabel.includes('RSA')
            ? ` Convert with: openssl pkcs8 -topk8 -nocrypt -in <key> -out <key>.p8.pem`
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

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}
