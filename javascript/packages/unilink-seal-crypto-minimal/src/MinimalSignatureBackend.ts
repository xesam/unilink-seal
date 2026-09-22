import type { SignatureBackend } from 'unilink-seal-resolver';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

// Wire the synchronous SHA-512 into noble/ed25519 so `ed.verify` (sync) works.
// Both packages are pure JS with zero platform API dependency — no `crypto.subtle`,
// `atob`, `TextEncoder`, `new URL`, or `Buffer` — so this backend runs in environments
// such as WeChat / Alipay / ByteDance mini-programs.
ed.hashes.sha512 = sha512;

/**
 * Minimal {@link SignatureBackend} backed by [`@noble/ed25519`](https://github.com/paulmillr/noble-curves)
 * (Ed25519 verification) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (SHA-512).
 *
 * This backend has **zero platform API dependencies** — it does not use
 * `crypto.subtle`, `atob`, `TextEncoder`, `new URL`, `Buffer`, `window`,
 * `navigator`, or any other browser/Node.js API. It is designed for
 * environments where none of these are available, such as WeChat / Alipay /
 * ByteDance mini-programs.
 *
 * Only Ed25519 verification is supported, which is the algorithm used by the
 * UniLink Seal protocol. Signing is intentionally not implemented — the signer
 * runs on the server.
 *
 * @example
 * ```ts
 * import { LinkSealCore } from 'unilink-seal-resolver';
 * import { MinimalSignatureBackend } from 'unilink-seal-crypto-minimal';
 *
 * const resolver = new LinkSealCore({
 *   allowedHosts: ['api.example.com'],
 *   signatureBackend: new MinimalSignatureBackend(),
 * });
 * await resolver.setPublicKey(publicKeyPem);
 * ```
 */
export class MinimalSignatureBackend implements SignatureBackend {
  private defaultKey: Uint8Array | null = null;
  private readonly keysByKid = new Map<string, Uint8Array>();

  async setPublicKey(keyPem: string): Promise<void>;
  async setPublicKey(kid: string, keyPem: string): Promise<void>;
  async setPublicKey(arg1: string, arg2?: string): Promise<void> {
    const key = parseSpkiEd25519PublicKey(arg2 ?? arg1);
    if (arg2 !== undefined) {
      this.keysByKid.set(arg1, key);
    } else {
      this.defaultKey = key;
    }
  }

  async verify(canonicalPayload: string, signatureBase64: string, kid?: string): Promise<boolean> {
    const publicKey = this.selectKey(kid);
    if (!publicKey) {
      throw new Error(kid ? `No public key registered for kid '${kid}'` : 'Public key not set');
    }

    try {
      const signature = base64ToBytes(signatureBase64);
      if (signature.length !== 64) return false;
      const message = utf8Encode(canonicalPayload);
      return ed.verify(signature, message, publicKey);
    } catch {
      // Any decode/crypto error means the signature is invalid
      return false;
    }
  }

  private selectKey(kid: string | undefined): Uint8Array | null {
    if (kid !== undefined && kid !== null && kid !== '') {
      return this.keysByKid.get(kid) ?? null;
    }
    return this.defaultKey;
  }
}

// ---------------------------------------------------------------------------
// SPKI / DER parsing (Ed25519)
// ---------------------------------------------------------------------------

/**
 * Parse a PEM-encoded SubjectPublicKeyInfo (SPKI) Ed25519 public key and extract
 * the 32-byte raw public key.
 *
 * Ed25519 SPKI structure:
 * ```
 * SEQUENCE {
 *   SEQUENCE { OID 1.3.101.112 }        -- AlgorithmIdentifier (Ed25519, no params)
 *   BIT STRING { 0x00, <32 bytes> }      -- unused-bits byte + raw public key
 * }
 * ```
 * This is a minimal DER parser that navigates the fixed SPKI structure — it is
 * not a general-purpose ASN.1 parser.
 */
function parseSpkiEd25519PublicKey(pem: string): Uint8Array {
  const der = pemToDer(pem);

  // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
  const outer = readTlv(der, 0);

  // Skip AlgorithmIdentifier (SEQUENCE containing the Ed25519 OID).
  const algo = readTlv(outer.value, 0);
  if (!validateEd25519AlgorithmIdentifier(algo.value)) {
    throw new Error('SPKI AlgorithmIdentifier is not Ed25519 (OID 1.3.101.112)');
  }

  // BIT STRING containing the raw public key.
  const bitString = readTlv(outer.value, algo.next);
  if (bitString.tag !== 0x03) {
    throw new Error('Expected BIT STRING in SubjectPublicKeyInfo');
  }
  // First byte of BIT STRING value is the count of unused bits (must be 0).
  if (bitString.value.length < 1 || bitString.value[0] !== 0x00) {
    throw new Error('Unexpected BIT STRING unused-bits byte in Ed25519 public key');
  }
  const publicKey = bitString.value.subarray(1);
  if (publicKey.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKey.length}`);
  }
  return new Uint8Array(publicKey);
}

/**
 * Validate that an AlgorithmIdentifier body is the Ed25519 OID (1.3.101.112)
 * with no NULL params. The OID DER-encodes as `06 03 2b 65 70`.
 */
function validateEd25519AlgorithmIdentifier(algoBody: Uint8Array): boolean {
  // SEQUENCE { OID 06 03 2b 65 70 [, NULL] }
  const oid = readTlv(algoBody, 0);
  const ED25519_OID = Uint8Array.from([0x2b, 0x65, 0x70]);
  return (
    oid.tag === 0x06 &&
    oid.value.length === ED25519_OID.length &&
    oid.value.every((b, i) => b === ED25519_OID[i])
  );
}

/** Result of reading a single DER Tag-Length-Value element. */
interface Tlv {
  tag: number;
  value: Uint8Array;
  next: number;
}

/** Read a DER Tag-Length-Value at the given offset. */
function readTlv(bytes: Uint8Array, offset: number): Tlv {
  if (offset + 1 >= bytes.length) {
    throw new Error('Unexpected end of DER data');
  }
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let headerSize = 2;

  if (length & 0x80) {
    const numLengthBytes = length & 0x7f;
    if (numLengthBytes === 0 || offset + 2 + numLengthBytes > bytes.length) {
      throw new Error('Invalid DER length encoding');
    }
    length = 0;
    for (let i = 0; i < numLengthBytes; i++) {
      length = (length << 8) | bytes[offset + 2 + i];
    }
    headerSize = 2 + numLengthBytes;
  }

  const valueStart = offset + headerSize;
  const valueEnd = valueStart + length;
  if (valueEnd > bytes.length) {
    throw new Error('DER value extends beyond buffer');
  }

  return { tag, value: bytes.subarray(valueStart, valueEnd), next: valueEnd };
}

// ---------------------------------------------------------------------------
// Base64 / hex / byte utilities (pure JS, no atob/btoa/Buffer)
// ---------------------------------------------------------------------------

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < B64_CHARS.length; i++) {
  B64_LOOKUP[B64_CHARS.charCodeAt(i)] = i;
}

/** Decode a base64 string to a Uint8Array (pure JS, no atob). */
function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    const a = b64CharAt(clean, i);
    const b = b64CharAt(clean, i + 1);
    const c = b64CharAt(clean, i + 2);
    const d = b64CharAt(clean, i + 3);

    if (a < 0 || b < 0) break;
    bytes.push((a << 2) | (b >> 4));
    if (c >= 0 && c !== 64) {
      bytes.push(((b & 0x0f) << 4) | (c >> 2));
      if (d >= 0 && d !== 64) {
        bytes.push(((c & 0x03) << 6) | d);
      }
    }
  }
  return new Uint8Array(bytes);
}

function b64CharAt(str: string, index: number): number {
  if (index >= str.length) return -1;
  const ch = str.charCodeAt(index);
  if (ch === 61 /* '=' */) return 64; // padding marker
  return B64_LOOKUP[ch];
}

// ---------------------------------------------------------------------------
// PEM decoding
// ---------------------------------------------------------------------------

/** Strip PEM headers/footers and decode base64 body to a Uint8Array. */
function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, '')
    .replace(/-----END [A-Z ]+-----/g, '')
    .replace(/\s/g, '');
  if (!b64) {
    throw new Error('Empty PEM data');
  }
  return base64ToBytes(b64);
}

// ---------------------------------------------------------------------------
// UTF-8 encoding (pure JS, no TextEncoder)
// ---------------------------------------------------------------------------

/** Encode a string to UTF-8 bytes without `TextEncoder` (mini-program safe). */
function utf8Encode(str: string): Uint8Array {
  const tmp: number[] = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code < 0x80) {
      tmp.push(code);
    } else if (code < 0x800) {
      tmp.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code >= 0xd800 && code <= 0xdbff) {
      // High surrogate — combine with the next low surrogate
      code = 0x10000 + ((code - 0xd800) << 10) + (str.charCodeAt(++i) - 0xdc00);
      tmp.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    } else {
      tmp.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  const bytes = new Uint8Array(tmp.length);
  for (let i = 0; i < tmp.length; i++) {
    bytes[i] = tmp[i];
  }
  return bytes;
}
