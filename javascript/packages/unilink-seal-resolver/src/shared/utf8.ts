/**
 * Pure-JS UTF-8 encoder — replaces `new TextEncoder().encode(str)`.
 *
 * Used by TemplateEngine (value percent-encoding) and WebCryptoSignatureBackend
 * (canonical payload → bytes for Ed25519 verify). Inlined rather than depending on
 * the global `TextEncoder` so the resolver core has zero platform dependencies
 * beyond the crypto backend itself.
 */
export function utf8Encode(str: string): Uint8Array<ArrayBuffer> {
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
        0x80 | (code & 0x3f)
      );
    } else {
      tmp.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  // Construct via length (not array) so TypeScript infers Uint8Array<ArrayBuffer>,
  // which satisfies BufferSource for crypto.subtle.verify.
  const bytes = new Uint8Array(tmp.length);
  for (let i = 0; i < tmp.length; i++) {
    bytes[i] = tmp[i];
  }
  return bytes;
}
