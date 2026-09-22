/**
 * Extracts scheme and host from a URL string — replaces `new URL(url)`.
 *
 * LinkSealCore.assertTrustedUrl only needs the scheme (minus trailing ':')
 * and the hostname (without port), both lower-cased to match WHATWG URL
 * normalization. Inlined so the resolver core does not depend on the global
 * `URL` constructor, which is unavailable in mini-program runtimes.
 *
 * A URL without an authority (no `//` after the scheme, e.g. `mailto:` or
 * `https:evil.com/x`) yields an empty host — mirroring Java's `URI.getHost()`
 * returning null — so both SDKs reject it identically whenever a host
 * allowlist is configured.
 */

import { TrustError } from '../errors.js';

export interface ParsedSchemeAndHost {
  scheme: string;
  host: string;
}

/** RFC 3986 scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ), lower-cased.
 *  Java's `URI` rejects a malformed scheme; this keeps the JS side equally strict so both
 *  SDKs agree on what counts as "malformed". `+` stays legal for schemes like `web+action:`. */
const SCHEME_SYNTAX = /^[a-z][a-z0-9+.\-]*$/;

export function parseSchemeAndHost(url: string): ParsedSchemeAndHost {
  const colonIdx = url.indexOf(':');
  if (colonIdx === -1) {
    throw new TrustError(`Untrusted URL: malformed or no scheme (${url})`);
  }
  const scheme = url.slice(0, colonIdx).toLowerCase();
  if (!SCHEME_SYNTAX.test(scheme)) {
    throw new TrustError(`Untrusted URL: malformed scheme '${scheme}' (${url})`);
  }

  // No authority (no `//`) → empty host, same as Java's URI.getHost() == null.
  let rest = url.slice(colonIdx + 1);
  if (!rest.startsWith('//')) {
    return { scheme, host: '' };
  }
  rest = rest.slice(2);
  let end = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const ch = rest.charCodeAt(i);
    // '/' = 0x2F, '?' = 0x3F, '#' = 0x23, ':' = 0x3A
    if (ch === 0x2f || ch === 0x3f || ch === 0x23 || ch === 0x3a) {
      end = i;
      break;
    }
  }
  const host = rest.slice(0, end).toLowerCase();
  return { scheme, host };
}
