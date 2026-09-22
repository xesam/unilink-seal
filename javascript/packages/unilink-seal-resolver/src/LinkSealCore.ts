import type { SignedProtocol } from 'unilink-seal';
import { canonicalizePayload } from 'unilink-seal';
import { TemplateEngine } from './TemplateEngine.js';
import { VariableResolver, type VariableProvider } from './VariableResolver.js';
import { PolicyProcessor } from './PolicyProcessor.js';
import type { SignatureBackend } from './SignatureBackend.js';
import { WebCryptoSignatureBackend } from './WebCryptoSignatureBackend.js';
import { parseSchemeAndHost } from './shared/url-parse.js';
import { VerificationError, ResolutionError, TrustError } from './errors.js';

/**
 * Schemes the resolver will emit by default. Restricted to `https` so a signed template
 * cannot produce a `javascript:`/`http:`/`intent:` URL — the signature only proves the
 * template is un-tampered, not that its scheme is safe to load. Override with
 * `setAllowedSchemes`, or pass the explicit wildcard `['*']` to disable scheme enforcement
 * (tests only).
 */
const DEFAULT_ALLOWED_SCHEMES = ['https'];

/** ISO-8601 instant with an offset or `Z` — the surface Java's `Instant.parse` accepts. */
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export interface LinkSealCoreOptions {
  /**
   * Hosts the resolver is allowed to emit, matched by hostname (without port), lower-cased.
   * **Required** — a signature only proves the template bytes are un-tampered, not that its
   * host is trusted for this resolver, so the trusted-host boundary must be an explicit
   * decision rather than an opt-in. Pass `["*"]` to explicitly opt out of host enforcement.
   * Can be changed later via {@link LinkSealCore.setAllowedHosts}.
   */
  allowedHosts: string[];
  /**
   * Pluggable signature backend. Defaults to {@link WebCryptoSignatureBackend} (Web Crypto
   * API, works in browsers and Node.js ≥ 18). For environments without `crypto.subtle`
   * (e.g. mini-programs), pass an alternative backend such as `MinimalSignatureBackend`
   * from `unilink-seal-crypto-minimal` (backed by `@noble/ed25519`, pure JS).
   */
  signatureBackend?: SignatureBackend;
}

export class LinkSealCore {
  private templateEngine: TemplateEngine;
  private variableResolver: VariableResolver;
  private policyProcessor: PolicyProcessor;
  private signatureBackend: SignatureBackend;
  private allowedSchemes: Set<string> | null = new Set(DEFAULT_ALLOWED_SCHEMES);
  private allowedHosts: Set<string> | null = null;

  constructor(options: LinkSealCoreOptions) {
    if (!options || !Array.isArray(options.allowedHosts) || options.allowedHosts.length === 0) {
      throw new Error(
        "LinkSealCore requires allowedHosts: pass the hosts this resolver may emit " +
          "(e.g. ['api.example.com']), or ['*'] to explicitly disable host enforcement"
      );
    }
    this.templateEngine = new TemplateEngine();
    this.variableResolver = new VariableResolver();
    this.policyProcessor = new PolicyProcessor();
    this.signatureBackend = options.signatureBackend ?? new WebCryptoSignatureBackend();
    this.setAllowedHosts(options.allowedHosts);
  }

  async setPublicKey(keyPem: string): Promise<void>;
  async setPublicKey(kid: string, keyPem: string): Promise<void>;
  async setPublicKey(arg1: string, arg2?: string): Promise<void> {
    if (arg2 === undefined) {
      await this.signatureBackend.setPublicKey(arg1);
    } else {
      await this.signatureBackend.setPublicKey(arg1, arg2);
    }
  }

  setVariables(values: Record<string, string>): void {
    this.variableResolver.setVariables(values);
  }

  /** Clears statically registered variables so the lazy provider takes over for those names. */
  clearVariables(): void {
    this.variableResolver.clearVariables();
  }

  setResolver(provider: VariableProvider | null): void {
    this.variableResolver.setResolver(provider);
  }

  /** Restrict emitted URL schemes (lower-cased). Pass `null` to disable scheme enforcement. */
  /**
   * Restrict emitted URL schemes (lower-cased). Neither {@code null} nor an empty list is
   * accepted: an empty scheme allowlist would make every generateUrl call fail. To disable
   * scheme enforcement, pass the explicit wildcard {@code ['*']}. Throws on null/empty.
   */
  setAllowedSchemes(schemes: string[]): void {
    if (schemes === null || schemes === undefined) {
      throw new Error(
        "setAllowedSchemes does not accept null — pass a scheme list, or ['*'] to explicitly disable scheme enforcement"
      );
    }
    if (schemes.length === 0) {
      throw new Error(
        "setAllowedSchemes does not accept an empty list — an empty scheme allowlist would reject every URL. Pass ['*'] to explicitly disable scheme enforcement"
      );
    }
    const lowered = schemes.map((s) => s.toLowerCase());
    this.allowedSchemes = lowered.includes('*') ? null : new Set(lowered);
  }

  /**
   * Restrict emitted URL hosts (lower-cased, matched by hostname without port). Neither
   * {@code null} nor undefined is accepted — host enforcement is an explicit decision, so
   * the only way to disable it is the explicit wildcard {@code ['*']}. An empty list is
   * valid and rejects every host (fail-closed). The host is checked on the **expanded** URL
   * so a variable filling the host position (e.g. `https://{host}/...`) is covered.
   */
  setAllowedHosts(hosts: string[]): void {
    if (hosts === null || hosts === undefined) {
      throw new Error(
        "setAllowedHosts does not accept null — pass a host list, [] to reject every host, or ['*'] to explicitly disable host enforcement"
      );
    }
    const lowered = hosts.map((h) => h.toLowerCase());
    this.allowedHosts = lowered.includes('*') ? null : new Set(lowered);
  }

  async generateUrl(signedProtocol: SignedProtocol): Promise<string> {
    const { payload, signature } = signedProtocol;

    // Canonicalize once in the core (RFC 8785, pure JS) — the backend only sees bytes.
    const canonical = canonicalizePayload(payload);

    const isValid = await this.signatureBackend.verify(canonical, signature, payload.kid);
    if (!isValid) {
      throw new VerificationError('INVALID_SIGNATURE', 'Protocol signature verification failed');
    }

    this.assertNotExpired(payload.expiresAt);

    const declared = this.templateEngine.variableNames(payload.template);
    const resolved = this.variableResolver.resolve(declared);

    const policyResult = this.policyProcessor.applyMissingPolicy(
      payload.template,
      resolved,
      payload.policy
    );
    if (policyResult.error) {
      throw new ResolutionError(
        policyResult.error.code as any,
        policyResult.error.message
      );
    }

    const url = this.templateEngine.expand(payload.template, policyResult.result);
    this.assertTrustedUrl(url);
    return url;
  }

  /**
   * Defense against a validly-signed-but-untrusted URL: a compromised signer key, a malicious
   * signer, or a lazy provider returning an untrusted host. The signature only covers the
   * template bytes; it says nothing about whether this resolver should trust the resulting
   * scheme/host. Checked on the expanded URL because variables can fill the host position.
   */
  private assertTrustedUrl(url: string): void {
    let parsed: { scheme: string; host: string };
    try {
      parsed = parseSchemeAndHost(url);
    } catch (e) {
      // parseSchemeAndHost throws its own descriptive "Untrusted URL: ..." errors —
      // rethrow those as-is; only an unexpected failure gets the generic wrap.
      if (e instanceof Error && e.message.startsWith('Untrusted URL:')) {
        throw e;
      }
      throw new TrustError(`Untrusted URL: malformed or no scheme (${url})`);
    }
    const { scheme, host } = parsed;
    if (this.allowedSchemes && !this.allowedSchemes.has(scheme)) {
      throw new TrustError(`Untrusted URL scheme '${scheme}': not in allowed schemes`);
    }
    if (this.allowedHosts) {
      if (!this.allowedHosts.has(host)) {
        throw new TrustError(`Untrusted URL host '${host}': not in allowed hosts`);
      }
    }
  }

  /** Rejects a payload past its `expiresAt`. Checked after verify so only signed expiry claims
   *  are honored — an attacker can't strip expiry without invalidating the signature.
   *  Accepts only ISO-8601 instants with an offset or `Z` — the same surface Java's
   *  `Instant.parse` accepts — so a bare date/local-time string is rejected on both ends rather
   *  than accepted by JS's lenient `Date.parse` and rejected by Java. */
  private assertNotExpired(expiresAt: string | undefined): void {
    if (!expiresAt) {
      return;
    }
    if (!ISO_INSTANT.test(expiresAt)) {
      throw new VerificationError('MALFORMED_EXPIRES_AT', `Malformed expiresAt: '${expiresAt}'`);
    }
    const expiryMs = Date.parse(expiresAt);
    if (Number.isNaN(expiryMs)) {
      throw new VerificationError('MALFORMED_EXPIRES_AT', `Malformed expiresAt: '${expiresAt}'`);
    }
    if (Date.now() > expiryMs) {
      throw new VerificationError('PROTOCOL_EXPIRED', `Protocol expired at ${expiresAt}`);
    }
  }
}
