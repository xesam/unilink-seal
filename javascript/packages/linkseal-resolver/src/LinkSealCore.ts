import type { SignedProtocol } from 'linkseal';
import { TemplateEngine } from './TemplateEngine.js';
import { VariableResolver, type VariableProvider } from './VariableResolver.js';
import { PolicyProcessor } from './PolicyProcessor.js';
import { SignatureVerifier } from './SignatureVerifier.js';

/**
 * Schemes the resolver will emit by default. Restricted to `https` so a signed template
 * cannot produce a `javascript:`/`http:`/`intent:` URL — the signature only proves the
 * template is un-tampered, not that its scheme is safe to load. Override with
 * `setAllowedSchemes`, or pass `null` to disable scheme enforcement (tests only).
 */
const DEFAULT_ALLOWED_SCHEMES = ['https'];

/** ISO-8601 instant with an offset or `Z` — the surface Java's `Instant.parse` accepts. */
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export class LinkSealCore {
  private templateEngine: TemplateEngine;
  private variableResolver: VariableResolver;
  private policyProcessor: PolicyProcessor;
  private signatureVerifier: SignatureVerifier;
  private allowedSchemes: Set<string> | null = new Set(DEFAULT_ALLOWED_SCHEMES);
  private allowedHosts: Set<string> | null = null;

  constructor() {
    this.templateEngine = new TemplateEngine();
    this.variableResolver = new VariableResolver();
    this.policyProcessor = new PolicyProcessor();
    this.signatureVerifier = new SignatureVerifier();
  }

  async setPublicKey(keyPem: string): Promise<void>;
  async setPublicKey(kid: string, keyPem: string): Promise<void>;
  async setPublicKey(arg1: string, arg2?: string): Promise<void> {
    if (arg2 === undefined) {
      await this.signatureVerifier.setPublicKey(arg1);
    } else {
      await this.signatureVerifier.setPublicKey(arg1, arg2);
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
  setAllowedSchemes(schemes: string[] | null): void {
    this.allowedSchemes = schemes === null ? null : new Set(schemes.map((s) => s.toLowerCase()));
  }

  /**
   * Restrict emitted URL hosts (lower-cased, matched by hostname without port). Pass `null`
   * to disable host enforcement (the default). The host is checked on the **expanded** URL so
   * a variable filling the host position (e.g. `https://{host}/...`) is covered.
   */
  setAllowedHosts(hosts: string[] | null): void {
    this.allowedHosts = hosts === null ? null : new Set(hosts.map((h) => h.toLowerCase()));
  }

  async generateUrl(signedProtocol: SignedProtocol): Promise<string> {
    const { payload, signature } = signedProtocol;

    const isValid = await this.signatureVerifier.verify(payload, signature);
    if (!isValid) {
      throw new Error('Protocol signature verification failed');
    }

    this.assertNotExpired(payload.expiresAt);

    const declared = this.templateEngine.variableNames(payload.template);
    const resolved = this.variableResolver.resolve(declared);

    const policyResult = this.policyProcessor.applyMissingPolicy(resolved, payload.policy);
    if (policyResult.error) {
      throw new Error(policyResult.error.message);
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
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error(`Untrusted URL: malformed or no scheme (${url})`);
    }
    // WHATWG URL already lowercases protocol (always trailing ':') and hostname, so no
    // extra lowercasing is needed here — Java's URI does not normalize, so its side must.
    const scheme = parsed.protocol.slice(0, -1);
    if (this.allowedSchemes && !this.allowedSchemes.has(scheme)) {
      throw new Error(`Untrusted URL scheme '${scheme}': not in allowed schemes`);
    }
    if (this.allowedHosts) {
      const host = parsed.hostname;
      if (!this.allowedHosts.has(host)) {
        throw new Error(`Untrusted URL host '${host}': not in allowed hosts`);
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
      throw new Error(`Malformed expiresAt: '${expiresAt}'`);
    }
    const expiryMs = Date.parse(expiresAt);
    if (Number.isNaN(expiryMs)) {
      throw new Error(`Malformed expiresAt: '${expiresAt}'`);
    }
    if (Date.now() > expiryMs) {
      throw new Error(`Protocol expired at ${expiresAt}`);
    }
  }
}
