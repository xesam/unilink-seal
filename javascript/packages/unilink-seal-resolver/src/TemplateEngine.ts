/**
 * Expands the LinkSeal-supported subset of RFC 6570 URI templates.
 *
 * Supported expressions (and only these):
 *   {var}   — simple substitution (Level 1), one or more comma-separated names
 *   {?var}  — form-style query start
 *   {&var}  — form-style query continuation
 *
 * Unsupported RFC 6570 operators (+ # . / ;) and modifiers (explode *, prefix :N) are
 * rejected rather than silently mis-expanded, so this SDK accepts and rejects the exact
 * same template grammar as the Java SDK. Variable names are restricted to [A-Za-z0-9_.].
 *
 * Value encoding follows strict RFC 6570, which defers to RFC 3986 "unreserved":
 * the characters A-Za-z0-9-._~ pass through unchanged; every other byte is percent-encoded
 * as its UTF-8 octet. This is hand-rolled (rather than delegating to a library) so both
 * SDKs emit byte-identical output regardless of which URI-charset generation a library
 * froze at — see spec/PROTOCOL.md §4.4 and §5.
 */
import { utf8Encode } from './shared/utf8.js';
import { ResolutionError } from './errors.js';

const ANY_BRACE = /\{([^}]*)\}/g;
const OPERATORS = '+#./;?&';
const VARNAME = /^[A-Za-z0-9_.]+$/;

/** Unbalanced or nested braces make the template invalid — reject rather than emit them
 *  as literals. Both SDKs run this before expression-level validation. */
function assertBracesBalanced(template: string): void {
  let depth = 0;
  for (const ch of template) {
    if (ch === '{') {
      if (depth > 0) {
        throw new ResolutionError('INVALID_TEMPLATE', `Nested '{' in template: ${template}`);
      }
      depth++;
    } else if (ch === '}') {
      if (depth === 0) {
        throw new ResolutionError('INVALID_TEMPLATE', `Unmatched '}' in template: ${template}`);
      }
      depth--;
    }
  }
  if (depth > 0) {
    throw new ResolutionError('INVALID_TEMPLATE', `Unclosed '{' in template: ${template}`);
  }
}

function validateTemplate(template: string): void {
  assertBracesBalanced(template);
  for (const match of template.matchAll(ANY_BRACE)) {
    const expr = match[1];
    let operator = '';
    let bodyStart = 0;
    if (expr.length > 0 && OPERATORS.includes(expr[0])) {
      operator = expr[0];
      bodyStart = 1;
    }
    if (operator !== '' && operator !== '?' && operator !== '&') {
      throw new ResolutionError(
        'UNSUPPORTED_TEMPLATE',
        `Unsupported RFC 6570 operator '{${operator}}' in template: ${template} — LinkSeal supports only {}, {?}, and {&}`
      );
    }
    for (const spec of expr.slice(bodyStart).split(',')) {
      const name = spec;
      if (name === '') {
        throw new ResolutionError('INVALID_TEMPLATE', `Empty variable spec in template: ${template}`);
      }
      if (name.includes('*') || name.includes(':')) {
        throw new ResolutionError(
          'UNSUPPORTED_TEMPLATE',
          `Unsupported modifier in '${name}': explode (*) and prefix (:N) are not supported`
        );
      }
      if (!VARNAME.test(name)) {
        throw new ResolutionError(
          'INVALID_TEMPLATE',
          `Invalid variable name '${name}' in template: ${template}`
        );
      }
    }
  }
}

/** RFC 3986 unreserved (A-Za-z0-9-._~) passes through; all other bytes are %XX UTF-8. */
function encodeValue(value: string): string {
  let out = '';
  for (const byte of utf8Encode(value)) {
    if (
      (byte >= 0x30 && byte <= 0x39) || // 0-9
      (byte >= 0x41 && byte <= 0x5a) || // A-Z
      (byte >= 0x61 && byte <= 0x7a) || // a-z
      byte === 0x2d || // -
      byte === 0x2e || // .
      byte === 0x5f || // _
      byte === 0x7e    // ~
    ) {
      out += String.fromCharCode(byte);
    } else {
      out += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
    }
  }
  return out;
}

export class TemplateEngine {
  expand(template: string, variables: Record<string, string>): string {
    validateTemplate(template);
    let out = '';
    let last = 0;
    for (const match of template.matchAll(ANY_BRACE)) {
      const index = match.index ?? 0;
      out += template.slice(last, index);
      last = index + match[0].length;

      const expr = match[1];
      let operator = '';
      let body = expr;
      if (expr.length > 0 && OPERATORS.includes(expr[0])) {
        operator = expr[0];
        body = expr.slice(1);
      }
      const names = body.split(',');

      if (operator === '?' || operator === '&') {
        const pairs = names
          .filter((name) => variables[name] !== undefined && variables[name] !== null)
          .map((name) => `${name}=${encodeValue(variables[name])}`);
        out += pairs.length ? operator + pairs.join('&') : '';
      } else {
        out += names.map((name) => encodeValue(variables[name] ?? '')).join(',');
      }
    }
    return out + template.slice(last);
  }

  /** Placeholder names declared by the template — the basis for missing-variable detection. */
  variableNames(template: string): string[] {
    validateTemplate(template);
    const names = new Set<string>();
    for (const match of template.matchAll(ANY_BRACE)) {
      const expr = match[1];
      let body = expr;
      if (expr.length > 0 && OPERATORS.includes(expr[0])) {
        body = expr.slice(1);
      }
      for (const spec of body.split(',')) {
        const name = spec;
        if (name) names.add(name);
      }
    }
    return [...names];
  }
}
