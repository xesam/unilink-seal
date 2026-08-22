import { describe, it, expect } from 'vitest';
import { canonicalizePayload } from '../canonicalize.js';

describe('canonicalizePayload', () => {
  it('sorts object keys alphabetically', () => {
    expect(canonicalizePayload({ c: 3, a: 1, b: 2 })).toBe('{"a":1,"b":2,"c":3}');
  });

  it('sorts nested object keys recursively', () => {
    expect(canonicalizePayload({ b: { z: 1, a: 2 }, a: { y: 3, b: 4 } })).toBe(
      '{"a":{"b":4,"y":3},"b":{"a":2,"z":1}}'
    );
  });

  it('serializes nested policy contents', () => {
    const result = canonicalizePayload({
      version: '1.0',
      template: 'https://api.example.com/users/{userId}{?token}',
      policy: { missing: 'error' },
    });
    expect(result).toBe(
      '{"policy":{"missing":"error"},' +
        '"template":"https://api.example.com/users/{userId}{?token}","version":"1.0"}'
    );
  });

  it('distinguishes payloads that differ only in template', () => {
    const base = {
      version: '1.0',
      template: 'https://x.com/u/{userId}',
      policy: { missing: 'error' },
    };
    const tampered = { ...base, template: 'https://evil.com/u/{userId}' };
    expect(canonicalizePayload(base)).not.toBe(canonicalizePayload(tampered));
  });

  it('distinguishes payloads that differ only inside policy', () => {
    const base = {
      version: '1.0',
      template: 'https://x.com/u/{userId}',
      policy: { missing: 'error' },
    };
    const tampered = { ...base, policy: { missing: 'ignore' } };
    expect(canonicalizePayload(base)).not.toBe(canonicalizePayload(tampered));
  });

  it('distinguishes payloads that differ only in policy defaults', () => {
    const base = {
      version: '1.0',
      template: 'https://x.com/u/{userId}',
      policy: { missing: 'default', defaults: { userId: 'anon' } },
    };
    const tampered = { ...base, policy: { missing: 'default', defaults: { userId: 'admin' } } };
    expect(canonicalizePayload(base)).not.toBe(canonicalizePayload(tampered));
  });

  it('is independent of key insertion order', () => {
    const a = { version: '1.0', policy: { missing: 'error' }, template: 'https://x.com/{a}' };
    const b = { template: 'https://x.com/{a}', version: '1.0', policy: { missing: 'error' } };
    expect(canonicalizePayload(a)).toBe(canonicalizePayload(b));
  });

  it('serializes arrays and primitives', () => {
    expect(canonicalizePayload({ a: [1, 'x', true, null] })).toBe('{"a":[1,"x",true,null]}');
  });

  it('escapes quotes and backslashes', () => {
    expect(canonicalizePayload({ a: 'he said "hi"' })).toBe('{"a":"he said \\"hi\\""}');
    expect(canonicalizePayload({ a: 'a\\b' })).toBe('{"a":"a\\\\b"}');
  });

  it('escapes control characters', () => {
    expect(canonicalizePayload({ a: '\n\t' })).toBe('{"a":"\\n\\t"}');
    expect(canonicalizePayload({ a: String.fromCharCode(1) })).toBe('{"a":"\\u0001"}');
  });

  it('omits undefined values', () => {
    expect(canonicalizePayload({ a: '1', b: undefined })).toBe('{"a":"1"}');
  });

  it('handles empty objects', () => {
    expect(canonicalizePayload({})).toBe('{}');
  });

  it('rejects non-finite numbers', () => {
    expect(() => canonicalizePayload({ a: Infinity })).toThrow('Infinity is not allowed');
    expect(() => canonicalizePayload({ a: NaN })).toThrow('NaN is not allowed');
  });
});
