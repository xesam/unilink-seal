import { describe, it, expect } from 'vitest';
import { TemplateEngine } from '../TemplateEngine.js';

describe('TemplateEngine', () => {
  it('expands simple variable substitutions', () => {
    const engine = new TemplateEngine();
    const result = engine.expand('https://example.com/users/{userId}', {
      userId: 'user_123',
    });
    expect(result).toBe('https://example.com/users/user_123');
  });

  it('expands multiple simple substitutions', () => {
    const engine = new TemplateEngine();
    const result = engine.expand('/{org}/{repo}/issues/{id}', {
      org: 'myorg',
      repo: 'myrepo',
      id: '42',
    });
    expect(result).toBe('/myorg/myrepo/issues/42');
  });

  it('expands {?} query start operator', () => {
    const engine = new TemplateEngine();
    const result = engine.expand(
      'https://api.example.com/users/{userId}{?token,locale}',
      { userId: 'user_123', token: 'sess_abc', locale: 'en-US' }
    );
    expect(result).toBe('https://api.example.com/users/user_123?token=sess_abc&locale=en-US');
  });

  it('expands {&} query continuation operator', () => {
    const engine = new TemplateEngine();
    const result = engine.expand(
      'https://api.example.com/users/{userId}?source=app{&token,locale}',
      { userId: 'user_123', token: 'sess_abc', locale: 'en-US' }
    );
    expect(result).toBe('https://api.example.com/users/user_123?source=app&token=sess_abc&locale=en-US');
  });

  it('skips missing variables in query expansion', () => {
    const engine = new TemplateEngine();
    const result = engine.expand(
      '/search{?q,page}',
      { q: 'test' }
    );
    expect(result).toBe('/search?q=test');
  });

  it('returns empty string when all query variables are missing', () => {
    const engine = new TemplateEngine();
    const result = engine.expand(
      '/search{?q,page}',
      {}
    );
    expect(result).toBe('/search');
  });

  it('replaces template variable with empty string when missing', () => {
    const engine = new TemplateEngine();
    const result = engine.expand('/users/{id}', {});
    expect(result).toBe('/users/');
  });

  it('handles URL encoding of special characters', () => {
    const engine = new TemplateEngine();
    const result = engine.expand('/search{?q}', { q: 'hello world' });
    expect(result).toBe('/search?q=hello%20world');
  });

  it('handles the spec E2E template', () => {
    const engine = new TemplateEngine();
    const result = engine.expand(
      'https://api.example.com/users/{userId}?source=app{&token,locale}',
      { userId: 'user_123', token: 'sess_abc', locale: 'en-US' }
    );
    expect(result).toBe('https://api.example.com/users/user_123?source=app&token=sess_abc&locale=en-US');
  });

  it('expands comma-joined simple substitution', () => {
    const engine = new TemplateEngine();
    const result = engine.expand('{a,b}', { a: 'foo', b: 'bar' });
    expect(result).toBe('foo,bar');
  });

  describe('rejects unsupported RFC 6570 features', () => {
    const engine = new TemplateEngine();

    it('rejects reserved expansion {+}', () => {
      expect(() => engine.expand('{+path}', { path: '/x' })).toThrow('Unsupported RFC 6570 operator');
    });

    it('rejects fragment expansion {#}', () => {
      expect(() => engine.expand('{#frag}', { frag: 'x' })).toThrow('Unsupported RFC 6570 operator');
    });

    it('rejects label expansion {.}', () => {
      expect(() => engine.expand('{.x}', { x: '1' })).toThrow('Unsupported RFC 6570 operator');
    });

    it('rejects path expansion {/}', () => {
      expect(() => engine.expand('{/x}', { x: '1' })).toThrow('Unsupported RFC 6570 operator');
    });

    it('rejects path-style parameter expansion {;}', () => {
      expect(() => engine.expand('{;x}', { x: '1' })).toThrow('Unsupported RFC 6570 operator');
    });

    it('rejects the explode modifier *', () => {
      expect(() => engine.expand('{?list*}', { list: 'x' })).toThrow('Unsupported modifier');
    });

    it('rejects the prefix modifier :N', () => {
      expect(() => engine.expand('{?x:3}', { x: 'abcdef' })).toThrow('Unsupported modifier');
    });

    it('rejects in variableNames too', () => {
      expect(() => engine.variableNames('{+path}')).toThrow('Unsupported RFC 6570 operator');
    });
  });

  describe('value encoding (strict RFC 3986 unreserved)', () => {
    // Mirrored byte-for-byte by the Java SDK; these expected strings are the parity pin.
    // RFC 3986 unreserved = A-Za-z0-9-._~ passes through; everything else is %XX UTF-8.
    const cases: Array<[string, string]> = [
      ['~', '?q=~'],
      ['(', '?q=%28'],
      [')', '?q=%29'],
      ["'", '?q=%27'],
      ['*', '?q=%2A'],
      ['/', '?q=%2F'],
      ['?', '?q=%3F'],
      ['#', '?q=%23'],
      ['!', '?q=%21'],
      ['$', '?q=%24'],
      ['&', '?q=%26'],
      [',', '?q=%2C'],
      [';', '?q=%3B'],
      ['=', '?q=%3D'],
      [' ', '?q=%20'],
      ['中', '?q=%E4%B8%AD'],
      ['-._~', '?q=-._~'],
      ["a b/c(d)e*f'g", '?q=a%20b%2Fc%28d%29e%2Af%27g'],
    ];

    it.each(cases)('form-style {?q} encodes %j', (value, expected) => {
      expect(new TemplateEngine().expand('/x{?q}', { q: value })).toBe('/x' + expected);
    });

    it('simple expansion {v} uses the same encoder', () => {
      const engine = new TemplateEngine();
      expect(engine.expand('/p/{v}', { v: 'a*b' })).toBe('/p/a%2Ab');
      expect(engine.expand('/p/{v}', { v: 'a~b' })).toBe('/p/a~b');
      expect(engine.expand('/p/{v}', { v: '中' })).toBe('/p/%E4%B8%AD');
    });

    it('encodes a defined empty value as name= (not skipped)', () => {
      expect(new TemplateEngine().expand('/x{?q}', { q: '' })).toBe('/x?q=');
    });
  });

  describe('variableNames', () => {
    it('extracts simple placeholders', () => {
      expect(new TemplateEngine().variableNames('/{org}/{repo}/issues/{id}')).toEqual([
        'org',
        'repo',
        'id',
      ]);
    });

    it('extracts names across query operators', () => {
      expect(
        new TemplateEngine().variableNames(
          'https://api.example.com/users/{userId}?source=app{&token,locale}'
        )
      ).toEqual(['userId', 'token', 'locale']);
    });

    it('extracts names from the query start operator', () => {
      expect(new TemplateEngine().variableNames('/search{?q,page}')).toEqual(['q', 'page']);
    });

    it('returns an empty list for a template with no placeholders', () => {
      expect(new TemplateEngine().variableNames('https://example.com/static')).toEqual([]);
    });

    it('deduplicates a name used more than once', () => {
      expect(new TemplateEngine().variableNames('/{id}/detail/{id}')).toEqual(['id']);
    });

    it('yields exactly the names expand consumes', () => {
      const engine = new TemplateEngine();
      const template = 'https://api.example.com/users/{userId}?source=app{&token,locale}';
      const values = Object.fromEntries(engine.variableNames(template).map((n) => [n, 'x']));

      expect(engine.expand(template, values)).toBe(
        'https://api.example.com/users/x?source=app&token=x&locale=x'
      );
    });
  });
});
