import { describe, it, expect, vi } from 'vitest';
import { VariableResolver } from '../VariableResolver.js';

describe('VariableResolver', () => {
  it('has no values before any are registered', () => {
    const resolver = new VariableResolver();
    expect(resolver.resolveOne('userId')).toBeNull();
  });

  it('resolves registered values by placeholder name', () => {
    const resolver = new VariableResolver();
    resolver.setVariables({ userId: 'user_123', token: 'sess_abc' });
    expect(resolver.resolveOne('userId')).toBe('user_123');
    expect(resolver.resolveOne('token')).toBe('sess_abc');
  });

  it('returns null for an unregistered name', () => {
    const resolver = new VariableResolver();
    resolver.setVariables({ userId: 'user_123' });
    expect(resolver.resolveOne('token')).toBeNull();
  });

  it('setVariables merges instead of replacing', () => {
    const resolver = new VariableResolver();
    resolver.setVariables({ userId: 'user_123' });
    resolver.setVariables({ token: 'sess_abc' });
    expect(resolver.resolveOne('userId')).toBe('user_123');
    expect(resolver.resolveOne('token')).toBe('sess_abc');
  });

  it('setVariables overrides an existing value', () => {
    const resolver = new VariableResolver();
    resolver.setVariables({ userId: 'first' });
    resolver.setVariables({ userId: 'second' });
    expect(resolver.resolveOne('userId')).toBe('second');
  });

  it('falls back to the provider when a name is not registered', () => {
    const resolver = new VariableResolver();
    resolver.setResolver((name) => (name === 'token' ? 'fresh_token' : null));
    expect(resolver.resolveOne('token')).toBe('fresh_token');
  });

  // Registered values win, and the provider must not even be consulted for them.
  it('prefers registered values over the provider', () => {
    const provider = vi.fn(() => 'FROM_PROVIDER');
    const resolver = new VariableResolver();
    resolver.setVariables({ userId: 'user_123' });
    resolver.setResolver(provider);

    expect(resolver.resolveOne('userId')).toBe('user_123');
    expect(provider).not.toHaveBeenCalled();
  });

  it('consults the provider only for names the map misses', () => {
    const provider = vi.fn((name: string) => (name === 'token' ? 'fresh' : null));
    const resolver = new VariableResolver();
    resolver.setVariables({ userId: 'user_123' });
    resolver.setResolver(provider);

    resolver.resolve(['userId', 'token']);

    expect(provider).toHaveBeenCalledTimes(1);
    expect(provider).toHaveBeenCalledWith('token');
  });

  it('treats a provider returning null as missing', () => {
    const resolver = new VariableResolver();
    resolver.setResolver(() => null);
    expect(resolver.resolveOne('token')).toBeNull();
  });

  it('setResolver(null) clears a previously registered provider', () => {
    const resolver = new VariableResolver();
    resolver.setResolver(() => 'value');
    resolver.setResolver(null);
    expect(resolver.resolveOne('token')).toBeNull();
  });

  // Unresolved names must survive as null, or PolicyProcessor cannot see them.
  it('resolve keeps unresolved names as null', () => {
    const resolver = new VariableResolver();
    resolver.setVariables({ userId: 'user_123' });

    expect(resolver.resolve(['userId', 'token', 'locale'])).toEqual({
      userId: 'user_123',
      token: null,
      locale: null,
    });
  });

  it('resolve returns an entry for every requested name', () => {
    const resolver = new VariableResolver();
    const result = resolver.resolve(['a', 'b']);
    expect(Object.keys(result)).toEqual(['a', 'b']);
  });

  it('resolve on an empty name list returns an empty map', () => {
    expect(new VariableResolver().resolve([])).toEqual({});
  });
});
