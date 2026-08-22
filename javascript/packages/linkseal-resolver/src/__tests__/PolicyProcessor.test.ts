import { describe, it, expect } from 'vitest';
import { PolicyProcessor } from '../PolicyProcessor.js';
import type { PolicyConfig } from 'linkseal';

describe('PolicyProcessor', () => {
  describe('process', () => {
    it('passes through resolved variables', () => {
      const result = new PolicyProcessor().process({ token: 'abc' }, { missing: 'error' });
      expect(result.result).toEqual({ token: 'abc' });
      expect(result.missing).toEqual([]);
    });

    // Regression: missing was computed from resolved keys only, so it was always empty.
    it('reports null variables as missing', () => {
      const result = new PolicyProcessor().process(
        { userId: 'user_123', token: null },
        { missing: 'error' }
      );
      expect(result.missing).toEqual(['token']);
      expect(result.result).toEqual({ userId: 'user_123' });
    });

    it('fills null variables from defaults in default mode', () => {
      const result = new PolicyProcessor().process(
        { locale: null },
        { missing: 'default', defaults: { locale: 'zh-CN' } }
      );
      expect(result.result).toEqual({ locale: 'zh-CN' });
      expect(result.missing).toEqual([]);
    });

    it('still reports missing when default mode lacks a matching default', () => {
      const result = new PolicyProcessor().process(
        { locale: null, token: null },
        { missing: 'default', defaults: { locale: 'zh-CN' } }
      );
      expect(result.result).toEqual({ locale: 'zh-CN' });
      expect(result.missing).toEqual(['token']);
    });

    it('resolved variables take precedence over defaults', () => {
      const result = new PolicyProcessor().process(
        { locale: 'en-US' },
        { missing: 'default', defaults: { locale: 'zh-CN' } }
      );
      expect(result.result).toEqual({ locale: 'en-US' });
    });

    it('ignores defaults outside of default mode', () => {
      const result = new PolicyProcessor().process(
        { locale: null },
        { missing: 'ignore', defaults: { locale: 'zh-CN' } }
      );
      expect(result.result).toEqual({});
      expect(result.missing).toEqual(['locale']);
    });

    it('does not mutate the supplied config', () => {
      const config: PolicyConfig = { missing: 'error' };
      new PolicyProcessor().process({ token: null }, config);
      expect(config).toEqual({ missing: 'error' });
      expect(config.defaults).toBeUndefined();
    });
  });

  describe('applyMissingPolicy', () => {
    it('error mode reports missing variables', () => {
      const result = new PolicyProcessor().applyMissingPolicy(
        { userId: 'user_123', token: null },
        { missing: 'error' }
      );
      expect(result.error?.code).toBe('MISSING_VARIABLE');
      expect(result.error?.message).toContain('token');
    });

    it('error mode succeeds when all variables resolve', () => {
      const result = new PolicyProcessor().applyMissingPolicy(
        { token: 'abc', locale: 'en' },
        { missing: 'error' }
      );
      expect(result.error).toBeUndefined();
      expect(result.result).toEqual({ token: 'abc', locale: 'en' });
    });

    it('ignore mode omits missing variables without erroring', () => {
      const result = new PolicyProcessor().applyMissingPolicy(
        { userId: 'user_123', token: null },
        { missing: 'ignore' }
      );
      expect(result.error).toBeUndefined();
      expect(result.result).toEqual({ userId: 'user_123' });
    });

    it('default mode uses provided defaults', () => {
      const result = new PolicyProcessor().applyMissingPolicy(
        { theme: 'light', lang: null },
        { missing: 'default', defaults: { theme: 'dark', lang: 'en' } }
      );
      expect(result.error).toBeUndefined();
      expect(result.result).toEqual({ theme: 'light', lang: 'en' });
    });

    it('empty variable set is not an error', () => {
      const result = new PolicyProcessor().applyMissingPolicy({}, { missing: 'error' });
      expect(result.error).toBeUndefined();
      expect(result.result).toEqual({});
    });
  });
});
