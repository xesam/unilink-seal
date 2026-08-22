import type { PolicyConfig } from 'linkseal';

export class PolicyProcessor {
  process(
    variables: Record<string, string | null>,
    config: PolicyConfig
  ): { result: Record<string, string>; missing: string[] } {
    const defaults = config.defaults ?? {};
    const result: Record<string, string> = {};
    const missing: string[] = [];

    for (const [key, value] of Object.entries(variables)) {
      if (value !== null && value !== undefined) {
        result[key] = value;
      } else if (config.missing === 'default' && defaults[key] !== undefined) {
        result[key] = defaults[key];
      } else {
        missing.push(key);
      }
    }

    return { result, missing };
  }

  applyMissingPolicy(
    variables: Record<string, string | null>,
    config: PolicyConfig
  ): { result: Record<string, string>; error?: { code: string; message: string } } {
    const { result, missing } = this.process(variables, config);

    if (config.missing === 'error' && missing.length > 0) {
      return {
        result,
        error: {
          code: 'MISSING_VARIABLE',
          message: `Missing required variables: ${missing.join(', ')}`,
        },
      };
    }

    return { result };
  }
}
