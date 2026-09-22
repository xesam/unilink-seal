import type { PolicyConfig } from 'unilink-seal';
import { ResolutionError } from './errors.js';

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
    template: string,
    variables: Record<string, string | null>,
    config: PolicyConfig
  ): { result: Record<string, string>; error?: { code: string; message: string } } {
    const { result, missing } = this.process(variables, config);

    if (missing.length > 0) {
      if (config.missing === 'error') {
        return {
          result,
          error: {
            code: 'MISSING_VARIABLE',
            message: `Missing required variables: ${missing.join(', ')}`,
          },
        };
      }

      if (config.missing === 'ignore') {
        // Check if any missing variable is in a path segment
        const pathSegmentVars = this.extractPathSegmentVariables(template);
        const missingInPath = missing.filter(v => pathSegmentVars.has(v));

        if (missingInPath.length > 0) {
          return {
            result,
            error: {
              code: 'INVALID_TEMPLATE',
              message: `Policy "ignore" is unsafe for path-segment variables [${missingInPath.join(', ')}]. Use "error" or "default" policy for path variables.`,
            },
          };
        }
      }
    }

    return { result };
  }

  /**
   * Extracts variable names that appear in path segments (not in query parts).
   * Path segment variables are those in {var} expressions before the '?' query separator
   * and not using query operators {?...} or {&...}.
   */
  private extractPathSegmentVariables(template: string): Set<string> {
    const pathVars = new Set<string>();

    // Split at '?' to get path part only
    const [pathPart] = template.split('?');

    const varPattern = /\{([^}]+)\}/g;
    let match: RegExpExecArray | null;

    while ((match = varPattern.exec(pathPart)) !== null) {
      const expression = match[1];

      // Skip query operators
      if (expression.startsWith('?') || expression.startsWith('&')) {
        continue;
      }

      // Handle comma-separated variable lists (e.g., {x,y,z})
      const varNames = expression.split(',');
      for (const varName of varNames) {
        pathVars.add(varName.trim());
      }
    }

    return pathVars;
  }
}
