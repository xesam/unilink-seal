export type VariableProvider = (name: string) => string | null;

export class VariableResolver {
  private variables: Record<string, string> = {};
  private provider: VariableProvider | null = null;

  setVariables(values: Record<string, string>): void {
    this.variables = { ...this.variables, ...values };
  }

  /** Clears statically registered variables so the provider takes over for those names again.
   *  Use when a previously registered value (e.g. a stale token) must stop shadowing the lazy
   *  provider. setVariables merges and never removes, so this is the only way to unset. */
  clearVariables(): void {
    this.variables = {};
  }

  setResolver(provider: VariableProvider | null): void {
    this.provider = provider;
  }

  // Registered values win; the provider is only consulted for names they don't cover.
  resolveOne(name: string): string | null {
    const value = this.variables[name];
    if (value !== undefined && value !== null) {
      return value;
    }
    return this.provider ? this.provider(name) ?? null : null;
  }

  /** Unresolved names stay as null so PolicyProcessor can detect them. */
  resolve(names: readonly string[]): Record<string, string | null> {
    const resolved: Record<string, string | null> = {};
    for (const name of names) {
      resolved[name] = this.resolveOne(name);
    }
    return resolved;
  }
}
