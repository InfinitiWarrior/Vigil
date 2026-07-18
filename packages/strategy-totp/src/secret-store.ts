export interface TotpSecretStore {
  get(userId: string): Promise<string | null>;
  save(userId: string, secret: string): Promise<void>;
  /** Returns the time-step index of the last code successfully verified for
   * this user, or `null` if none has been used yet. Used to reject a
   * replayed code within the drift window (RFC 6238 §5.2) — without this, a
   * shoulder-surfed or logged code stays valid for as long as it remains
   * inside the window. */
  getLastUsedStep(userId: string): Promise<number | null>;
  /** Persists the time-step index of a successfully verified code. */
  setLastUsedStep(userId: string, step: number): Promise<void>;
}

/** In-memory secret store for local development and tests. TOTP secrets are
 * long-lived second-factor credentials — production deployments must
 * implement TotpSecretStore against a real database. */
export class MemoryTotpSecretStore implements TotpSecretStore {
  private readonly secrets = new Map<string, string>();
  private readonly lastUsedSteps = new Map<string, number>();

  async get(userId: string): Promise<string | null> {
    return this.secrets.get(userId) ?? null;
  }

  async save(userId: string, secret: string): Promise<void> {
    this.secrets.set(userId, secret);
  }

  async getLastUsedStep(userId: string): Promise<number | null> {
    return this.lastUsedSteps.get(userId) ?? null;
  }

  async setLastUsedStep(userId: string, step: number): Promise<void> {
    this.lastUsedSteps.set(userId, step);
  }
}
