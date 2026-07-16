export interface WebAuthnChallengeData {
  /** Which user this challenge was issued for, or `null` for a fully
   * discoverable-credential (passkey) authentication attempt. */
  userId: string | null;
  createdAt: number;
}

export interface WebAuthnChallengeStore {
  set(challenge: string, data: WebAuthnChallengeData, ttlSeconds?: number): Promise<void>;
  /** Reads and deletes the entry in one step, enforcing single use (replay protection). */
  consume(challenge: string): Promise<WebAuthnChallengeData | null>;
}

/** In-memory challenge store. Fine for local development, tests, and
 * single-process deployments; state is lost on restart and isn't shared
 * across processes, so multi-instance production deployments should
 * implement WebAuthnChallengeStore against Redis or similar. */
export class MemoryWebAuthnChallengeStore implements WebAuthnChallengeStore {
  private readonly data = new Map<string, { value: WebAuthnChallengeData; expiresAt: number }>();

  async set(challenge: string, value: WebAuthnChallengeData, ttlSeconds = 300): Promise<void> {
    this.data.set(challenge, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async consume(challenge: string): Promise<WebAuthnChallengeData | null> {
    const entry = this.data.get(challenge);
    this.data.delete(challenge);
    if (!entry) return null;
    if (entry.expiresAt < Date.now()) return null;
    return entry.value;
  }
}
