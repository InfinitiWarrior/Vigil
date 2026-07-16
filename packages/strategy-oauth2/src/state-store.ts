export interface OAuthStateData {
  codeVerifier: string;
  redirectUri: string;
  createdAt: number;
}

export interface OAuthStateStore {
  set(state: string, data: OAuthStateData, ttlSeconds?: number): Promise<void>;
  /** Reads and deletes the entry in one step so a state value can't be replayed. */
  consume(state: string): Promise<OAuthStateData | null>;
}

/**
 * In-memory state store. Fine for local development, tests, and single-process
 * deployments; state is lost on restart and isn't shared across processes, so
 * multi-instance production deployments should implement OAuthStateStore
 * against Redis or similar (mirrors core's MemorySessionStore/MemoryRateLimitStore).
 */
export class MemoryOAuthStateStore implements OAuthStateStore {
  private readonly data = new Map<string, { value: OAuthStateData; expiresAt: number }>();

  async set(state: string, value: OAuthStateData, ttlSeconds = 600): Promise<void> {
    this.data.set(state, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async consume(state: string): Promise<OAuthStateData | null> {
    const entry = this.data.get(state);
    this.data.delete(state);
    if (!entry) return null;
    if (entry.expiresAt < Date.now()) return null;
    return entry.value;
  }
}

export function createMemoryOAuthStateStore(): OAuthStateStore {
  return new MemoryOAuthStateStore();
}
