export interface MagicLinkTokenData {
  identifier: string;
  createdAt: number;
}

export interface MagicLinkTokenStore {
  set(tokenHash: string, data: MagicLinkTokenData, ttlSeconds?: number): Promise<void>;
  /** Reads and deletes the entry in one step, enforcing single use. */
  consume(tokenHash: string): Promise<MagicLinkTokenData | null>;
}

/** In-memory token store. Fine for local development, tests, and
 * single-process deployments; state is lost on restart and isn't shared
 * across processes, so multi-instance production deployments should
 * implement MagicLinkTokenStore against Redis or similar. */
export class MemoryMagicLinkTokenStore implements MagicLinkTokenStore {
  private readonly data = new Map<string, { value: MagicLinkTokenData; expiresAt: number }>();

  async set(tokenHash: string, value: MagicLinkTokenData, ttlSeconds = 600): Promise<void> {
    this.data.set(tokenHash, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async consume(tokenHash: string): Promise<MagicLinkTokenData | null> {
    const entry = this.data.get(tokenHash);
    this.data.delete(tokenHash);
    if (!entry) return null;
    if (entry.expiresAt < Date.now()) return null;
    return entry.value;
  }
}

export function createMemoryMagicLinkTokenStore(): MagicLinkTokenStore {
  return new MemoryMagicLinkTokenStore();
}
