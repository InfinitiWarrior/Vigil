import type { RateLimitStore, SessionData, SessionStore } from "./types.js";

/**
 * In-memory session store. Fine for local development and tests; state is
 * lost on restart and isn't shared across processes, so production
 * deployments should implement SessionStore against Redis, Postgres, etc.
 */
export class MemorySessionStore implements SessionStore {
  private readonly data = new Map<string, { value: SessionData; expiresAt: number | null }>();
  private readonly byUser = new Map<string, Set<string>>();

  private userKey(subject: unknown): string {
    return JSON.stringify(subject);
  }

  private addToIndex(sessionId: string, subject: unknown): void {
    const key = this.userKey(subject);
    const ids = this.byUser.get(key) ?? new Set();
    ids.add(sessionId);
    this.byUser.set(key, ids);
  }

  private removeFromIndex(sessionId: string, subject: unknown): void {
    const key = this.userKey(subject);
    const ids = this.byUser.get(key);
    if (!ids) return;
    ids.delete(sessionId);
    if (ids.size === 0) this.byUser.delete(key);
  }

  async get(sessionId: string): Promise<SessionData | null> {
    const entry = this.data.get(sessionId);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt < Date.now()) {
      this.removeFromIndex(sessionId, entry.value.subject);
      this.data.delete(sessionId);
      return null;
    }
    return entry.value;
  }

  async set(sessionId: string, value: SessionData, ttl?: number): Promise<void> {
    const existing = this.data.get(sessionId);
    if (existing) this.removeFromIndex(sessionId, existing.value.subject);
    this.data.set(sessionId, {
      value,
      expiresAt: ttl ? Date.now() + ttl * 1000 : null,
    });
    this.addToIndex(sessionId, value.subject);
  }

  async destroy(sessionId: string): Promise<void> {
    const entry = this.data.get(sessionId);
    if (entry) this.removeFromIndex(sessionId, entry.value.subject);
    this.data.delete(sessionId);
  }

  async touch(sessionId: string, ttl: number): Promise<void> {
    const entry = this.data.get(sessionId);
    if (entry) entry.expiresAt = Date.now() + ttl * 1000;
  }

  async listByUser(subject: unknown): Promise<string[]> {
    return [...(this.byUser.get(this.userKey(subject)) ?? [])];
  }

  async destroyAllForUser(subject: unknown): Promise<void> {
    const ids = this.byUser.get(this.userKey(subject));
    if (!ids) return;
    for (const sessionId of [...ids]) {
      this.data.delete(sessionId);
    }
    this.byUser.delete(this.userKey(subject));
  }
}

export function createMemorySessionStore(): SessionStore {
  return new MemorySessionStore();
}

/** In-memory fixed-window rate limit store. Dev/single-process use only. */
export class MemoryRateLimitStore implements RateLimitStore {
  private readonly counters = new Map<string, { count: number; resetAt: number }>();

  async increment(key: string, windowSeconds: number): Promise<{ count: number; resetAt: number }> {
    const now = Date.now();
    const existing = this.counters.get(key);
    if (!existing || existing.resetAt <= now) {
      const resetAt = now + windowSeconds * 1000;
      const entry = { count: 1, resetAt };
      this.counters.set(key, entry);
      return entry;
    }
    existing.count += 1;
    return existing;
  }
}

export function createMemoryRateLimitStore(): RateLimitStore {
  return new MemoryRateLimitStore();
}
