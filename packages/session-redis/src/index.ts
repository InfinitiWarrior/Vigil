import type { SessionData, SessionStore } from "@vigil/core";

/**
 * Structural subset of ioredis/node-redis both satisfy as-is, so this package
 * has no hard dependency on either client — pass in whichever instance the
 * app already manages (connection pooling, cluster mode, auth, etc. stay the
 * caller's responsibility, mirroring connect-redis's approach for Express).
 */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  del(key: string): Promise<unknown>;
  expire(key: string, seconds: number): Promise<unknown>;
}

export interface RedisSessionStoreOptions {
  /** Defaults to `"vigil:session:"`. */
  prefix?: string;
}

export class RedisSessionStore implements SessionStore {
  private readonly client: RedisLike;
  private readonly prefix: string;

  constructor(client: RedisLike, options: RedisSessionStoreOptions = {}) {
    this.client = client;
    this.prefix = options.prefix ?? "vigil:session:";
  }

  private key(sessionId: string): string {
    return `${this.prefix}${sessionId}`;
  }

  async get(sessionId: string): Promise<SessionData | null> {
    const raw = await this.client.get(this.key(sessionId));
    if (!raw) return null;
    try {
      return JSON.parse(raw) as SessionData;
    } catch {
      return null;
    }
  }

  async set(sessionId: string, data: SessionData, ttl?: number): Promise<void> {
    const key = this.key(sessionId);
    await this.client.set(key, JSON.stringify(data));
    if (ttl) await this.client.expire(key, ttl);
  }

  async destroy(sessionId: string): Promise<void> {
    await this.client.del(this.key(sessionId));
  }

  async touch(sessionId: string, ttl: number): Promise<void> {
    await this.client.expire(this.key(sessionId), ttl);
  }
}

export function createRedisSessionStore(client: RedisLike, options?: RedisSessionStoreOptions): SessionStore {
  return new RedisSessionStore(client, options);
}
