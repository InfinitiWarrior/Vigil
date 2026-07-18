import type { RateLimitStore, SessionData, SessionStore } from "@vigil/core";

/**
 * Deliberately minimal so this package has no hard dependency on ioredis or
 * node-redis — pass in whichever instance the app already manages
 * (connection pooling, cluster mode, auth, etc. stay the caller's
 * responsibility, mirroring connect-redis's approach for Express).
 *
 * Unlike `get`/`del`/`expire`, `set` isn't satisfied by either client's raw
 * method as-is when `ttlSeconds` is given: neither ioredis's
 * `set(key, value, "EX", seconds)` nor node-redis v4's
 * `set(key, value, { EX: seconds })` matches `set(key, value, ttlSeconds)`
 * positionally. Pass a thin wrapper instead of the raw client, e.g. for
 * ioredis: `(key, value, ttl) => ttl ? redis.set(key, value, "EX", ttl) : redis.set(key, value)`;
 * for node-redis v4: `(key, value, ttl) => redis.set(key, value, ttl ? { EX: ttl } : undefined)`.
 * The wrapper must set the value and expiry atomically — that's what keeps
 * a freshly created session from ever existing in Redis with no TTL.
 *
 * `sadd`/`srem`/`smembers` are optional — only needed for
 * `listByUser()`/`destroyAllForUser()` ("sign out everywhere"). ioredis
 * exposes them as-is (`sadd`/`srem`/`smembers`); node-redis v4 uses
 * camelCase (`sAdd`/`sRem`/`sMembers`) and needs the same kind of thin
 * wrapper as `set`.
 */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds?: number): Promise<unknown>;
  del(key: string): Promise<unknown>;
  expire(key: string, seconds: number): Promise<unknown>;
  sadd?(key: string, member: string): Promise<unknown>;
  srem?(key: string, member: string): Promise<unknown>;
  smembers?(key: string): Promise<string[]>;
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

  /** Key of the Redis set indexing every session ID belonging to `subject`,
   * used by `listByUser()`/`destroyAllForUser()`. */
  private userKey(subject: unknown): string {
    return `${this.prefix}by-user:${JSON.stringify(subject)}`;
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
    await this.client.set(this.key(sessionId), JSON.stringify(data), ttl);
    await this.client.sadd?.(this.userKey(data.subject), sessionId);
  }

  async destroy(sessionId: string): Promise<void> {
    const existing = await this.get(sessionId);
    await this.client.del(this.key(sessionId));
    if (existing) await this.client.srem?.(this.userKey(existing.subject), sessionId);
  }

  async touch(sessionId: string, ttl: number): Promise<void> {
    await this.client.expire(this.key(sessionId), ttl);
  }

  async listByUser(subject: unknown): Promise<string[]> {
    if (!this.client.smembers) {
      throw new Error("RedisSessionStore.listByUser() requires a client that implements `smembers`");
    }
    return this.client.smembers(this.userKey(subject));
  }

  async destroyAllForUser(subject: unknown): Promise<void> {
    const sessionIds = await this.listByUser(subject);
    for (const sessionId of sessionIds) {
      await this.client.del(this.key(sessionId));
    }
    await this.client.del(this.userKey(subject));
  }
}

export function createRedisSessionStore(client: RedisLike, options?: RedisSessionStoreOptions): SessionStore {
  return new RedisSessionStore(client, options);
}

/**
 * Unlike `RedisLike`, `incr`/`expire`/`ttl` are all single-word commands
 * that ioredis and node-redis v4 both expose under the same lowercase name,
 * so a raw client instance satisfies this as-is with no wrapper needed.
 */
export interface RedisRateLimitClient {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  ttl(key: string): Promise<number>;
}

export interface RedisRateLimitStoreOptions {
  /** Defaults to `"vigil:ratelimit:"`. */
  prefix?: string;
}

/**
 * Redis-backed fixed-window rate limit store, for deployments running more
 * than one process (`MemoryRateLimitStore` only counts within a single
 * process). `INCR` then, only on the first hit in a window, `EXPIRE` isn't
 * perfectly atomic — a crash between the two leaves a counter that never
 * expires — but unlike the same race in session storage, this fails closed
 * (a key gets stuck rate-limited, not stuck authenticated), which is the
 * safe direction for this kind of bug.
 */
export class RedisRateLimitStore implements RateLimitStore {
  private readonly client: RedisRateLimitClient;
  private readonly prefix: string;

  constructor(client: RedisRateLimitClient, options: RedisRateLimitStoreOptions = {}) {
    this.client = client;
    this.prefix = options.prefix ?? "vigil:ratelimit:";
  }

  async increment(key: string, windowSeconds: number): Promise<{ count: number; resetAt: number }> {
    const fullKey = `${this.prefix}${key}`;
    const count = await this.client.incr(fullKey);

    if (count === 1) {
      await this.client.expire(fullKey, windowSeconds);
      return { count, resetAt: Date.now() + windowSeconds * 1000 };
    }

    const ttl = await this.client.ttl(fullKey);
    return { count, resetAt: Date.now() + Math.max(ttl, 0) * 1000 };
  }
}

export function createRedisRateLimitStore(
  client: RedisRateLimitClient,
  options?: RedisRateLimitStoreOptions,
): RateLimitStore {
  return new RedisRateLimitStore(client, options);
}
