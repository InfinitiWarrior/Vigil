import { describe, expect, it, vi } from "vitest";
import type { SessionData } from "@vigil/core";
import {
  RedisRateLimitStore,
  RedisSessionStore,
  type RedisLike,
  type RedisRateLimitClient,
} from "@vigil/session-redis";

/** Minimal in-memory stand-in for ioredis/node-redis, just enough to exercise
 * RedisSessionStore's serialization, TTL-forwarding, and set-indexing logic
 * without a real server. */
class FakeRedis implements RedisLike {
  private readonly data = new Map<string, { value: string; expiresAt: number | null }>();
  private readonly sets = new Map<string, Set<string>>();

  async get(key: string): Promise<string | null> {
    const entry = this.data.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt < Date.now()) {
      this.data.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<unknown> {
    this.data.set(key, { value, expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null });
    return "OK";
  }

  async del(key: string): Promise<unknown> {
    this.sets.delete(key);
    return this.data.delete(key) ? 1 : 0;
  }

  async expire(key: string, seconds: number): Promise<unknown> {
    const entry = this.data.get(key);
    if (!entry) return 0;
    entry.expiresAt = Date.now() + seconds * 1000;
    return 1;
  }

  async sadd(key: string, member: string): Promise<unknown> {
    const set = this.sets.get(key) ?? new Set();
    set.add(member);
    this.sets.set(key, set);
    return 1;
  }

  async srem(key: string, member: string): Promise<unknown> {
    return this.sets.get(key)?.delete(member) ? 1 : 0;
  }

  async smembers(key: string): Promise<string[]> {
    return [...(this.sets.get(key) ?? [])];
  }

  size(): number {
    return this.data.size;
  }
}

/** Minimal in-memory stand-in for a rate-limit-capable Redis client
 * (incr/expire/ttl — all satisfied as-is by real ioredis/node-redis clients). */
class FakeRateLimitRedis implements RedisRateLimitClient {
  private readonly counters = new Map<string, { count: number; expiresAt: number | null }>();

  async incr(key: string): Promise<number> {
    const entry = this.counters.get(key);
    if (!entry || (entry.expiresAt !== null && entry.expiresAt < Date.now())) {
      this.counters.set(key, { count: 1, expiresAt: null });
      return 1;
    }
    entry.count += 1;
    return entry.count;
  }

  async expire(key: string, seconds: number): Promise<unknown> {
    const entry = this.counters.get(key);
    if (!entry) return 0;
    entry.expiresAt = Date.now() + seconds * 1000;
    return 1;
  }

  async ttl(key: string): Promise<number> {
    const entry = this.counters.get(key);
    if (!entry || entry.expiresAt === null) return -1;
    return Math.ceil((entry.expiresAt - Date.now()) / 1000);
  }
}

function sessionData(subject: unknown): SessionData {
  return { subject, createdAt: Date.now() };
}

describe("RedisSessionStore", () => {
  it("returns null for a session that was never set", async () => {
    const store = new RedisSessionStore(new FakeRedis());
    expect(await store.get("missing")).toBeNull();
  });

  it("round-trips session data through JSON serialization", async () => {
    const store = new RedisSessionStore(new FakeRedis());
    const data = sessionData({ userId: "1" });

    await store.set("sess-1", data);
    expect(await store.get("sess-1")).toEqual(data);
  });

  it("forwards the ttl to the client's set call atomically, without a separate expire call", async () => {
    const redis = new FakeRedis();
    const setSpy = vi.spyOn(redis, "set");
    const expireSpy = vi.spyOn(redis, "expire");
    const store = new RedisSessionStore(redis);

    await store.set("sess-1", sessionData({ userId: "1" }), 60);
    expect(setSpy).toHaveBeenCalledWith("vigil:session:sess-1", expect.any(String), 60);
    expect(expireSpy).not.toHaveBeenCalled();
  });

  it("omits the ttl argument when none is given", async () => {
    const redis = new FakeRedis();
    const setSpy = vi.spyOn(redis, "set");
    const store = new RedisSessionStore(redis);

    await store.set("sess-1", sessionData({ userId: "1" }));
    expect(setSpy).toHaveBeenCalledWith("vigil:session:sess-1", expect.any(String), undefined);
  });

  it("expires a session once its ttl elapses", async () => {
    vi.useFakeTimers();
    try {
      const store = new RedisSessionStore(new FakeRedis());
      await store.set("sess-1", sessionData({ userId: "1" }), 1);
      expect(await store.get("sess-1")).not.toBeNull();

      vi.advanceTimersByTime(1500);
      expect(await store.get("sess-1")).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("destroys a session", async () => {
    const redis = new FakeRedis();
    const store = new RedisSessionStore(redis);
    await store.set("sess-1", sessionData({ userId: "1" }));

    await store.destroy("sess-1");
    expect(await store.get("sess-1")).toBeNull();
    expect(redis.size()).toBe(0);
  });

  it("renews a session's ttl via touch", async () => {
    const redis = new FakeRedis();
    const expireSpy = vi.spyOn(redis, "expire");
    const store = new RedisSessionStore(redis);
    await store.set("sess-1", sessionData({ userId: "1" }), 30);

    await store.touch("sess-1", 90);
    expect(expireSpy).toHaveBeenLastCalledWith("vigil:session:sess-1", 90);
  });

  it("namespaces keys with a custom prefix", async () => {
    const redis = new FakeRedis();
    const getSpy = vi.spyOn(redis, "get");
    const store = new RedisSessionStore(redis, { prefix: "myapp:sess:" });

    await store.set("sess-1", sessionData({ userId: "1" }));
    await store.get("sess-1");
    expect(getSpy).toHaveBeenCalledWith("myapp:sess:sess-1");
  });

  it("lists and revokes every session for a user", async () => {
    const redis = new FakeRedis();
    const store = new RedisSessionStore(redis);

    await store.set("sess-1", sessionData({ userId: "1" }));
    await store.set("sess-2", sessionData({ userId: "1" }));
    await store.set("sess-3", sessionData({ userId: "2" }));

    const sessions = await store.listByUser({ userId: "1" });
    expect(sessions.sort()).toEqual(["sess-1", "sess-2"]);

    await store.destroyAllForUser({ userId: "1" });
    expect(await store.get("sess-1")).toBeNull();
    expect(await store.get("sess-2")).toBeNull();
    expect(await store.get("sess-3")).not.toBeNull();
  });

  it("throws from listByUser when the client has no smembers support", async () => {
    const bareClient: RedisLike = {
      get: async () => null,
      set: async () => "OK",
      del: async () => 1,
      expire: async () => 1,
    };
    const store = new RedisSessionStore(bareClient);
    await expect(store.listByUser({ userId: "1" })).rejects.toThrow();
  });
});

describe("RedisRateLimitStore", () => {
  it("counts hits within a window and reports the reset time", async () => {
    const client = new FakeRateLimitRedis();
    const store = new RedisRateLimitStore(client);

    const first = await store.increment("1.2.3.4", 60);
    expect(first.count).toBe(1);
    expect(first.resetAt).toBeGreaterThan(Date.now());

    const second = await store.increment("1.2.3.4", 60);
    expect(second.count).toBe(2);
  });

  it("tracks separate keys independently", async () => {
    const client = new FakeRateLimitRedis();
    const store = new RedisRateLimitStore(client);

    await store.increment("a", 60);
    await store.increment("a", 60);
    const b = await store.increment("b", 60);

    expect(b.count).toBe(1);
  });

  it("sets an expiry only on the first hit in a window", async () => {
    const client = new FakeRateLimitRedis();
    const expireSpy = vi.spyOn(client, "expire");
    const store = new RedisRateLimitStore(client);

    await store.increment("1.2.3.4", 60);
    await store.increment("1.2.3.4", 60);

    expect(expireSpy).toHaveBeenCalledTimes(1);
    expect(expireSpy).toHaveBeenCalledWith("vigil:ratelimit:1.2.3.4", 60);
  });

  it("namespaces keys with a custom prefix", async () => {
    const client = new FakeRateLimitRedis();
    const incrSpy = vi.spyOn(client, "incr");
    const store = new RedisRateLimitStore(client, { prefix: "myapp:rl:" });

    await store.increment("1.2.3.4", 60);
    expect(incrSpy).toHaveBeenCalledWith("myapp:rl:1.2.3.4");
  });
});
