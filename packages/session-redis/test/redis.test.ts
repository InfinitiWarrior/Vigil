import { describe, expect, it, vi } from "vitest";
import type { SessionData } from "@vigil/core";
import { RedisSessionStore, type RedisLike } from "@vigil/session-redis";

/** Minimal in-memory stand-in for ioredis/node-redis, just enough to exercise
 * RedisSessionStore's serialization and TTL-forwarding logic without a real server. */
class FakeRedis implements RedisLike {
  private readonly data = new Map<string, { value: string; expiresAt: number | null }>();

  async get(key: string): Promise<string | null> {
    const entry = this.data.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt < Date.now()) {
      this.data.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string): Promise<unknown> {
    const existing = this.data.get(key);
    this.data.set(key, { value, expiresAt: existing?.expiresAt ?? null });
    return "OK";
  }

  async del(key: string): Promise<unknown> {
    return this.data.delete(key) ? 1 : 0;
  }

  async expire(key: string, seconds: number): Promise<unknown> {
    const entry = this.data.get(key);
    if (!entry) return 0;
    entry.expiresAt = Date.now() + seconds * 1000;
    return 1;
  }

  size(): number {
    return this.data.size;
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

  it("forwards the ttl to the client's expire call", async () => {
    const redis = new FakeRedis();
    const expireSpy = vi.spyOn(redis, "expire");
    const store = new RedisSessionStore(redis);

    await store.set("sess-1", sessionData({ userId: "1" }), 60);
    expect(expireSpy).toHaveBeenCalledWith("vigil:session:sess-1", 60);
  });

  it("does not call expire when no ttl is given", async () => {
    const redis = new FakeRedis();
    const expireSpy = vi.spyOn(redis, "expire");
    const store = new RedisSessionStore(redis);

    await store.set("sess-1", sessionData({ userId: "1" }));
    expect(expireSpy).not.toHaveBeenCalled();
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
});
