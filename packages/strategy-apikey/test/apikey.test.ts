import { describe, expect, it } from "vitest";
import { ApiKeyStrategy, hashApiKey } from "@vigil/strategy-apikey";

const baseRequest = {
  method: "GET",
  url: "/",
  path: "/",
  cookies: {},
  body: {},
} as const;

describe("ApiKeyStrategy", () => {
  it("authenticates via the default header", async () => {
    const strategy = new ApiKeyStrategy({
      verify: async (key) => {
        if (key !== "vgl_secret123") return { success: false, reason: "Invalid key" };
        return { success: true, user: { id: "owner-1" } };
      },
    });

    const result = await strategy.authenticate({
      ...baseRequest,
      headers: { "x-api-key": "vgl_secret123" },
      query: {},
    });
    expect(result).toEqual({ success: true, user: { id: "owner-1" } });
  });

  it("rejects when no key is present", async () => {
    const strategy = new ApiKeyStrategy({ verify: async () => ({ success: true, user: {} }) });
    const result = await strategy.authenticate({ ...baseRequest, headers: {}, query: {} });
    expect(result).toMatchObject({ success: false, status: 401 });
  });

  it("extracts the key from a custom header name", async () => {
    const strategy = new ApiKeyStrategy({
      headerName: "Authorization-Key",
      verify: async (key) => ({ success: true, user: { key } }),
    });
    const result = await strategy.authenticate({
      ...baseRequest,
      headers: { "authorization-key": "abc" },
      query: {},
    });
    expect(result).toEqual({ success: true, user: { key: "abc" } });
  });

  it("extracts the key from the query string when configured", async () => {
    const strategy = new ApiKeyStrategy({
      extractFrom: "query",
      verify: async (key) => ({ success: true, user: { key } }),
    });
    const result = await strategy.authenticate({
      ...baseRequest,
      headers: {},
      query: { api_key: "xyz" },
    });
    expect(result).toEqual({ success: true, user: { key: "xyz" } });
  });

  it("supports a custom extraction function", async () => {
    const strategy = new ApiKeyStrategy({
      extractFrom: (request) => (request.body as Record<string, string>)["key"],
      verify: async (key) => ({ success: true, user: { key } }),
    });
    const result = await strategy.authenticate({
      ...baseRequest,
      headers: {},
      query: {},
      body: { key: "body-key" },
    });
    expect(result).toEqual({ success: true, user: { key: "body-key" } });
  });

  it("propagates the verify function's failure result", async () => {
    const strategy = new ApiKeyStrategy({
      verify: async () => ({ success: false, reason: "Key revoked", status: 403 }),
    });
    const result = await strategy.authenticate({
      ...baseRequest,
      headers: { "x-api-key": "revoked-key" },
      query: {},
    });
    expect(result).toEqual({ success: false, reason: "Key revoked", status: 403 });
  });
});

describe("hashApiKey", () => {
  it("produces a deterministic sha256 hex digest", () => {
    const hash = hashApiKey("vgl_secret123");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hashApiKey("vgl_secret123")).toBe(hash);
  });

  it("produces different hashes for different keys", () => {
    expect(hashApiKey("key-a")).not.toBe(hashApiKey("key-b"));
  });
});
