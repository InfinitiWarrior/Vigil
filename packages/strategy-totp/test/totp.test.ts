import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TotpStrategy, generateTotpCode, generateTotpSecret, verifyTotpCode } from "@vigil/strategy-totp";

const baseRequest = {
  method: "POST",
  url: "/2fa/verify",
  path: "/2fa/verify",
  headers: {},
  cookies: {},
  query: {},
} as const;

describe("TOTP primitives", () => {
  it("generates a code that verifies against the same secret", () => {
    const secret = generateTotpSecret();
    const code = generateTotpCode(secret);
    expect(verifyTotpCode(secret, code)).toBe(true);
  });

  it("rejects a code generated from a different secret", () => {
    const secretA = generateTotpSecret();
    const secretB = generateTotpSecret();
    const code = generateTotpCode(secretA);
    expect(verifyTotpCode(secretB, code)).toBe(false);
  });

  it("rejects a code of the wrong length", () => {
    const secret = generateTotpSecret();
    expect(verifyTotpCode(secret, "123")).toBe(false);
  });

  it("tolerates clock drift within the window", () => {
    vi.useFakeTimers();
    try {
      const secret = generateTotpSecret();
      vi.setSystemTime(0);
      const code = generateTotpCode(secret);

      vi.setSystemTime(30_000); // one period later
      expect(verifyTotpCode(secret, code, { window: 1 })).toBe(true);

      vi.setSystemTime(90_000); // three periods later, outside window 1
      expect(verifyTotpCode(secret, code, { window: 1 })).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("TotpStrategy", () => {
  let secretStore: Map<string, string>;

  beforeEach(() => {
    secretStore = new Map();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function makeStrategy() {
    return new TotpStrategy<{ id: string }>({
      issuer: "VigilTest",
      secretStore: {
        get: async (userId) => secretStore.get(userId) ?? null,
        save: async (userId, secret) => {
          secretStore.set(userId, secret);
        },
      },
      verify: async (userId) => ({ success: true, user: { id: userId } }),
    });
  }

  it("generates a secret and a matching otpauth URL", () => {
    const strategy = makeStrategy();
    const { secret, otpauthUrl } = strategy.generateSecret("alice@example.com");
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    expect(otpauthUrl).toContain("otpauth://totp/");
    expect(otpauthUrl).toContain(`secret=${secret}`);
    expect(otpauthUrl).toContain("issuer=VigilTest");
  });

  it("confirms setup with a valid code", () => {
    const strategy = makeStrategy();
    const { secret } = strategy.generateSecret("alice@example.com");
    const code = generateTotpCode(secret);
    expect(strategy.verifySetup(secret, code)).toBe(true);
  });

  it("rejects setup confirmation with an invalid code", () => {
    const strategy = makeStrategy();
    const { secret } = strategy.generateSecret("alice@example.com");
    expect(strategy.verifySetup(secret, "000000")).toBe(false);
  });

  it("authenticates a valid second-factor code for the identified user", async () => {
    const strategy = makeStrategy();
    const { secret } = strategy.generateSecret("alice@example.com");
    await secretStore.set("user-1", secret);
    const code = generateTotpCode(secret);

    const result = await strategy.authenticate({
      ...baseRequest,
      user: { id: "user-1" },
      body: { code },
    });
    expect(result).toEqual({ success: true, user: { id: "user-1" } });
  });

  it("rejects when the identified user has no TOTP configured", async () => {
    const strategy = makeStrategy();
    const result = await strategy.authenticate({
      ...baseRequest,
      user: { id: "user-1" },
      body: { code: "123456" },
    });
    expect(result).toMatchObject({ success: false, reason: "TOTP not configured", status: 400 });
  });

  it("rejects when there is no user to identify", async () => {
    const strategy = makeStrategy();
    const result = await strategy.authenticate({ ...baseRequest, user: null, body: { code: "123456" } });
    expect(result).toMatchObject({ success: false, status: 401 });
  });

  it("rejects a missing code", async () => {
    const strategy = makeStrategy();
    secretStore.set("user-1", generateTotpSecret());
    const result = await strategy.authenticate({ ...baseRequest, user: { id: "user-1" }, body: {} });
    expect(result).toMatchObject({ success: false, status: 400 });
  });

  it("rejects an incorrect code", async () => {
    const strategy = makeStrategy();
    const secret = generateTotpSecret();
    secretStore.set("user-1", secret);

    const result = await strategy.authenticate({
      ...baseRequest,
      user: { id: "user-1" },
      body: { code: "000000" },
    });
    expect(result).toMatchObject({ success: false, reason: "Invalid code", status: 401 });
  });

  it("supports a custom identify() hook", async () => {
    const strategy = new TotpStrategy<{ id: string }>({
      issuer: "VigilTest",
      identify: (request) => (request.body as { userId?: string }).userId ?? null,
      secretStore: {
        get: async (userId) => secretStore.get(userId) ?? null,
        save: async (userId, secret) => {
          secretStore.set(userId, secret);
        },
      },
      verify: async (userId) => ({ success: true, user: { id: userId } }),
    });

    const secret = generateTotpSecret();
    secretStore.set("user-2", secret);
    const code = generateTotpCode(secret);

    const result = await strategy.authenticate({
      ...baseRequest,
      user: null,
      body: { userId: "user-2", code },
    });
    expect(result).toEqual({ success: true, user: { id: "user-2" } });
  });
});
