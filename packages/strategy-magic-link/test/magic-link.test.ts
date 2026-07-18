import { describe, expect, it, vi } from "vitest";
import { MagicLinkStrategy } from "@vigil/strategy-magic-link";

const baseRequest = {
  method: "GET",
  url: "/auth/magic-link",
  path: "/auth/magic-link",
  headers: {},
  cookies: {},
} as const;

function makeStrategy(sendLink: ReturnType<typeof vi.fn>, overrides: Record<string, unknown> = {}) {
  return new MagicLinkStrategy<{ email: string }>({
    buildUrl: (token) => `https://app.example/callback?token=${token}`,
    sendLink,
    verify: async (identifier) => ({ success: true, user: { email: identifier } }),
    ...overrides,
  });
}

describe("MagicLinkStrategy", () => {
  it("sends a token for the requested identifier", async () => {
    const sendLink = vi.fn(async () => {});
    const strategy = makeStrategy(sendLink);

    await strategy.sendToken({ ...baseRequest, method: "POST", query: {}, body: { email: "alice@example.com" } });

    expect(sendLink).toHaveBeenCalledTimes(1);
    const [identifier, url, token] = sendLink.mock.calls[0]!;
    expect(identifier).toBe("alice@example.com");
    expect(url).toBe(`https://app.example/callback?token=${token}`);
    expect(token).toBeTruthy();
  });

  it("throws when the identifier field is missing", async () => {
    const sendLink = vi.fn(async () => {});
    const strategy = makeStrategy(sendLink);
    await expect(strategy.sendToken({ ...baseRequest, method: "POST", query: {}, body: {} })).rejects.toThrow(/email/);
    expect(sendLink).not.toHaveBeenCalled();
  });

  it("authenticates with a token issued by sendToken", async () => {
    const sendLink = vi.fn(async () => {});
    const strategy = makeStrategy(sendLink);
    await strategy.sendToken({ ...baseRequest, method: "POST", query: {}, body: { email: "alice@example.com" } });
    const token = sendLink.mock.calls[0]![2] as string;

    const result = await strategy.authenticate({ ...baseRequest, query: { token }, body: {} });
    expect(result).toEqual({ success: true, user: { email: "alice@example.com" } });
  });

  it("rejects a callback with no token", async () => {
    const strategy = makeStrategy(vi.fn(async () => {}));
    const result = await strategy.authenticate({ ...baseRequest, query: {}, body: {} });
    expect(result).toMatchObject({ success: false, status: 400 });
  });

  it("rejects an unknown token", async () => {
    const strategy = makeStrategy(vi.fn(async () => {}));
    const result = await strategy.authenticate({ ...baseRequest, query: { token: "never-issued" }, body: {} });
    expect(result).toMatchObject({ success: false, reason: "Invalid or expired token", status: 400 });
  });

  it("enforces single use — a token can't be replayed", async () => {
    const sendLink = vi.fn(async () => {});
    const strategy = makeStrategy(sendLink);
    await strategy.sendToken({ ...baseRequest, method: "POST", query: {}, body: { email: "alice@example.com" } });
    const token = sendLink.mock.calls[0]![2] as string;

    const first = await strategy.authenticate({ ...baseRequest, query: { token }, body: {} });
    expect(first).toMatchObject({ success: true });

    const second = await strategy.authenticate({ ...baseRequest, query: { token }, body: {} });
    expect(second).toMatchObject({ success: false, status: 400 });
  });

  it("expires a token once its ttl elapses", async () => {
    vi.useFakeTimers();
    try {
      const sendLink = vi.fn(async () => {});
      const strategy = makeStrategy(sendLink, { tokenTtlSeconds: 1 });
      await strategy.sendToken({ ...baseRequest, method: "POST", query: {}, body: { email: "alice@example.com" } });
      const token = sendLink.mock.calls[0]![2] as string;

      vi.advanceTimersByTime(1500);

      const result = await strategy.authenticate({ ...baseRequest, query: { token }, body: {} });
      expect(result).toMatchObject({ success: false, status: 400 });
    } finally {
      vi.useRealTimers();
    }
  });

  it("uses a custom identifier field", async () => {
    const sendLink = vi.fn(async () => {});
    const strategy = makeStrategy(sendLink, { identifierField: "username" });
    await strategy.sendToken({ ...baseRequest, method: "POST", query: {}, body: { username: "alice" } });
    expect(sendLink.mock.calls[0]![0]).toBe("alice");
  });
});
