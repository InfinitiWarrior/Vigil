import { describe, expect, it } from "vitest";
import { SignJWT } from "jose";
import { JwtStrategy } from "@vigil/strategy-jwt";

const secret = "test-secret-test-secret-1234567890";

const baseRequest = {
  method: "GET",
  url: "/",
  path: "/",
  cookies: {},
  query: {},
  body: {},
} as const;

describe("JwtStrategy", () => {
  it("verifies a valid HS256 bearer token", async () => {
    const token = await new SignJWT({ sub: "user-1" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(secret));

    const strategy = new JwtStrategy({
      secret,
      algorithms: ["HS256"],
      verify: async (payload) => ({ success: true, user: { id: payload.sub } }),
    });

    const result = await strategy.authenticate({
      ...baseRequest,
      headers: { authorization: `Bearer ${token}` },
    });
    expect(result).toEqual({ success: true, user: { id: "user-1" } });
  });

  it("rejects when no token is present", async () => {
    const strategy = new JwtStrategy({
      secret,
      algorithms: ["HS256"],
      verify: async () => ({ success: true, user: {} }),
    });
    const result = await strategy.authenticate({ ...baseRequest, headers: {} });
    expect(result).toMatchObject({ success: false, status: 401 });
  });

  it("rejects an expired token", async () => {
    const token = await new SignJWT({ sub: "user-1" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt(0)
      .setExpirationTime(1)
      .sign(new TextEncoder().encode(secret));

    const strategy = new JwtStrategy({
      secret,
      algorithms: ["HS256"],
      verify: async () => ({ success: true, user: {} }),
    });
    const result = await strategy.authenticate({
      ...baseRequest,
      headers: { authorization: `Bearer ${token}` },
    });
    expect(result).toMatchObject({ success: false });
  });

  it("extracts the token from a cookie when configured", async () => {
    const token = await new SignJWT({ sub: "user-2" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(secret));

    const strategy = new JwtStrategy({
      secret,
      algorithms: ["HS256"],
      extractFrom: "cookie",
      cookieName: "token",
      verify: async (payload) => ({ success: true, user: { id: payload.sub } }),
    });

    const result = await strategy.authenticate({ ...baseRequest, headers: {}, cookies: { token } });
    expect(result).toEqual({ success: true, user: { id: "user-2" } });
  });

  it("rejects tokens signed with an algorithm outside the allowlist", async () => {
    const token = await new SignJWT({ sub: "user-1" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(secret));

    const strategy = new JwtStrategy({
      secret,
      algorithms: ["HS512"],
      verify: async () => ({ success: true, user: {} }),
    });
    const result = await strategy.authenticate({
      ...baseRequest,
      headers: { authorization: `Bearer ${token}` },
    });
    expect(result).toMatchObject({ success: false });
  });
});
