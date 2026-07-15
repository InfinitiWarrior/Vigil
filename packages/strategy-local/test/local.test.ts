import { describe, expect, it } from "vitest";
import { LocalStrategy } from "@vigil/strategy-local";

const baseRequest = {
  method: "POST",
  url: "/login",
  path: "/login",
  headers: {},
  cookies: {},
  query: {},
} as const;

describe("LocalStrategy", () => {
  it("calls verify with the extracted credentials", async () => {
    const strategy = new LocalStrategy({
      verify: async (username, password) => {
        if (username === "alice@example.com" && password === "hunter2") {
          return { success: true, user: { id: "1" } };
        }
        return { success: false, reason: "Invalid credentials" };
      },
    });

    const result = await strategy.authenticate({
      ...baseRequest,
      body: { username: "alice@example.com", password: "hunter2" },
    });
    expect(result).toEqual({ success: true, user: { id: "1" } });
  });

  it("rejects with 400 when fields are missing", async () => {
    const strategy = new LocalStrategy({ verify: async () => ({ success: true, user: {} }) });
    const result = await strategy.authenticate({ ...baseRequest, body: {} });
    expect(result).toMatchObject({ success: false, status: 400 });
  });

  it("supports custom field names", async () => {
    const strategy = new LocalStrategy({
      usernameField: "email",
      passwordField: "pass",
      verify: async (u, p) => ({ success: true, user: { id: u, pass: p } }),
    });
    const result = await strategy.authenticate({
      ...baseRequest,
      body: { email: "bob@example.com", pass: "secret" },
    });
    expect(result).toEqual({ success: true, user: { id: "bob@example.com", pass: "secret" } });
  });
});
