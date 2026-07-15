import { describe, expect, it } from "vitest";
import { generateApiKey, generateToken, hashPassword, hmac, timingSafeEqual, verifyPassword } from "@vigil/core";

describe("crypto", () => {
  it("generates hex tokens of the requested byte length", () => {
    const token = generateToken(16);
    expect(token).toMatch(/^[0-9a-f]{32}$/);
  });

  it("generates base64url tokens without padding characters", () => {
    const token = generateToken(16, "base64url");
    expect(token).not.toMatch(/[+/=]/);
  });

  it("generates prefixed api keys", () => {
    const key = generateApiKey("vgl_live");
    expect(key.startsWith("vgl_live_")).toBe(true);
  });

  it("hmacs deterministically and detects tampering", () => {
    const a = hmac("sha256", "secret", "data");
    const b = hmac("sha256", "secret", "data");
    expect(a).toBe(b);
    expect(hmac("sha256", "secret", "other")).not.toBe(a);
  });

  it("compares strings in constant time", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
  });

  it("hashes and verifies passwords with argon2id", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(hash.startsWith("$argon2id$")).toBe(true);
    expect(await verifyPassword(hash, "correct horse battery staple")).toBe(true);
    expect(await verifyPassword(hash, "wrong password")).toBe(false);
  });
});
