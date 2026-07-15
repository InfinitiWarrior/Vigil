import {
  randomBytes,
  createHmac,
  timingSafeEqual as nodeTimingSafeEqual,
} from "node:crypto";

/**
 * Argon2id is an optional dependency (`@node-rs/argon2`). The core engine
 * itself has zero runtime dependencies; this is the one place that reaches
 * for a hashing library, and it's loaded lazily so `hashPassword` /
 * `verifyPassword` are the only functions that require it to be installed.
 */
async function loadArgon2() {
  try {
    return await import("@node-rs/argon2");
  } catch {
    throw new Error(
      "Password hashing requires the optional dependency '@node-rs/argon2'. " +
        "Install it with: npm install @node-rs/argon2",
    );
  }
}

/** `@node-rs/argon2`'s `Algorithm` is an ambient const enum, which isolatedModules
 * forbids referencing across module boundaries — so Argon2id's raw value (2) is
 * passed directly instead of `argon2.Algorithm.Argon2id`. */
const ARGON2ID = 2;

export async function hashPassword(plaintext: string): Promise<string> {
  const argon2 = await loadArgon2();
  return argon2.hash(plaintext, { algorithm: ARGON2ID });
}

export async function verifyPassword(hash: string, plaintext: string): Promise<boolean> {
  const argon2 = await loadArgon2();
  return argon2.verify(hash, plaintext);
}

export type TokenEncoding = "hex" | "base64url";

export function generateToken(bytes = 32, encoding: TokenEncoding = "hex"): string {
  return randomBytes(bytes).toString(encoding === "base64url" ? "base64url" : "hex");
}

export function generateApiKey(prefix = "vgl"): string {
  return `${prefix}_${generateToken(24, "base64url")}`;
}

export function hmac(algorithm: string, secret: string, data: string): string {
  return createHmac(algorithm, secret).update(data).digest("hex");
}

export function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Still run a comparison of equal-length buffers so this branch isn't
    // trivially distinguishable by timing from the equal-length case.
    nodeTimingSafeEqual(bufA, bufA);
    return false;
  }
  return nodeTimingSafeEqual(bufA, bufB);
}

export const crypto = {
  hashPassword,
  verifyPassword,
  generateToken,
  generateApiKey,
  hmac,
  timingSafeEqual,
};
