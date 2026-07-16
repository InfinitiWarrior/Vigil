import { createHash } from "node:crypto";
import { generateToken } from "@vigil/core";

/** RFC 7636 recommends 43-128 characters from the unreserved URL-safe set;
 * 32 random bytes base64url-encode to 43 characters, the minimum allowed length. */
export function generateCodeVerifier(): string {
  return generateToken(32, "base64url");
}

export function deriveCodeChallenge(codeVerifier: string): string {
  return createHash("sha256").update(codeVerifier).digest("base64url");
}
