import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { base32Decode, base32Encode } from "./base32.js";

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface TotpOptions {
  /** Defaults to 6. */
  digits?: number;
  /** Step size in seconds. Defaults to 30. */
  period?: number;
  /** Accepts codes from this many periods before/after the current one, to tolerate clock drift. Defaults to 1. */
  window?: number;
  /** Defaults to "SHA1" — what Google Authenticator and most authenticator apps assume. */
  algorithm?: TotpAlgorithm;
}

interface ResolvedTotpOptions {
  digits: number;
  period: number;
  window: number;
  algorithm: TotpAlgorithm;
}

const DEFAULTS: ResolvedTotpOptions = { digits: 6, period: 30, window: 1, algorithm: "SHA1" };

/** Callers (TotpStrategy) may pass an options object with explicit
 * `undefined` values for unset fields — plain object spread would let those
 * override the defaults, so each field falls through individually instead. */
function resolve(options: TotpOptions): ResolvedTotpOptions {
  return {
    digits: options.digits ?? DEFAULTS.digits,
    period: options.period ?? DEFAULTS.period,
    window: options.window ?? DEFAULTS.window,
    algorithm: options.algorithm ?? DEFAULTS.algorithm,
  };
}

/** RFC 4226 HOTP. Counter is clamped to zero — only reachable if the system
 * clock is at or before the Unix epoch, but writeBigUInt64BE throws on negatives. */
function hotp(secret: Buffer, counter: bigint, digits: number, algorithm: TotpAlgorithm): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(counter < 0n ? 0n : counter);

  const hmac = createHmac(algorithm.toLowerCase(), secret).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const binCode =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);

  return (binCode % 10 ** digits).toString().padStart(digits, "0");
}

export function generateTotpSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

export function buildOtpauthUrl(
  options: { secret: string; accountName: string; issuer: string } & TotpOptions,
): string {
  const { digits, period, algorithm } = resolve(options);
  const label = encodeURIComponent(`${options.issuer}:${options.accountName}`);
  const params = new URLSearchParams({
    secret: options.secret,
    issuer: options.issuer,
    digits: String(digits),
    period: String(period),
    algorithm,
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

export function generateTotpCode(secret: string, options: TotpOptions = {}): string {
  const { digits, period, algorithm } = resolve(options);
  const counter = BigInt(Math.floor(Date.now() / 1000 / period));
  return hotp(base32Decode(secret), counter, digits, algorithm);
}

/** Like `verifyTotpCode`, but returns the matched time-step index instead of
 * a boolean — callers that need replay protection (RFC 6238 §5.2) persist
 * this alongside the user's secret and reject any future code whose step is
 * at or before the last one accepted. Returns `null` if `code` doesn't match
 * any step in the window. */
export function verifyTotpCodeStep(secret: string, code: string, options: TotpOptions = {}): number | null {
  const { digits, period, window, algorithm } = resolve(options);
  if (code.length !== digits) return null;

  const secretBuffer = base32Decode(secret);
  const counter = BigInt(Math.floor(Date.now() / 1000 / period));
  const codeBuffer = Buffer.from(code);

  for (let drift = -window; drift <= window; drift++) {
    const step = counter + BigInt(drift);
    const candidate = Buffer.from(hotp(secretBuffer, step, digits, algorithm));
    if (candidate.length === codeBuffer.length && timingSafeEqual(candidate, codeBuffer)) return Number(step);
  }
  return null;
}

export function verifyTotpCode(secret: string, code: string, options: TotpOptions = {}): boolean {
  return verifyTotpCodeStep(secret, code, options) !== null;
}
