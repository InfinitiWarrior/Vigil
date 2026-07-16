import type { CookieOptions } from "@vigil/core";

export function parseCookieHeader(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!header) return cookies;

  for (const pair of header.split(";")) {
    const index = pair.indexOf("=");
    if (index < 0) continue;
    const key = pair.slice(0, index).trim();
    const value = pair.slice(index + 1).trim();
    if (!key) continue;
    try {
      cookies[key] = decodeURIComponent(value);
    } catch {
      cookies[key] = value;
    }
  }
  return cookies;
}

/** Fastify has no built-in cookie serialization without the @fastify/cookie
 * plugin, so Set-Cookie strings are built by hand here (RFC 6265's Max-Age
 * is in seconds, matching core's CookieOptions unit — no conversion needed). */
export function serializeCookie(name: string, value: string, options?: CookieOptions): string {
  const segments = [`${name}=${encodeURIComponent(value)}`];

  segments.push(`Path=${options?.path ?? "/"}`);
  if (options?.domain) segments.push(`Domain=${options.domain}`);
  if (options?.maxAge !== undefined) segments.push(`Max-Age=${Math.floor(options.maxAge)}`);
  if (options?.httpOnly) segments.push("HttpOnly");
  if (options?.secure) segments.push("Secure");
  if (options?.sameSite) {
    const value = options.sameSite;
    segments.push(`SameSite=${value.charAt(0).toUpperCase()}${value.slice(1)}`);
  }

  return segments.join("; ");
}
