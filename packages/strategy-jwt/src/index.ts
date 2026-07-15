import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import type { AuthResult, Strategy, VigilRequest } from "@vigil/core";

export type ExtractFrom = "header" | "cookie" | "query" | ((request: VigilRequest) => string | undefined);

export interface JwtStrategyOptions<TUser> {
  /** HMAC secret. Ignored if `jwksUri` is provided (use it for asymmetric algorithms instead). */
  secret?: string | Uint8Array;
  /** Remote JWKS endpoint, used for asymmetric algorithms with key rotation. */
  jwksUri?: string;
  /** Explicit allowlist. `"none"` can never appear here — jose's verifier rejects it unconditionally. */
  algorithms: string[];
  issuer?: string;
  audience?: string;
  clockTolerance?: number | string;
  extractFrom?: ExtractFrom;
  headerName?: string;
  cookieName?: string;
  queryName?: string;
  verify(payload: JWTPayload): Promise<AuthResult<TUser>>;
}

function extractToken(request: VigilRequest, options: JwtStrategyOptions<unknown>): string | undefined {
  const mode = options.extractFrom ?? "header";

  if (typeof mode === "function") return mode(request);

  if (mode === "header") {
    const headerName = (options.headerName ?? "authorization").toLowerCase();
    const raw = request.headers[headerName];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (!value) return undefined;
    const match = /^Bearer\s+(.+)$/i.exec(value);
    return match?.[1];
  }

  if (mode === "cookie") {
    return request.cookies[options.cookieName ?? "token"];
  }

  const raw = request.query[options.queryName ?? "token"];
  return Array.isArray(raw) ? raw[0] : raw;
}

export class JwtStrategy<TUser = unknown> implements Strategy<TUser> {
  readonly name = "jwt";

  private readonly options: JwtStrategyOptions<TUser>;
  private readonly hmacKey?: Uint8Array;
  private readonly jwksKey?: JWTVerifyGetKey;

  constructor(options: JwtStrategyOptions<TUser>) {
    this.options = options;

    if (options.jwksUri) {
      this.jwksKey = createRemoteJWKSet(new URL(options.jwksUri));
    } else if (options.secret) {
      this.hmacKey = typeof options.secret === "string" ? new TextEncoder().encode(options.secret) : options.secret;
    } else {
      throw new Error("JwtStrategy requires either `secret` or `jwksUri`");
    }
  }

  async authenticate(request: VigilRequest<TUser>): Promise<AuthResult<TUser>> {
    const token = extractToken(request, this.options);
    if (!token) {
      return { success: false, reason: "No token provided", status: 401 };
    }

    const verifyOptions = {
      algorithms: this.options.algorithms,
      issuer: this.options.issuer,
      audience: this.options.audience,
      clockTolerance: this.options.clockTolerance,
    };

    let payload: JWTPayload;
    try {
      const result = this.jwksKey
        ? await jwtVerify(token, this.jwksKey, verifyOptions)
        : await jwtVerify(token, this.hmacKey!, verifyOptions);
      payload = result.payload;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Invalid token";
      const expired = /exp/i.test(message) || (err as { code?: string })?.code === "ERR_JWT_EXPIRED";
      return { success: false, reason: expired ? "Token expired" : message, status: 401 };
    }

    return this.options.verify(payload);
  }
}
