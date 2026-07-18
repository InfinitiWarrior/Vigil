import { AuthError } from "./errors.js";
import { generateToken, timingSafeEqual } from "./crypto.js";
import { MemoryRateLimitStore } from "./stores.js";
import type {
  AuthenticateOptions,
  AuthResult,
  CookieOptions,
  Hooks,
  LogoutOptions,
  RateLimitOptions,
  RequireAuthOptions,
  SessionData,
  Strategy,
  VigilConfig,
  VigilHandler,
  VigilRequest,
  VigilResponse,
} from "./types.js";

const DEFAULT_SESSION_COOKIE = "vigil.sid";
const DEFAULT_CSRF_COOKIE = "vigil.csrf";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Defaults `secure` to whatever the adapter detected on the actual request
 * (TLS, or a trusted `X-Forwarded-Proto: https`) when available, falling
 * back to `NODE_ENV` only if the adapter didn't report it — this way cookies
 * still get `Secure` correctly even if `NODE_ENV` isn't set to
 * `"production"` in a production deployment (a common misconfiguration). */
function defaultCookieOptions(req: VigilRequest<unknown>, overrides?: Partial<CookieOptions>): CookieOptions {
  return {
    httpOnly: true,
    secure: req.secure ?? process.env["NODE_ENV"] === "production",
    sameSite: "lax",
    path: "/",
    ...overrides,
  };
}

export class Vigil<TUser = unknown> {
  private readonly config: VigilConfig<TUser>;
  private readonly strategyMap: Map<string, Strategy<TUser>>;
  private readonly defaultRateLimitStore = new MemoryRateLimitStore();

  constructor(config: VigilConfig<TUser>) {
    this.config = config;
    this.strategyMap = new Map(config.strategies.map((s) => [s.name, s]));
  }

  private get hooks(): Hooks<TUser> {
    return this.config.hooks ?? {};
  }

  private serialize(user: TUser): unknown {
    return this.config.serialize ? this.config.serialize(user) : user;
  }

  private async deserialize(subject: unknown): Promise<TUser | null> {
    if (this.config.deserialize) return this.config.deserialize(subject);
    return subject as TUser;
  }

  /** The session cookie's configured name (`session.cookie.name`, or the
   * `"vigil.sid"` default) — public so adapters that read the cookie
   * outside a normal request/response cycle (e.g. a Next.js Server
   * Component via `next/headers`) know which cookie to look for. */
  sessionCookieName(): string {
    if (this.config.session === false) return DEFAULT_SESSION_COOKIE;
    return this.config.session.cookie?.name ?? DEFAULT_SESSION_COOKIE;
  }

  private sessionCookieOptions(req: VigilRequest<TUser>): CookieOptions {
    if (this.config.session === false) return defaultCookieOptions(req);
    return defaultCookieOptions(req, this.config.session.cookie);
  }

  private sessionMaxAge(): number | undefined {
    if (this.config.session === false) return undefined;
    return this.config.session.cookie?.maxAge;
  }

  /** Loads `req.user` from the session cookie if one is present and no user
   * has already been attached earlier in the pipeline (e.g. by `authenticate`).
   * Renews the session's TTL (sliding expiration) unless `session.rolling`
   * is explicitly `false`. */
  private async loadSessionUser(req: VigilRequest<TUser>): Promise<void> {
    if (req.user !== undefined && req.user !== null) return;
    const sessionConfig = this.config.session;
    if (sessionConfig === false) return;

    const cookieName = this.sessionCookieName();
    const sessionId = req.cookies[cookieName];
    if (!sessionId) return;

    const session = await sessionConfig.store.get(sessionId);
    if (!session) return;

    const maxAge = this.sessionMaxAge();
    if ((sessionConfig.rolling ?? true) && maxAge && sessionConfig.store.touch) {
      await sessionConfig.store.touch(sessionId, maxAge);
    }

    const user = await this.deserialize(session.subject);
    req.sessionId = sessionId;
    req.session = session;
    req.user = user;
  }

  /** Lists the session IDs currently active for `user`. Requires a
   * `SessionStore` that implements `listByUser()` (e.g. `RedisSessionStore`
   * with a client that supports Redis sets). */
  async listSessions(user: TUser): Promise<string[]> {
    const sessionConfig = this.config.session;
    if (sessionConfig === false) return [];
    if (!sessionConfig.store.listByUser) {
      throw new Error("Vigil: the configured SessionStore does not implement listByUser()");
    }
    return sessionConfig.store.listByUser(this.serialize(user));
  }

  /** Destroys every session belonging to `user` — "sign out everywhere."
   * Requires a `SessionStore` that implements `destroyAllForUser()`. */
  async revokeAllSessions(user: TUser): Promise<void> {
    const sessionConfig = this.config.session;
    if (sessionConfig === false) return;
    if (!sessionConfig.store.destroyAllForUser) {
      throw new Error("Vigil: the configured SessionStore does not implement destroyAllForUser()");
    }
    await sessionConfig.store.destroyAllForUser(this.serialize(user));
  }

  /** Resolves the user for a given session ID directly, without a
   * VigilRequest/VigilResponse cycle — for anywhere that has a session ID
   * but no HTTP request/response pair to run through `requireAuth()`, e.g.
   * a Next.js Server Component reading the cookie via `next/headers`, a
   * WebSocket upgrade handler, or building a GraphQL context. Returns
   * `null` if there's no session config, the session doesn't exist, or it
   * has expired. */
  async getUserBySessionId(sessionId: string): Promise<TUser | null> {
    const sessionConfig = this.config.session;
    if (sessionConfig === false) return null;
    const session = await sessionConfig.store.get(sessionId);
    if (!session) return null;
    return this.deserialize(session.subject);
  }

  private resolveStrategies(names: string | string[]): Strategy<TUser>[] {
    const list = Array.isArray(names) ? names : [names];
    return list.map((name) => {
      const strategy = this.strategyMap.get(name);
      if (!strategy) {
        throw new Error(`Vigil: no strategy registered with name "${name}"`);
      }
      return strategy;
    });
  }

  authenticate(strategyNames: string | string[], options: AuthenticateOptions = {}): VigilHandler<TUser> {
    const strategies = this.resolveStrategies(strategyNames);

    return async (req, res, next) => {
      try {
        await this.hooks.onAuthenticate?.(strategies[0]!.name, req);
      } catch (err) {
        next(err);
        return;
      }

      let lastFailure: { reason: string; status?: number } | null = null;

      for (const strategy of strategies) {
        let result: AuthResult<TUser>;
        try {
          result = await strategy.authenticate(req, options);
        } catch (err) {
          const reason = err instanceof Error ? err.message : "Strategy threw an unexpected error";
          await this.hooks.onFailure?.(reason, strategy.name, req);
          next(new AuthError("STRATEGY_ERROR", "Authentication failed", undefined, reason));
          return;
        }

        if ("redirect" in result) {
          res.redirect(result.redirect, result.status ?? 302);
          return;
        }

        if (result.success) {
          await this.hooks.onSuccess?.(result.user, strategy.name, req);
          await this.establishIdentity(req, res, result.user, options);

          if (options.successRedirect) {
            res.redirect(options.successRedirect);
            return;
          }
          next();
          return;
        }

        lastFailure = { reason: result.reason, status: result.status };
        await this.hooks.onFailure?.(result.reason, strategy.name, req);

        if (options.failFast) break;
      }

      const failure = lastFailure ?? { reason: "Authentication failed" };
      if (options.failureRedirect) {
        res.redirect(options.failureRedirect);
        return;
      }
      const publicMessage = options.exposeFailureReason ? failure.reason : "Authentication failed";
      next(new AuthError("UNAUTHENTICATED", publicMessage, failure.status, failure.reason));
    };
  }

  private async establishIdentity(
    req: VigilRequest<TUser>,
    res: VigilResponse,
    user: TUser,
    options: AuthenticateOptions,
  ): Promise<void> {
    req.user = user;

    const session = this.config.session;
    if (options.session === false || session === false) return;

    const sessionId = generateToken(32);
    const maxAge = this.sessionMaxAge();
    const data: SessionData = { subject: this.serialize(user), createdAt: Date.now() };

    await session.store.set(sessionId, data, maxAge);
    res.setCookie(this.sessionCookieName(), sessionId, {
      ...this.sessionCookieOptions(req),
      maxAge,
    });

    req.sessionId = sessionId;
    req.session = data;
  }

  requireAuth(options: RequireAuthOptions = {}): VigilHandler<TUser> {
    return async (req, res, next) => {
      await this.loadSessionUser(req);

      if (req.user) {
        next();
        return;
      }

      if (options.redirectTo) {
        res.redirect(options.redirectTo);
        return;
      }
      next(new AuthError("UNAUTHENTICATED", options.message ?? "Authentication required"));
    };
  }

  optionalAuth(): VigilHandler<TUser> {
    return async (req, _res, next) => {
      await this.loadSessionUser(req);
      req.user = req.user ?? null;
      next();
    };
  }

  authorize(...roles: string[]): VigilHandler<TUser> {
    return async (req, _res, next) => {
      if (!req.user) {
        next(new AuthError("UNAUTHENTICATED", "Authentication required"));
        return;
      }

      const user = req.user as unknown as { role?: string; roles?: string[] };
      const userRoles = user.roles ?? (user.role ? [user.role] : []);
      const authorized = roles.some((role) => userRoles.includes(role));

      if (!authorized) {
        next(new AuthError("FORBIDDEN", "Insufficient permissions"));
        return;
      }
      next();
    };
  }

  logout(options: LogoutOptions = {}): VigilHandler<TUser> {
    return async (req, res, next) => {
      await this.loadSessionUser(req);

      const sessionConfig = this.config.session;
      if (sessionConfig !== false && req.sessionId) {
        await sessionConfig.store.destroy(req.sessionId);
        res.clearCookie(this.sessionCookieName(), this.sessionCookieOptions(req));
      }

      await this.hooks.onLogout?.(req.user ?? null, req);

      req.user = null;
      req.session = null;
      req.sessionId = null;

      if (options.redirectTo) {
        res.redirect(options.redirectTo);
        return;
      }
      next();
    };
  }

  csrf(): VigilHandler<TUser> {
    return async (req, res, next) => {
      const cookieToken = req.cookies[DEFAULT_CSRF_COOKIE];

      if (SAFE_METHODS.has(req.method.toUpperCase())) {
        const token = cookieToken ?? generateToken(32, "base64url");
        if (!cookieToken) {
          res.setCookie(DEFAULT_CSRF_COOKIE, token, {
            httpOnly: false,
            secure: req.secure ?? process.env["NODE_ENV"] === "production",
            sameSite: "lax",
            path: "/",
          });
        }
        req.csrfToken = () => token;
        next();
        return;
      }

      const headerToken = req.headers["x-csrf-token"];
      const submittedToken = Array.isArray(headerToken) ? headerToken[0] : headerToken;
      const bodyToken =
        typeof req.body === "object" && req.body !== null ? (req.body as Record<string, unknown>)["_csrf"] : undefined;
      const candidate = submittedToken ?? (typeof bodyToken === "string" ? bodyToken : undefined);

      if (!cookieToken || !candidate || !timingSafeEqual(cookieToken, candidate)) {
        next(new AuthError("CSRF_INVALID", "CSRF token missing or invalid"));
        return;
      }

      req.csrfToken = () => cookieToken;
      next();
    };
  }

  rateLimit(options: RateLimitOptions): VigilHandler<TUser> {
    const store = options.store ?? this.defaultRateLimitStore;

    return async (req, res, next) => {
      const key = this.resolveRateLimitKey(req, options.keyBy ?? "ip");
      const { count, resetAt } = await store.increment(key, options.window);

      if (count > options.max) {
        const retryAfter = Math.max(0, Math.ceil((resetAt - Date.now()) / 1000));
        res.setHeader("Retry-After", String(retryAfter));
        next(new AuthError("RATE_LIMITED", "Too many attempts, please try again later"));
        return;
      }
      next();
    };
  }

  private resolveRateLimitKey(req: VigilRequest<TUser>, keyBy: RateLimitOptions["keyBy"]): string {
    if (typeof keyBy === "function") return keyBy(req);
    if (keyBy === "ip" || keyBy === undefined) return req.ip ?? "unknown";
    if (keyBy.startsWith("body.")) {
      const field = keyBy.slice("body.".length);
      const value =
        typeof req.body === "object" && req.body !== null ? (req.body as Record<string, unknown>)[field] : undefined;
      return typeof value === "string" ? value : "unknown";
    }
    return "unknown";
  }
}

export function createVigil<TUser = unknown>(config: VigilConfig<TUser>): Vigil<TUser> {
  return new Vigil(config);
}
