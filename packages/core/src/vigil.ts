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

function defaultCookieOptions(overrides?: Partial<CookieOptions>): CookieOptions {
  return {
    httpOnly: true,
    secure: process.env["NODE_ENV"] === "production",
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

  private sessionCookieName(): string {
    if (this.config.session === false) return DEFAULT_SESSION_COOKIE;
    return this.config.session.cookie?.name ?? DEFAULT_SESSION_COOKIE;
  }

  private sessionCookieOptions(): CookieOptions {
    if (this.config.session === false) return defaultCookieOptions();
    return defaultCookieOptions(this.config.session.cookie);
  }

  private sessionMaxAge(): number | undefined {
    if (this.config.session === false) return undefined;
    return this.config.session.cookie?.maxAge;
  }

  /** Loads `req.user` from the session cookie if one is present and no user
   * has already been attached earlier in the pipeline (e.g. by `authenticate`). */
  private async loadSessionUser(req: VigilRequest<TUser>): Promise<void> {
    if (req.user !== undefined && req.user !== null) return;
    const sessionConfig = this.config.session;
    if (sessionConfig === false) return;

    const cookieName = this.sessionCookieName();
    const sessionId = req.cookies[cookieName];
    if (!sessionId) return;

    const session = await sessionConfig.store.get(sessionId);
    if (!session) return;

    const user = await this.deserialize(session.subject);
    req.sessionId = sessionId;
    req.session = session;
    req.user = user;
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
          next(new AuthError("STRATEGY_ERROR", reason));
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
      next(new AuthError("UNAUTHENTICATED", failure.reason, failure.status));
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
      ...this.sessionCookieOptions(),
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
        res.clearCookie(this.sessionCookieName(), this.sessionCookieOptions());
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
            secure: process.env["NODE_ENV"] === "production",
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
        typeof req.body === "object" && req.body !== null
          ? (req.body as Record<string, unknown>)["_csrf"]
          : undefined;
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

  private resolveRateLimitKey(
    req: VigilRequest<TUser>,
    keyBy: RateLimitOptions["keyBy"],
  ): string {
    if (typeof keyBy === "function") return keyBy(req);
    if (keyBy === "ip" || keyBy === undefined) return req.ip ?? "unknown";
    if (keyBy.startsWith("body.")) {
      const field = keyBy.slice("body.".length);
      const value =
        typeof req.body === "object" && req.body !== null
          ? (req.body as Record<string, unknown>)[field]
          : undefined;
      return typeof value === "string" ? value : "unknown";
    }
    return "unknown";
  }
}

export function createVigil<TUser = unknown>(config: VigilConfig<TUser>): Vigil<TUser> {
  return new Vigil(config);
}
