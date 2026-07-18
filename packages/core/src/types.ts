/** Framework-agnostic view of an incoming request. Adapters populate this from
 * their native request object; strategies and engine logic only ever see this shape. */
export interface VigilRequest<TUser = unknown> {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  cookies: Record<string, string>;
  query: Record<string, string | string[] | undefined>;
  body: unknown;
  ip?: string;
  /** Whether the underlying connection is HTTPS (or terminated as HTTPS by a
   * trusted proxy) — populated by the adapter. Used to default cookies'
   * `Secure` attribute without relying solely on `NODE_ENV`. */
  secure?: boolean;
  /** Mutable auth state populated by the pipeline as it runs. */
  user?: TUser | null;
  session?: SessionData | null;
  sessionId?: string | null;
  /** Populated by `vigil.csrf()` on safe requests. */
  csrfToken?: () => string;
}

export interface CookieOptions {
  maxAge?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "lax" | "strict" | "none";
  path?: string;
  domain?: string;
}

/** Framework-agnostic view of the outgoing response. Adapters implement this
 * on top of their native response object. */
export interface VigilResponse {
  status(code: number): void;
  setHeader(name: string, value: string): void;
  setCookie(name: string, value: string, options?: CookieOptions): void;
  clearCookie(name: string, options?: Pick<CookieOptions, "path" | "domain">): void;
  redirect(url: string, status?: number): void;
  json(body: unknown): void;
  send(body?: string): void;
}

/**
 * A Vigil handler mirrors Express-style middleware but speaks only in terms
 * of VigilRequest/VigilResponse. Adapters translate it to the target framework.
 * A handler must either call `next()` to continue the chain, call `next(err)`
 * to signal failure, or write directly to `res` (and not call next).
 */
export type VigilHandler<TUser = unknown> = (
  req: VigilRequest<TUser>,
  res: VigilResponse,
  next: (err?: unknown) => void,
) => Promise<void>;

export type AuthResult<TUser = unknown> =
  | { success: true; user: TUser }
  | { success: false; reason: string; status?: number }
  | { redirect: string; status?: number };

export interface Strategy<TUser = unknown, TOptions = unknown> {
  name: string;
  authenticate(request: VigilRequest<TUser>, options?: TOptions): Promise<AuthResult<TUser>>;
}

export interface SessionData {
  /** The serialized user identifier, as produced by the `serialize` option. */
  subject: unknown;
  createdAt: number;
  [key: string]: unknown;
}

export interface SessionStore {
  get(sessionId: string): Promise<SessionData | null>;
  set(sessionId: string, data: SessionData, ttl?: number): Promise<void>;
  destroy(sessionId: string): Promise<void>;
  touch?(sessionId: string, ttl: number): Promise<void>;
  /** Lists the session IDs currently active for a given subject (the
   * serialized user identifier stored as `SessionData.subject`). Optional —
   * only needed to support `vigil.listSessions()`. */
  listByUser?(subject: unknown): Promise<string[]>;
  /** Destroys every session belonging to a given subject — "sign out
   * everywhere." Optional — only needed to support `vigil.revokeAllSessions()`. */
  destroyAllForUser?(subject: unknown): Promise<void>;
}

export interface RateLimitStore {
  /** Increments the counter for `key` and returns the new count and the
   * epoch-seconds at which the window resets. */
  increment(key: string, windowSeconds: number): Promise<{ count: number; resetAt: number }>;
}

export interface SessionConfig {
  store: SessionStore;
  /** Renew a session's TTL (via `store.touch()`) each time it's loaded by
   * `requireAuth()`/`optionalAuth()`/`logout()`, so an active session doesn't
   * expire mid-use. Defaults to `true`. Has no effect without both a
   * `cookie.maxAge` and a store that implements `touch()`. Set to `false`
   * for an absolute (non-sliding) session lifetime instead. */
  rolling?: boolean;
  cookie?: {
    name?: string;
    maxAge?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "lax" | "strict" | "none";
    path?: string;
    domain?: string;
  };
}

export interface Hooks<TUser = unknown> {
  onAuthenticate?(strategyName: string, request: VigilRequest<TUser>): Promise<void>;
  onSuccess?(user: TUser, strategyName: string, request: VigilRequest<TUser>): Promise<void>;
  onFailure?(reason: string, strategyName: string, request: VigilRequest<TUser>): Promise<void>;
  onSerialize?(user: TUser): Promise<unknown>;
  onDeserialize?(serialized: unknown): Promise<TUser | null>;
  onLogout?(user: TUser | null, request: VigilRequest<TUser>): Promise<void>;
}

export interface VigilConfig<TUser = unknown> {
  strategies: Strategy<TUser>[];
  session: SessionConfig | false;
  serialize?: (user: TUser) => unknown;
  deserialize?: (serialized: unknown) => Promise<TUser | null>;
  hooks?: Hooks<TUser>;
}

export interface AuthenticateOptions {
  successRedirect?: string;
  failureRedirect?: string;
  session?: boolean;
  failFast?: boolean;
  /** By default, a failed authentication's public error message is a
   * generic "Authentication failed" — the specific reason a strategy's
   * `verify()` callback returned (e.g. "User not found" vs. "Invalid
   * password") is only attached to `AuthError.detail`, for hooks/logging,
   * not sent to the client. That's deliberate: differing messages between
   * "no such user" and "wrong password" is a classic user-enumeration leak
   * (OWASP A07). Set this to `true` to expose the real reason as the
   * error's public `.message` instead — e.g. for internal tools where
   * enumeration isn't a concern. */
  exposeFailureReason?: boolean;
  [key: string]: unknown;
}

export interface RequireAuthOptions {
  redirectTo?: string;
  message?: string;
}

export interface LogoutOptions {
  redirectTo?: string;
}

export interface RateLimitOptions {
  window: number;
  max: number;
  keyBy?: "ip" | `body.${string}` | ((req: VigilRequest) => string);
  store?: RateLimitStore;
}
