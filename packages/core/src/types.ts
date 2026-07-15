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
}

export interface RateLimitStore {
  /** Increments the counter for `key` and returns the new count and the
   * epoch-seconds at which the window resets. */
  increment(key: string, windowSeconds: number): Promise<{ count: number; resetAt: number }>;
}

export interface SessionConfig {
  store: SessionStore;
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
