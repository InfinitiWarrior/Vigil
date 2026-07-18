export type AuthErrorCode =
  | "UNAUTHENTICATED"
  | "FORBIDDEN"
  | "RATE_LIMITED"
  | "CSRF_INVALID"
  | "SESSION_EXPIRED"
  | "STRATEGY_ERROR"
  | "TOKEN_EXPIRED"
  | "TOKEN_INVALID";

const DEFAULT_STATUS: Record<AuthErrorCode, number> = {
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  RATE_LIMITED: 429,
  CSRF_INVALID: 403,
  SESSION_EXPIRED: 401,
  STRATEGY_ERROR: 500,
  TOKEN_EXPIRED: 401,
  TOKEN_INVALID: 401,
};

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly status: number;
  /** The original, possibly sensitive reason (a strategy's `verify()`
   * failure message, or a thrown exception's message) — always populated,
   * regardless of what the public `.message` exposes. See
   * `AuthenticateOptions.exposeFailureReason`. */
  readonly detail: string;

  constructor(code: AuthErrorCode, message?: string, status?: number, detail?: string) {
    super(message ?? code);
    this.name = "AuthError";
    this.code = code;
    this.status = status ?? DEFAULT_STATUS[code];
    this.detail = detail ?? this.message;
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}

export function isAuthError(err: unknown): err is AuthError {
  return err instanceof AuthError;
}
