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

  constructor(code: AuthErrorCode, message?: string, status?: number) {
    super(message ?? code);
    this.name = "AuthError";
    this.code = code;
    this.status = status ?? DEFAULT_STATUS[code];
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}

export function isAuthError(err: unknown): err is AuthError {
  return err instanceof AuthError;
}
