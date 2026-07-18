export { createVigil, Vigil } from "./vigil.js";
export { AuthError, isAuthError } from "./errors.js";
export type { AuthErrorCode } from "./errors.js";
export {
  crypto,
  hashPassword,
  verifyPassword,
  generateToken,
  generateApiKey,
  hmac,
  timingSafeEqual,
} from "./crypto.js";
export {
  MemorySessionStore,
  createMemorySessionStore,
  MemoryRateLimitStore,
  createMemoryRateLimitStore,
} from "./stores.js";
export type {
  AuthResult,
  AuthenticateOptions,
  CookieOptions,
  Hooks,
  LogoutOptions,
  RateLimitOptions,
  RateLimitStore,
  RequireAuthOptions,
  SessionConfig,
  SessionData,
  SessionStore,
  Strategy,
  VigilConfig,
  VigilHandler,
  VigilRequest,
  VigilResponse,
} from "./types.js";
