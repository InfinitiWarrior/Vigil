import type { AuthResult } from "@vigil/core";
import { OAuth2Strategy, type OAuth2Tokens } from "../oauth2.js";
import type { OAuthStateStore } from "../state-store.js";

export interface GoogleProfile {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  [key: string]: unknown;
}

export interface GoogleOAuth2Options<TUser> {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** Defaults to `["openid", "email", "profile"]`. */
  scope?: string | string[];
  authorizationParams?: Record<string, string>;
  stateStore?: OAuthStateStore;
  stateTtlSeconds?: number;
  verify(profile: GoogleProfile, tokens: OAuth2Tokens): Promise<AuthResult<TUser>>;
}

export function googleOAuth2<TUser = unknown>(options: GoogleOAuth2Options<TUser>): OAuth2Strategy<TUser> {
  return new OAuth2Strategy<TUser>({
    name: "google",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
    scope: options.scope ?? ["openid", "email", "profile"],
    authorizationParams: options.authorizationParams,
    stateStore: options.stateStore,
    stateTtlSeconds: options.stateTtlSeconds,
    verify: (profile, tokens) => options.verify(profile as GoogleProfile, tokens),
  });
}
