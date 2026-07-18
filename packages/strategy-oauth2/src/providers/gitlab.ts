import type { AuthResult } from "@vigil/core";
import { OAuth2Strategy, type OAuth2Tokens } from "../oauth2.js";
import type { OAuthStateStore } from "../state-store.js";

export interface GitLabProfile {
  id: number;
  username: string;
  name?: string;
  email?: string;
  avatar_url?: string;
  [key: string]: unknown;
}

export interface GitLabOAuth2Options<TUser> {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** Defaults to `"https://gitlab.com"` — set this for a self-hosted instance. */
  baseUrl?: string;
  /** Defaults to `["read_user"]`. */
  scope?: string | string[];
  authorizationParams?: Record<string, string>;
  stateStore?: OAuthStateStore;
  stateTtlSeconds?: number;
  verify(profile: GitLabProfile, tokens: OAuth2Tokens): Promise<AuthResult<TUser>>;
}

export function gitlabOAuth2<TUser = unknown>(options: GitLabOAuth2Options<TUser>): OAuth2Strategy<TUser> {
  const baseUrl = (options.baseUrl ?? "https://gitlab.com").replace(/\/$/, "");

  return new OAuth2Strategy<TUser>({
    name: "gitlab",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    authorizationUrl: `${baseUrl}/oauth/authorize`,
    tokenUrl: `${baseUrl}/oauth/token`,
    userInfoUrl: `${baseUrl}/api/v4/user`,
    scope: options.scope ?? ["read_user"],
    authorizationParams: options.authorizationParams,
    stateStore: options.stateStore,
    stateTtlSeconds: options.stateTtlSeconds,
    verify: (profile, tokens) => options.verify(profile as GitLabProfile, tokens),
  });
}
