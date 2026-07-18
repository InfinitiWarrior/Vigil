import type { AuthResult } from "@vigil/core";
import { OAuth2Strategy, type OAuth2Tokens } from "../oauth2.js";
import type { OAuthStateStore } from "../state-store.js";

export interface DiscordProfile {
  id: string;
  username: string;
  discriminator?: string;
  email?: string;
  verified?: boolean;
  avatar?: string | null;
  [key: string]: unknown;
}

export interface DiscordOAuth2Options<TUser> {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** Defaults to `["identify", "email"]`. */
  scope?: string | string[];
  authorizationParams?: Record<string, string>;
  stateStore?: OAuthStateStore;
  stateTtlSeconds?: number;
  verify(profile: DiscordProfile, tokens: OAuth2Tokens): Promise<AuthResult<TUser>>;
}

export function discordOAuth2<TUser = unknown>(options: DiscordOAuth2Options<TUser>): OAuth2Strategy<TUser> {
  return new OAuth2Strategy<TUser>({
    name: "discord",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    authorizationUrl: "https://discord.com/oauth2/authorize",
    tokenUrl: "https://discord.com/api/oauth2/token",
    userInfoUrl: "https://discord.com/api/users/@me",
    scope: options.scope ?? ["identify", "email"],
    authorizationParams: options.authorizationParams,
    stateStore: options.stateStore,
    stateTtlSeconds: options.stateTtlSeconds,
    verify: (profile, tokens) => options.verify(profile as DiscordProfile, tokens),
  });
}
