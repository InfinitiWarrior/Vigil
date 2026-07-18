import type { AuthResult } from "@vigil/core";
import { OAuth2Strategy, type OAuth2Tokens } from "../oauth2.js";
import type { OAuthStateStore } from "../state-store.js";

export interface MicrosoftProfile {
  sub: string;
  name?: string;
  email?: string;
  preferred_username?: string;
  [key: string]: unknown;
}

export interface MicrosoftOAuth2Options<TUser> {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** Azure AD / Entra ID tenant — a GUID, a verified domain, or one of
   * `"common"` (personal + work/school accounts), `"organizations"`
   * (work/school only), or `"consumers"` (personal only). Defaults to
   * `"common"`. */
  tenant?: string;
  /** Defaults to `["openid", "profile", "email"]`. */
  scope?: string | string[];
  authorizationParams?: Record<string, string>;
  stateStore?: OAuthStateStore;
  stateTtlSeconds?: number;
  verify(profile: MicrosoftProfile, tokens: OAuth2Tokens): Promise<AuthResult<TUser>>;
}

export function microsoftOAuth2<TUser = unknown>(options: MicrosoftOAuth2Options<TUser>): OAuth2Strategy<TUser> {
  const tenant = options.tenant ?? "common";

  return new OAuth2Strategy<TUser>({
    name: "microsoft",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    authorizationUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
    tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
    userInfoUrl: "https://graph.microsoft.com/oidc/userinfo",
    scope: options.scope ?? ["openid", "profile", "email"],
    authorizationParams: options.authorizationParams,
    stateStore: options.stateStore,
    stateTtlSeconds: options.stateTtlSeconds,
    verify: (profile, tokens) => options.verify(profile as MicrosoftProfile, tokens),
  });
}
