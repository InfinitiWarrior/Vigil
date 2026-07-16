import type { AuthResult } from "@vigil/core";
import { OAuth2Strategy, type OAuth2Profile, type OAuth2Tokens } from "../oauth2.js";
import type { OAuthStateStore } from "../state-store.js";

export interface GitHubProfile {
  id: number;
  login: string;
  name?: string | null;
  email?: string | null;
  avatar_url?: string;
  [key: string]: unknown;
}

export interface GitHubOAuth2Options<TUser> {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** Defaults to `["read:user", "user:email"]`. */
  scope?: string | string[];
  authorizationParams?: Record<string, string>;
  stateStore?: OAuthStateStore;
  stateTtlSeconds?: number;
  verify(profile: GitHubProfile, tokens: OAuth2Tokens): Promise<AuthResult<TUser>>;
}

interface GitHubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
}

/** GitHub's API rejects requests with no User-Agent, and `/user` omits `email`
 * whenever the user has it set to private — a second call fills it back in. */
async function fetchGitHubProfile(tokens: OAuth2Tokens): Promise<OAuth2Profile> {
  const headers = {
    Authorization: `Bearer ${tokens.accessToken}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "vigil-oauth2",
  };

  const userResponse = await fetch("https://api.github.com/user", { headers });
  if (!userResponse.ok) {
    throw new Error(`Failed to fetch GitHub profile (status ${userResponse.status})`);
  }
  const user = (await userResponse.json()) as Record<string, unknown>;

  if (!user["email"]) {
    const emailsResponse = await fetch("https://api.github.com/user/emails", { headers });
    if (emailsResponse.ok) {
      const emails = (await emailsResponse.json()) as GitHubEmail[];
      const primary = emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified);
      if (primary) user["email"] = primary.email;
    }
  }

  return user;
}

export function githubOAuth2<TUser = unknown>(options: GitHubOAuth2Options<TUser>): OAuth2Strategy<TUser> {
  return new OAuth2Strategy<TUser>({
    name: "github",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    redirectUri: options.redirectUri,
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    scope: options.scope ?? ["read:user", "user:email"],
    authorizationParams: options.authorizationParams,
    stateStore: options.stateStore,
    stateTtlSeconds: options.stateTtlSeconds,
    fetchProfile: fetchGitHubProfile,
    verify: (profile, tokens) => options.verify(profile as GitHubProfile, tokens),
  });
}
