import { generateToken } from "@vigil/core";
import type { AuthResult, Strategy, VigilRequest } from "@vigil/core";
import { deriveCodeChallenge, generateCodeVerifier } from "./pkce.js";
import { MemoryOAuthStateStore, type OAuthStateStore } from "./state-store.js";

export interface OAuth2Tokens {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType?: string;
  expiresIn?: number;
  scope?: string;
  raw: Record<string, unknown>;
}

export type OAuth2Profile = Record<string, unknown>;

export interface OAuth2StrategyOptions<TUser> {
  /** Strategy name registered with `createVigil`. Defaults to "oauth2"; presets override it (e.g. "google"). */
  name?: string;
  clientId: string;
  /** Static secret, or a function returning one — the latter lets Apple's
   * per-request signed-JWT client secret plug in without a separate code path. */
  clientSecret?: string | (() => Promise<string> | string);
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl?: string;
  redirectUri: string;
  scope?: string | string[];
  /** Defaults to true. Only disable for providers that reject the extra params. */
  pkce?: boolean;
  authorizationParams?: Record<string, string>;
  stateStore?: OAuthStateStore;
  stateTtlSeconds?: number;
  /** Overrides the default "GET userInfoUrl with a bearer token" profile fetch —
   * needed for providers like Apple that only expose identity via the ID token. */
  fetchProfile?(tokens: OAuth2Tokens): Promise<OAuth2Profile>;
  verify(profile: OAuth2Profile, tokens: OAuth2Tokens): Promise<AuthResult<TUser>>;
}

function readParam(request: VigilRequest, key: string): string | undefined {
  const fromQuery = request.query[key];
  if (typeof fromQuery === "string") return fromQuery;
  if (Array.isArray(fromQuery) && fromQuery.length > 0) return fromQuery[0];

  const body = typeof request.body === "object" && request.body !== null
    ? (request.body as Record<string, unknown>)
    : {};
  const fromBody = body[key];
  return typeof fromBody === "string" ? fromBody : undefined;
}

function normalizeScope(scope: OAuth2StrategyOptions<unknown>["scope"]): string | undefined {
  if (!scope) return undefined;
  return Array.isArray(scope) ? scope.join(" ") : scope;
}

export class OAuth2Strategy<TUser = unknown> implements Strategy<TUser> {
  readonly name: string;

  private readonly options: OAuth2StrategyOptions<TUser>;
  private readonly stateStore: OAuthStateStore;
  private readonly pkceEnabled: boolean;

  constructor(options: OAuth2StrategyOptions<TUser>) {
    this.name = options.name ?? "oauth2";
    this.options = options;
    this.stateStore = options.stateStore ?? new MemoryOAuthStateStore();
    this.pkceEnabled = options.pkce ?? true;
  }

  async authenticate(request: VigilRequest<TUser>): Promise<AuthResult<TUser>> {
    const error = readParam(request, "error");
    if (error) {
      const description = readParam(request, "error_description") ?? error;
      return { success: false, reason: description, status: 400 };
    }

    const code = readParam(request, "code");
    if (!code) return this.initiate();

    const state = readParam(request, "state");
    return this.callback(code, state);
  }

  private async initiate(): Promise<AuthResult<TUser>> {
    const state = generateToken(24, "base64url");
    const codeVerifier = this.pkceEnabled ? generateCodeVerifier() : "";

    await this.stateStore.set(
      state,
      { codeVerifier, redirectUri: this.options.redirectUri, createdAt: Date.now() },
      this.options.stateTtlSeconds,
    );

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.options.clientId,
      redirect_uri: this.options.redirectUri,
      state,
      ...this.options.authorizationParams,
    });

    const scope = normalizeScope(this.options.scope);
    if (scope) params.set("scope", scope);

    if (this.pkceEnabled) {
      params.set("code_challenge", deriveCodeChallenge(codeVerifier));
      params.set("code_challenge_method", "S256");
    }

    return { redirect: `${this.options.authorizationUrl}?${params.toString()}` };
  }

  private async callback(code: string, state: string | undefined): Promise<AuthResult<TUser>> {
    if (!state) return { success: false, reason: "Missing state parameter", status: 400 };

    const stateData = await this.stateStore.consume(state);
    if (!stateData) return { success: false, reason: "Invalid or expired state", status: 400 };

    let tokens: OAuth2Tokens;
    try {
      tokens = await this.exchangeCode(code, stateData.redirectUri, stateData.codeVerifier);
    } catch (err) {
      const reason = err instanceof Error ? err.message : "Token exchange failed";
      return { success: false, reason, status: 401 };
    }

    let profile: OAuth2Profile;
    try {
      profile = await this.getProfile(tokens);
    } catch (err) {
      const reason = err instanceof Error ? err.message : "Failed to fetch profile";
      return { success: false, reason, status: 401 };
    }

    return this.options.verify(profile, tokens);
  }

  private async resolveClientSecret(): Promise<string | undefined> {
    const secret = this.options.clientSecret;
    if (typeof secret === "function") return secret();
    return secret;
  }

  private async exchangeCode(code: string, redirectUri: string, codeVerifier: string): Promise<OAuth2Tokens> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: this.options.clientId,
    });

    const clientSecret = await this.resolveClientSecret();
    if (clientSecret) body.set("client_secret", clientSecret);
    if (codeVerifier) body.set("code_verifier", codeVerifier);

    const response = await fetch(this.options.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: body.toString(),
    });

    const raw = (await response.json()) as Record<string, unknown>;

    if (!response.ok) {
      const description = typeof raw["error_description"] === "string"
        ? raw["error_description"]
        : typeof raw["error"] === "string"
          ? raw["error"]
          : `Token exchange failed with status ${response.status}`;
      throw new Error(description);
    }

    const accessToken = raw["access_token"];
    if (typeof accessToken !== "string") {
      throw new Error("Token response did not include an access_token");
    }

    return {
      accessToken,
      refreshToken: typeof raw["refresh_token"] === "string" ? raw["refresh_token"] : undefined,
      idToken: typeof raw["id_token"] === "string" ? raw["id_token"] : undefined,
      tokenType: typeof raw["token_type"] === "string" ? raw["token_type"] : undefined,
      expiresIn: typeof raw["expires_in"] === "number" ? raw["expires_in"] : undefined,
      scope: typeof raw["scope"] === "string" ? raw["scope"] : undefined,
      raw,
    };
  }

  private async getProfile(tokens: OAuth2Tokens): Promise<OAuth2Profile> {
    if (this.options.fetchProfile) return this.options.fetchProfile(tokens);

    if (!this.options.userInfoUrl) {
      throw new Error("OAuth2Strategy requires either `userInfoUrl` or a `fetchProfile` implementation");
    }

    const response = await fetch(this.options.userInfoUrl, {
      headers: { Authorization: `Bearer ${tokens.accessToken}`, Accept: "application/json" },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch user profile (status ${response.status})`);
    }

    return (await response.json()) as OAuth2Profile;
  }
}
