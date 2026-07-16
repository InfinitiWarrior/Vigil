import { createRemoteJWKSet, importPKCS8, jwtVerify, SignJWT, type JWTPayload, type JWTVerifyGetKey } from "jose";
import type { AuthResult } from "@vigil/core";
import { OAuth2Strategy, type OAuth2Tokens } from "../oauth2.js";
import type { OAuthStateStore } from "../state-store.js";

export interface AppleProfile extends JWTPayload {
  email?: string;
  email_verified?: boolean | "true" | "false";
  [key: string]: unknown;
}

export interface AppleOAuth2Options<TUser> {
  /** Apple's "Services ID" — the client_id for web/OAuth2 flows, distinct from the app's bundle ID. */
  clientId: string;
  teamId: string;
  keyId: string;
  /** PKCS8 PEM contents of the private key downloaded from the Apple Developer portal. */
  privateKey: string;
  redirectUri: string;
  /** Defaults to `["name", "email"]`. */
  scope?: string | string[];
  authorizationParams?: Record<string, string>;
  stateStore?: OAuthStateStore;
  stateTtlSeconds?: number;
  /** Overrides the default `createRemoteJWKSet` key resolver used to verify the
   * id_token — mainly useful for tests, or to share a JWKS instance across strategies. */
  jwks?: JWTVerifyGetKey;
  verify(profile: AppleProfile, tokens: OAuth2Tokens): Promise<AuthResult<TUser>>;
}

const APPLE_ISSUER = "https://appleid.apple.com";
const APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys";
/** Kept short and regenerated per token exchange — simpler and safer than
 * caching a secret Apple would accept for up to six months. */
const CLIENT_SECRET_TTL_SECONDS = 300;

export function appleOAuth2<TUser = unknown>(options: AppleOAuth2Options<TUser>): OAuth2Strategy<TUser> {
  let signingKey: ReturnType<typeof importPKCS8> | undefined;
  const jwks = options.jwks ?? createRemoteJWKSet(new URL(APPLE_JWKS_URL));

  async function createClientSecret(): Promise<string> {
    signingKey ??= importPKCS8(options.privateKey, "ES256");
    const key = await signingKey;

    return new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: options.keyId })
      .setIssuer(options.teamId)
      .setIssuedAt()
      .setExpirationTime(`${CLIENT_SECRET_TTL_SECONDS}s`)
      .setAudience(APPLE_ISSUER)
      .setSubject(options.clientId)
      .sign(key);
  }

  async function fetchProfile(tokens: OAuth2Tokens): Promise<AppleProfile> {
    if (!tokens.idToken) throw new Error("Apple token response did not include an id_token");
    const { payload } = await jwtVerify(tokens.idToken, jwks, {
      issuer: APPLE_ISSUER,
      audience: options.clientId,
    });
    return payload as AppleProfile;
  }

  return new OAuth2Strategy<TUser>({
    name: "apple",
    clientId: options.clientId,
    clientSecret: createClientSecret,
    redirectUri: options.redirectUri,
    authorizationUrl: "https://appleid.apple.com/auth/authorize",
    tokenUrl: "https://appleid.apple.com/auth/token",
    scope: options.scope ?? ["name", "email"],
    authorizationParams: { response_mode: "form_post", ...options.authorizationParams },
    stateStore: options.stateStore,
    stateTtlSeconds: options.stateTtlSeconds,
    fetchProfile,
    verify: (profile, tokens) => options.verify(profile as AppleProfile, tokens),
  });
}
