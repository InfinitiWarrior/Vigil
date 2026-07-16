import { SAML, type Profile, type SamlConfig } from "@node-saml/node-saml";
import type { AuthResult, Strategy, VigilRequest } from "@vigil/core";

export { SAML } from "@node-saml/node-saml";
export type { Profile, SamlConfig } from "@node-saml/node-saml";

/** DESIGN.md's pseudocode names these `cert`/`callbackURL`; node-saml calls
 * them `idpCert`/`callbackUrl`. Every other SamlConfig field (privateKey,
 * decryptionPvk, audience, acceptedClockSkewMs, IdP-initiated support, ...)
 * passes straight through untouched. */
export type SamlStrategyOptions<TUser> = Omit<SamlConfig, "idpCert" | "callbackUrl"> & {
  cert: SamlConfig["idpCert"];
  callbackURL: string;
  verify(profile: Profile): Promise<AuthResult<TUser>>;
};

function readBody(request: VigilRequest): Record<string, unknown> {
  return typeof request.body === "object" && request.body !== null
    ? (request.body as Record<string, unknown>)
    : {};
}

function firstHeaderValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/**
 * All XML parsing, signature/assertion verification, and encryption handling
 * is delegated to @node-saml/node-saml (the maintained successor to
 * passport-saml's core) — this wrapper only adapts its API into Vigil's
 * Strategy/AuthResult shape. Hand-rolling SAML's XML canonicalization and
 * signature verification is exactly the kind of protocol-crypto code that's
 * easy to get subtly, security-critically wrong.
 */
export class SamlStrategy<TUser = unknown> implements Strategy<TUser> {
  readonly name = "saml";

  /** The underlying node-saml instance, for any feature this wrapper hasn't
   * surfaced directly (e.g. redirect-binding SLO via `validateRedirectAsync`). */
  readonly saml: SAML;

  private readonly verifyFn: (profile: Profile) => Promise<AuthResult<TUser>>;

  constructor(options: SamlStrategyOptions<TUser>) {
    const { cert, callbackURL, verify, ...rest } = options;
    this.verifyFn = verify;
    this.saml = new SAML({ ...rest, idpCert: cert, callbackUrl: callbackURL });
  }

  /**
   * Standard Strategy entrypoint, handling both legs of SP-initiated SSO:
   * with no `SAMLResponse` in the body, it redirects to the IdP; with one
   * present (the ACS callback), it validates the response and calls `verify`.
   * IdP-initiated SSO lands directly on the second branch.
   */
  async authenticate(request: VigilRequest<TUser>): Promise<AuthResult<TUser>> {
    const body = readBody(request);
    const samlResponse = body["SAMLResponse"];
    const relayState = typeof body["RelayState"] === "string" ? body["RelayState"] : "";

    if (typeof samlResponse !== "string") {
      if (!this.saml.options.entryPoint) {
        return {
          success: false,
          reason: "No SAMLResponse in the request and no entryPoint configured for SP-initiated login",
          status: 400,
        };
      }
      const host = firstHeaderValue(request.headers["host"]);
      const url = await this.saml.getAuthorizeUrlAsync(relayState, host, {});
      return { redirect: url };
    }

    let profile: Profile | null;
    let loggedOut: boolean;
    try {
      ({ profile, loggedOut } = await this.saml.validatePostResponseAsync({
        SAMLResponse: samlResponse,
        RelayState: relayState,
      }));
    } catch (err) {
      const reason = err instanceof Error ? err.message : "SAML response validation failed";
      return { success: false, reason, status: 401 };
    }

    if (loggedOut) return { success: false, reason: "Received a SAML logout response", status: 400 };
    if (!profile) return { success: false, reason: "SAML response did not include a profile", status: 401 };

    return this.verifyFn(profile);
  }

  /** SP metadata XML for registering this app with the IdP. */
  metadata(decryptionCert: string | null = null, publicCert?: string | string[] | null): string {
    return this.saml.generateServiceProviderMetadata(decryptionCert, publicCert);
  }

  /** Starts SP-initiated single logout: redirect the user to this URL. */
  async logout(profile: Profile, relayState = ""): Promise<string> {
    return this.saml.getLogoutUrlAsync(profile, relayState, {});
  }

  /** Validates the IdP's logout callback — a LogoutResponse (SP-initiated
   * SLO's second leg) or a LogoutRequest (IdP-initiated SLO), both delivered
   * via POST binding. */
  async logoutCallback(request: VigilRequest): Promise<{ profile: Profile | null; loggedOut: boolean }> {
    const body = readBody(request);
    if (typeof body["SAMLRequest"] === "string") {
      return this.saml.validatePostRequestAsync({ SAMLRequest: body["SAMLRequest"] });
    }
    const relayState = typeof body["RelayState"] === "string" ? body["RelayState"] : "";
    return this.saml.validatePostResponseAsync({
      SAMLResponse: body["SAMLResponse"] as string,
      RelayState: relayState,
    });
  }
}
