import { describe, expect, it, vi } from "vitest";
import type { Profile } from "@node-saml/node-saml";
import { SamlStrategy } from "@vigil/strategy-saml";

vi.mock("@node-saml/node-saml", () => {
  class MockSAML {
    options: Record<string, unknown>;
    getAuthorizeUrlAsync = vi.fn();
    validatePostResponseAsync = vi.fn();
    generateServiceProviderMetadata = vi.fn();
    getLogoutUrlAsync = vi.fn();
    validatePostRequestAsync = vi.fn();

    constructor(options: Record<string, unknown>) {
      this.options = options;
    }
  }
  return { SAML: MockSAML };
});

const baseRequest = {
  method: "POST",
  url: "/auth/saml/callback",
  path: "/auth/saml/callback",
  cookies: {},
  query: {},
} as const;

function makeStrategy(overrides: Partial<Record<string, unknown>> = {}) {
  return new SamlStrategy<{ email: string }>({
    entryPoint: "https://idp.example.com/sso",
    issuer: "vigil-test-sp",
    cert: "-----BEGIN CERTIFICATE-----FAKE-----END CERTIFICATE-----",
    callbackURL: "https://app.example/auth/saml/callback",
    verify: async (profile) => ({ success: true, user: { email: profile.email ?? profile.nameID } }),
    ...overrides,
  });
}

describe("SamlStrategy.authenticate — SP-initiated leg", () => {
  it("redirects to the IdP when there is no SAMLResponse", async () => {
    const strategy = makeStrategy();
    vi.mocked(strategy.saml.getAuthorizeUrlAsync).mockResolvedValue("https://idp.example.com/sso?SAMLRequest=abc");

    const result = await strategy.authenticate({ ...baseRequest, headers: { host: "app.example" }, body: {} });
    expect(result).toEqual({ redirect: "https://idp.example.com/sso?SAMLRequest=abc" });
    expect(strategy.saml.getAuthorizeUrlAsync).toHaveBeenCalledWith("", "app.example", {});
  });

  it("fails when there is no SAMLResponse and no entryPoint configured", async () => {
    const strategy = makeStrategy({ entryPoint: undefined });
    const result = await strategy.authenticate({ ...baseRequest, headers: {}, body: {} });
    expect(result).toMatchObject({ success: false, status: 400 });
    expect(strategy.saml.getAuthorizeUrlAsync).not.toHaveBeenCalled();
  });
});

describe("SamlStrategy.authenticate — ACS callback leg", () => {
  it("calls verify() with the validated profile", async () => {
    const strategy = makeStrategy();
    const profile = { issuer: "idp", nameID: "user-1", nameIDFormat: "email", email: "alice@example.com" } as Profile;
    vi.mocked(strategy.saml.validatePostResponseAsync).mockResolvedValue({ profile, loggedOut: false });

    const result = await strategy.authenticate({
      ...baseRequest,
      headers: {},
      body: { SAMLResponse: "base64-response", RelayState: "/dashboard" },
    });

    expect(result).toEqual({ success: true, user: { email: "alice@example.com" } });
    expect(strategy.saml.validatePostResponseAsync).toHaveBeenCalledWith({
      SAMLResponse: "base64-response",
      RelayState: "/dashboard",
    });
  });

  it("fails when the response carries no profile", async () => {
    const strategy = makeStrategy();
    vi.mocked(strategy.saml.validatePostResponseAsync).mockResolvedValue({ profile: null, loggedOut: false });

    const result = await strategy.authenticate({ ...baseRequest, headers: {}, body: { SAMLResponse: "resp" } });
    expect(result).toMatchObject({ success: false, status: 401 });
  });

  it("fails when the response is actually a logout response", async () => {
    const strategy = makeStrategy();
    vi.mocked(strategy.saml.validatePostResponseAsync).mockResolvedValue({ profile: null, loggedOut: true });

    const result = await strategy.authenticate({ ...baseRequest, headers: {}, body: { SAMLResponse: "resp" } });
    expect(result).toMatchObject({ success: false, reason: "Received a SAML logout response", status: 400 });
  });

  it("converts a validation error (e.g. bad signature) into a failure result", async () => {
    const strategy = makeStrategy();
    vi.mocked(strategy.saml.validatePostResponseAsync).mockRejectedValue(new Error("Invalid signature"));

    const result = await strategy.authenticate({ ...baseRequest, headers: {}, body: { SAMLResponse: "resp" } });
    expect(result).toEqual({ success: false, reason: "Invalid signature", status: 401 });
  });
});

describe("SamlStrategy other surfaces", () => {
  it("delegates metadata() to generateServiceProviderMetadata", () => {
    const strategy = makeStrategy();
    vi.mocked(strategy.saml.generateServiceProviderMetadata).mockReturnValue("<EntityDescriptor />");

    const xml = strategy.metadata("decrypt-cert", ["sign-cert"]);
    expect(xml).toBe("<EntityDescriptor />");
    expect(strategy.saml.generateServiceProviderMetadata).toHaveBeenCalledWith("decrypt-cert", ["sign-cert"]);
  });

  it("delegates logout() to getLogoutUrlAsync", async () => {
    const strategy = makeStrategy();
    vi.mocked(strategy.saml.getLogoutUrlAsync).mockResolvedValue("https://idp.example.com/slo?SAMLRequest=xyz");
    const profile = { issuer: "idp", nameID: "user-1", nameIDFormat: "email" } as Profile;

    const url = await strategy.logout(profile, "/bye");
    expect(url).toBe("https://idp.example.com/slo?SAMLRequest=xyz");
    expect(strategy.saml.getLogoutUrlAsync).toHaveBeenCalledWith(profile, "/bye", {});
  });

  it("routes logoutCallback() to validatePostRequestAsync for IdP-initiated SLO", async () => {
    const strategy = makeStrategy();
    vi.mocked(strategy.saml.validatePostRequestAsync).mockResolvedValue({
      profile: { issuer: "idp", nameID: "user-1", nameIDFormat: "email" } as Profile,
      loggedOut: true,
    });

    const result = await strategy.logoutCallback({
      ...baseRequest,
      headers: {},
      body: { SAMLRequest: "logout-request" },
    });
    expect(result.loggedOut).toBe(true);
    expect(strategy.saml.validatePostRequestAsync).toHaveBeenCalledWith({ SAMLRequest: "logout-request" });
  });

  it("routes logoutCallback() to validatePostResponseAsync for SP-initiated SLO's second leg", async () => {
    const strategy = makeStrategy();
    vi.mocked(strategy.saml.validatePostResponseAsync).mockResolvedValue({ profile: null, loggedOut: true });

    const result = await strategy.logoutCallback({
      ...baseRequest,
      headers: {},
      body: { SAMLResponse: "logout-response", RelayState: "" },
    });
    expect(result.loggedOut).toBe(true);
    expect(strategy.saml.validatePostResponseAsync).toHaveBeenCalledWith({
      SAMLResponse: "logout-response",
      RelayState: "",
    });
  });
});
