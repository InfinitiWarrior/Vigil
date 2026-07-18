import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createLocalJWKSet, exportJWK, exportPKCS8, generateKeyPair, SignJWT } from "jose";
import { appleOAuth2, discordOAuth2, githubOAuth2, gitlabOAuth2, microsoftOAuth2 } from "@vigil/strategy-oauth2";

const baseRequest = {
  method: "GET",
  url: "/auth/callback",
  path: "/auth/callback",
  headers: {},
  cookies: {},
  body: {},
} as const;

function jsonResponse(body: unknown, ok = true, status = ok ? 200 : 400) {
  return { ok, status, json: async () => body } as Response;
}

describe("githubOAuth2", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async (input: string | URL) => {
      const url = input.toString();
      if (url.includes("github.com/login/oauth/access_token")) {
        return jsonResponse({ access_token: "gh-token", token_type: "bearer" });
      }
      if (url === "https://api.github.com/user") {
        return jsonResponse({ id: 42, login: "octocat", email: null });
      }
      if (url === "https://api.github.com/user/emails") {
        return jsonResponse([
          { email: "secondary@example.com", primary: false, verified: true },
          { email: "primary@example.com", primary: true, verified: true },
        ]);
      }
      throw new Error(`Unexpected fetch to ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => vi.unstubAllGlobals());

  it("backfills the primary verified email when /user omits it", async () => {
    const strategy = githubOAuth2({
      clientId: "gh-client",
      clientSecret: "gh-secret",
      redirectUri: "https://app.example/callback",
      verify: async (profile) => ({ success: true, user: { id: profile.id, email: profile.email } }),
    });

    expect(strategy.name).toBe("github");

    const initiate = await strategy.authenticate({ ...baseRequest, query: {} });
    if (!("redirect" in initiate)) throw new Error("expected a redirect result");
    const state = new URL(initiate.redirect).searchParams.get("state")!;

    const result = await strategy.authenticate({ ...baseRequest, query: { code: "gh-code", state } });
    expect(result).toEqual({ success: true, user: { id: 42, email: "primary@example.com" } });

    const userAgentCall = fetchMock.mock.calls.find(([url]) => url === "https://api.github.com/user");
    expect(userAgentCall![1].headers["User-Agent"]).toBe("vigil-oauth2");
  });
});

describe("appleOAuth2", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let privateKeyPem: string;
  let localJwks: ReturnType<typeof createLocalJWKSet>;
  const clientId = "com.example.app.web";

  beforeEach(async () => {
    const clientKeys = await generateKeyPair("ES256", { extractable: true });
    const idTokenKeys = await generateKeyPair("ES256", { extractable: true });
    const idTokenJwk = await exportJWK(idTokenKeys.publicKey);
    idTokenJwk.kid = "apple-key-1";
    idTokenJwk.alg = "ES256";
    idTokenJwk.use = "sig";
    localJwks = createLocalJWKSet({ keys: [idTokenJwk] });

    privateKeyPem = await exportPKCS8(clientKeys.privateKey);

    const idToken = await new SignJWT({ email: "user@example.com", email_verified: true })
      .setProtectedHeader({ alg: "ES256", kid: "apple-key-1" })
      .setIssuer("https://appleid.apple.com")
      .setAudience(clientId)
      .setSubject("apple-user-1")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(idTokenKeys.privateKey);

    fetchMock = vi.fn(async (input: string | URL) => {
      const url = input.toString();
      if (url === "https://appleid.apple.com/auth/token") {
        return jsonResponse({ access_token: "apple-access", id_token: idToken });
      }
      throw new Error(`Unexpected fetch to ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => vi.unstubAllGlobals());

  it("signs a client-secret JWT and verifies the id_token via Apple's JWKS", async () => {
    const strategy = appleOAuth2({
      clientId,
      teamId: "TEAM123456",
      keyId: "KEY7890",
      privateKey: privateKeyPem,
      redirectUri: "https://app.example/callback",
      jwks: localJwks,
      verify: async (profile) => ({ success: true, user: { id: profile.sub, email: profile.email } }),
    });

    const initiate = await strategy.authenticate({ ...baseRequest, query: {} });
    if (!("redirect" in initiate)) throw new Error("expected a redirect result");
    const url = new URL(initiate.redirect);
    expect(url.searchParams.get("response_mode")).toBe("form_post");
    const state = url.searchParams.get("state")!;

    const result = await strategy.authenticate({
      ...baseRequest,
      body: { code: "apple-code", state },
      query: {},
    });

    expect(result).toEqual({ success: true, user: { id: "apple-user-1", email: "user@example.com" } });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url === "https://appleid.apple.com/auth/token");
    const tokenBody = new URLSearchParams(tokenCall![1].body as string);
    const clientSecretJwt = tokenBody.get("client_secret")!;
    const [headerB64] = clientSecretJwt.split(".");
    const header = JSON.parse(Buffer.from(headerB64!, "base64url").toString());
    expect(header).toMatchObject({ alg: "ES256", kid: "KEY7890" });
  });
});

describe("microsoftOAuth2", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async (input: string | URL) => {
      const url = input.toString();
      if (url.includes("login.microsoftonline.com") && url.includes("/oauth2/v2.0/token")) {
        return jsonResponse({ access_token: "ms-token", token_type: "Bearer" });
      }
      if (url === "https://graph.microsoft.com/oidc/userinfo") {
        return jsonResponse({ sub: "ms-user-1", email: "user@contoso.com", name: "Contoso User" });
      }
      throw new Error(`Unexpected fetch to ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => vi.unstubAllGlobals());

  it("scopes the authorize/token URLs to the given tenant", async () => {
    const strategy = microsoftOAuth2({
      clientId: "ms-client",
      clientSecret: "ms-secret",
      redirectUri: "https://app.example/callback",
      tenant: "contoso.onmicrosoft.com",
      verify: async (profile) => ({ success: true, user: { id: profile.sub, email: profile.email } }),
    });

    expect(strategy.name).toBe("microsoft");

    const initiate = await strategy.authenticate({ ...baseRequest, query: {} });
    if (!("redirect" in initiate)) throw new Error("expected a redirect result");
    expect(initiate.redirect).toContain("login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize");
    const state = new URL(initiate.redirect).searchParams.get("state")!;

    const result = await strategy.authenticate({ ...baseRequest, query: { code: "ms-code", state } });
    expect(result).toEqual({ success: true, user: { id: "ms-user-1", email: "user@contoso.com" } });
  });
});

describe("discordOAuth2", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async (input: string | URL) => {
      const url = input.toString();
      if (url === "https://discord.com/api/oauth2/token") {
        return jsonResponse({ access_token: "discord-token", token_type: "Bearer" });
      }
      if (url === "https://discord.com/api/users/@me") {
        return jsonResponse({ id: "999", username: "vigiluser", email: "user@example.com" });
      }
      throw new Error(`Unexpected fetch to ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => vi.unstubAllGlobals());

  it("completes the authorization code flow", async () => {
    const strategy = discordOAuth2({
      clientId: "discord-client",
      clientSecret: "discord-secret",
      redirectUri: "https://app.example/callback",
      verify: async (profile) => ({ success: true, user: { id: profile.id, username: profile.username } }),
    });

    expect(strategy.name).toBe("discord");

    const initiate = await strategy.authenticate({ ...baseRequest, query: {} });
    if (!("redirect" in initiate)) throw new Error("expected a redirect result");
    const state = new URL(initiate.redirect).searchParams.get("state")!;

    const result = await strategy.authenticate({ ...baseRequest, query: { code: "discord-code", state } });
    expect(result).toEqual({ success: true, user: { id: "999", username: "vigiluser" } });
  });
});

describe("gitlabOAuth2", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async (input: string | URL) => {
      const url = input.toString();
      if (url === "https://gitlab.example.com/oauth/token") {
        return jsonResponse({ access_token: "gitlab-token", token_type: "Bearer" });
      }
      if (url === "https://gitlab.example.com/api/v4/user") {
        return jsonResponse({ id: 7, username: "vigiluser", email: "user@example.com" });
      }
      throw new Error(`Unexpected fetch to ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => vi.unstubAllGlobals());

  it("supports a self-hosted instance via baseUrl", async () => {
    const strategy = gitlabOAuth2({
      clientId: "gitlab-client",
      clientSecret: "gitlab-secret",
      redirectUri: "https://app.example/callback",
      baseUrl: "https://gitlab.example.com/",
      verify: async (profile) => ({ success: true, user: { id: profile.id, username: profile.username } }),
    });

    expect(strategy.name).toBe("gitlab");

    const initiate = await strategy.authenticate({ ...baseRequest, query: {} });
    if (!("redirect" in initiate)) throw new Error("expected a redirect result");
    expect(initiate.redirect).toContain("https://gitlab.example.com/oauth/authorize");
    const state = new URL(initiate.redirect).searchParams.get("state")!;

    const result = await strategy.authenticate({ ...baseRequest, query: { code: "gitlab-code", state } });
    expect(result).toEqual({ success: true, user: { id: 7, username: "vigiluser" } });
  });
});
