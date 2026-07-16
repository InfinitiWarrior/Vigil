import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createLocalJWKSet, exportJWK, exportPKCS8, generateKeyPair, SignJWT } from "jose";
import { appleOAuth2, githubOAuth2 } from "@vigil/strategy-oauth2";

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
