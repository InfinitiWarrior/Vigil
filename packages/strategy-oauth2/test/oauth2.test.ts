import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OAuth2Strategy } from "@vigil/strategy-oauth2";

const baseRequest = {
  method: "GET",
  url: "/auth/oauth2",
  path: "/auth/oauth2",
  headers: {},
  cookies: {},
  body: {},
} as const;

function jsonResponse(body: unknown, ok = true, status = ok ? 200 : 400) {
  return {
    ok,
    status,
    json: async () => body,
  } as Response;
}

function makeStrategy(overrides: Partial<ConstructorParameters<typeof OAuth2Strategy>[0]> = {}) {
  return new OAuth2Strategy({
    clientId: "client-123",
    clientSecret: "secret-abc",
    authorizationUrl: "https://provider.example/authorize",
    tokenUrl: "https://provider.example/token",
    userInfoUrl: "https://provider.example/userinfo",
    redirectUri: "https://app.example/callback",
    scope: ["openid", "email"],
    verify: async (profile) => ({ success: true, user: { id: profile["sub"] } }),
    ...overrides,
  });
}

describe("OAuth2Strategy — initiate", () => {
  it("redirects to the authorization URL with PKCE parameters by default", async () => {
    const strategy = makeStrategy();
    const result = await strategy.authenticate({ ...baseRequest, query: {} });

    if (!("redirect" in result)) throw new Error("expected a redirect result");
    const url = new URL(result.redirect);

    expect(url.origin + url.pathname).toBe("https://provider.example/authorize");
    expect(url.searchParams.get("client_id")).toBe("client-123");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.example/callback");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid email");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    expect(url.searchParams.get("state")).toBeTruthy();
  });

  it("omits code_challenge parameters when pkce is disabled", async () => {
    const strategy = makeStrategy({ pkce: false });
    const result = await strategy.authenticate({ ...baseRequest, query: {} });

    if (!("redirect" in result)) throw new Error("expected a redirect result");
    const url = new URL(result.redirect);
    expect(url.searchParams.has("code_challenge")).toBe(false);
    expect(url.searchParams.has("code_challenge_method")).toBe(false);
  });
});

describe("OAuth2Strategy — callback", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async (input: string | URL) => {
      const url = input.toString();
      if (url.startsWith("https://provider.example/token")) {
        return jsonResponse({ access_token: "access-token-1", token_type: "Bearer", expires_in: 3600 });
      }
      if (url.startsWith("https://provider.example/userinfo")) {
        return jsonResponse({ sub: "user-1", email: "user@example.com" });
      }
      throw new Error(`Unexpected fetch to ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("exchanges the code, fetches the profile, and calls verify on success", async () => {
    const strategy = makeStrategy();
    const initiate = await strategy.authenticate({ ...baseRequest, query: {} });
    if (!("redirect" in initiate)) throw new Error("expected a redirect result");
    const state = new URL(initiate.redirect).searchParams.get("state")!;

    const result = await strategy.authenticate({
      ...baseRequest,
      query: { code: "auth-code-1", state },
    });

    expect(result).toEqual({ success: true, user: { id: "user-1" } });

    const tokenCall = fetchMock.mock.calls.find(([url]) => url.toString().includes("/token"));
    expect(tokenCall).toBeTruthy();
    const tokenBody = new URLSearchParams(tokenCall![1].body as string);
    expect(tokenBody.get("grant_type")).toBe("authorization_code");
    expect(tokenBody.get("code")).toBe("auth-code-1");
    expect(tokenBody.get("client_secret")).toBe("secret-abc");
    expect(tokenBody.get("code_verifier")).toBeTruthy();
  });

  it("rejects a callback with no matching state", async () => {
    const strategy = makeStrategy();
    const result = await strategy.authenticate({
      ...baseRequest,
      query: { code: "auth-code-1", state: "never-issued" },
    });
    expect(result).toMatchObject({ success: false, status: 400, reason: "Invalid or expired state" });
  });

  it("rejects a callback missing the state parameter", async () => {
    const strategy = makeStrategy();
    const result = await strategy.authenticate({
      ...baseRequest,
      query: { code: "auth-code-1" },
    });
    expect(result).toMatchObject({ success: false, status: 400 });
  });

  it("rejects a replayed state (single use)", async () => {
    const strategy = makeStrategy();
    const initiate = await strategy.authenticate({ ...baseRequest, query: {} });
    if (!("redirect" in initiate)) throw new Error("expected a redirect result");
    const state = new URL(initiate.redirect).searchParams.get("state")!;

    const first = await strategy.authenticate({ ...baseRequest, query: { code: "auth-code-1", state } });
    expect(first).toMatchObject({ success: true });

    const second = await strategy.authenticate({ ...baseRequest, query: { code: "auth-code-1", state } });
    expect(second).toMatchObject({ success: false, status: 400 });
  });

  it("surfaces the provider's error param without contacting the token endpoint", async () => {
    const strategy = makeStrategy();
    const result = await strategy.authenticate({
      ...baseRequest,
      query: { error: "access_denied", error_description: "The user denied the request" },
    });
    expect(result).toEqual({ success: false, reason: "The user denied the request", status: 400 });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns a failure when the token endpoint rejects the exchange", async () => {
    fetchMock.mockImplementationOnce(async () =>
      jsonResponse({ error: "invalid_grant", error_description: "Code already used" }, false, 400),
    );
    const strategy = makeStrategy();
    const initiate = await strategy.authenticate({ ...baseRequest, query: {} });
    if (!("redirect" in initiate)) throw new Error("expected a redirect result");
    const state = new URL(initiate.redirect).searchParams.get("state")!;

    const result = await strategy.authenticate({
      ...baseRequest,
      query: { code: "auth-code-1", state },
    });
    expect(result).toMatchObject({ success: false, reason: "Code already used", status: 401 });
  });
});
