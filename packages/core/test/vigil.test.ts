import { describe, expect, it, vi } from "vitest";
import { createVigil, isAuthError, MemorySessionStore } from "@vigil/core";
import type { AuthResult, Strategy } from "@vigil/core";
import { fakeRequest, run } from "./helpers.js";

interface User {
  id: string;
  role?: string;
}

function strategy(name: string, result: AuthResult<User>): Strategy<User> {
  return { name, authenticate: async () => result };
}

describe("authenticate", () => {
  it("attaches the user and sets a session cookie on success", async () => {
    const store = new MemorySessionStore();
    const vigil = createVigil<User>({
      strategies: [strategy("mock", { success: true, user: { id: "1" } })],
      session: { store, cookie: { name: "vigil.sid", maxAge: 3600 } },
    });

    const req = fakeRequest<User>();
    const { called, error, res } = await run(vigil.authenticate("mock"), req);

    expect(called).toBe(true);
    expect(error).toBeUndefined();
    expect(req.user).toEqual({ id: "1" });
    expect(res.cookies["vigil.sid"]).toBeDefined();

    const stored = await store.get(res.cookies["vigil.sid"]!);
    expect(stored?.subject).toEqual({ id: "1" });
  });

  it("skips the session when session: false is passed", async () => {
    const store = new MemorySessionStore();
    const vigil = createVigil<User>({
      strategies: [strategy("mock", { success: true, user: { id: "1" } })],
      session: { store },
    });

    const { res } = await run(vigil.authenticate("mock", { session: false }), fakeRequest<User>());
    expect(res.cookies["vigil.sid"]).toBeUndefined();
  });

  it("passes an AuthError to next on failure", async () => {
    const vigil = createVigil<User>({
      strategies: [strategy("mock", { success: false, reason: "bad creds", status: 401 })],
      session: false,
    });

    const { error } = await run(vigil.authenticate("mock"), fakeRequest<User>());
    expect(isAuthError(error)).toBe(true);
    if (isAuthError(error)) {
      expect(error.code).toBe("UNAUTHENTICATED");
      expect(error.status).toBe(401);
    }
  });

  it("hides the strategy's failure reason from the public error message by default", async () => {
    const vigil = createVigil<User>({
      strategies: [strategy("mock", { success: false, reason: "No account with that email", status: 401 })],
      session: false,
    });

    const { error } = await run(vigil.authenticate("mock"), fakeRequest<User>());
    expect(isAuthError(error)).toBe(true);
    if (isAuthError(error)) {
      expect(error.message).toBe("Authentication failed");
      expect(error.detail).toBe("No account with that email");
    }
  });

  it("exposes the real failure reason when exposeFailureReason is set", async () => {
    const vigil = createVigil<User>({
      strategies: [strategy("mock", { success: false, reason: "No account with that email", status: 401 })],
      session: false,
    });

    const { error } = await run(vigil.authenticate("mock", { exposeFailureReason: true }), fakeRequest<User>());
    expect(isAuthError(error) && error.message).toBe("No account with that email");
  });

  it("hides a thrown strategy error's message from the client regardless of exposeFailureReason", async () => {
    const throwing: Strategy<User> = {
      name: "broken",
      authenticate: async () => {
        throw new Error("connection string leaked: postgres://...");
      },
    };
    const vigil = createVigil<User>({ strategies: [throwing], session: false });

    const { error } = await run(vigil.authenticate("broken", { exposeFailureReason: true }), fakeRequest<User>());
    expect(isAuthError(error)).toBe(true);
    if (isAuthError(error)) {
      expect(error.code).toBe("STRATEGY_ERROR");
      expect(error.message).toBe("Authentication failed");
      expect(error.detail).toContain("connection string leaked");
    }
  });

  it("defaults the session cookie's secure flag from req.secure", async () => {
    const store = new MemorySessionStore();
    const vigil = createVigil<User>({
      strategies: [strategy("mock", { success: true, user: { id: "1" } })],
      session: { store, cookie: { name: "vigil.sid" } },
    });

    const { res: httpRes } = await run(vigil.authenticate("mock"), fakeRequest<User>({ secure: false }));
    expect(httpRes.cookieOptions["vigil.sid"]?.secure).toBe(false);

    const { res: httpsRes } = await run(vigil.authenticate("mock"), fakeRequest<User>({ secure: true }));
    expect(httpsRes.cookieOptions["vigil.sid"]?.secure).toBe(true);
  });

  it("tries strategies in order and stops at the first success", async () => {
    const vigil = createVigil<User>({
      strategies: [
        strategy("jwt", { success: false, reason: "no token", status: 401 }),
        strategy("apikey", { success: true, user: { id: "2" } }),
      ],
      session: false,
    });

    const req = fakeRequest<User>();
    const { error } = await run(vigil.authenticate(["jwt", "apikey"]), req);
    expect(error).toBeUndefined();
    expect(req.user).toEqual({ id: "2" });
  });

  it("redirects on successFailure options instead of calling next", async () => {
    const vigil = createVigil<User>({
      strategies: [strategy("mock", { success: true, user: { id: "1" } })],
      session: false,
    });

    const { called, res } = await run(
      vigil.authenticate("mock", { successRedirect: "/dashboard" }),
      fakeRequest<User>(),
    );
    expect(called).toBe(false);
    expect(res.redirected).toEqual({ url: "/dashboard", status: 302 });
  });
});

describe("requireAuth / optionalAuth", () => {
  it("loads the user from the session cookie", async () => {
    const store = new MemorySessionStore();
    await store.set("sess-1", { subject: { id: "9" }, createdAt: Date.now() });

    const vigil = createVigil<User>({ strategies: [], session: { store } });
    const req = fakeRequest<User>({ cookies: { "vigil.sid": "sess-1" } });

    const { error } = await run(vigil.requireAuth(), req);
    expect(error).toBeUndefined();
    expect(req.user).toEqual({ id: "9" });
  });

  it("rejects with UNAUTHENTICATED when there is no session", async () => {
    const vigil = createVigil<User>({ strategies: [], session: { store: new MemorySessionStore() } });
    const { error } = await run(vigil.requireAuth(), fakeRequest<User>());
    expect(isAuthError(error) && error.code).toBe("UNAUTHENTICATED");
  });

  it("optionalAuth always continues, with user null when absent", async () => {
    const vigil = createVigil<User>({ strategies: [], session: { store: new MemorySessionStore() } });
    const req = fakeRequest<User>();
    const { error } = await run(vigil.optionalAuth(), req);
    expect(error).toBeUndefined();
    expect(req.user).toBeNull();
  });

  it("renews the session's ttl on load by default (rolling sessions)", async () => {
    const store = new MemorySessionStore();
    const touchSpy = vi.spyOn(store, "touch");
    await store.set("sess-1", { subject: { id: "9" }, createdAt: Date.now() });

    const vigil = createVigil<User>({ strategies: [], session: { store, cookie: { maxAge: 3600 } } });
    await run(vigil.requireAuth(), fakeRequest<User>({ cookies: { "vigil.sid": "sess-1" } }));

    expect(touchSpy).toHaveBeenCalledWith("sess-1", 3600);
  });

  it("does not renew the session's ttl when rolling: false", async () => {
    const store = new MemorySessionStore();
    const touchSpy = vi.spyOn(store, "touch");
    await store.set("sess-1", { subject: { id: "9" }, createdAt: Date.now() });

    const vigil = createVigil<User>({
      strategies: [],
      session: { store, rolling: false, cookie: { maxAge: 3600 } },
    });
    await run(vigil.requireAuth(), fakeRequest<User>({ cookies: { "vigil.sid": "sess-1" } }));

    expect(touchSpy).not.toHaveBeenCalled();
  });
});

describe("getUserBySessionId", () => {
  it("resolves the user for a valid session id without a request/response cycle", async () => {
    const store = new MemorySessionStore();
    await store.set("sess-1", { subject: { id: "9" }, createdAt: Date.now() });
    const vigil = createVigil<User>({ strategies: [], session: { store } });

    expect(await vigil.getUserBySessionId("sess-1")).toEqual({ id: "9" });
  });

  it("returns null for an unknown session id", async () => {
    const vigil = createVigil<User>({ strategies: [], session: { store: new MemorySessionStore() } });
    expect(await vigil.getUserBySessionId("missing")).toBeNull();
  });

  it("returns null when sessions are disabled", async () => {
    const vigil = createVigil<User>({ strategies: [], session: false });
    expect(await vigil.getUserBySessionId("anything")).toBeNull();
  });
});

describe("listSessions / revokeAllSessions", () => {
  it("lists and revokes every session for a user", async () => {
    const store = new MemorySessionStore();
    const vigil = createVigil<User>({ strategies: [], session: { store } });

    await store.set("sess-1", { subject: { id: "1" }, createdAt: Date.now() });
    await store.set("sess-2", { subject: { id: "1" }, createdAt: Date.now() });
    await store.set("sess-3", { subject: { id: "2" }, createdAt: Date.now() });

    const sessions = await vigil.listSessions({ id: "1" });
    expect(sessions.sort()).toEqual(["sess-1", "sess-2"]);

    await vigil.revokeAllSessions({ id: "1" });
    expect(await store.get("sess-1")).toBeNull();
    expect(await store.get("sess-2")).toBeNull();
    expect(await store.get("sess-3")).not.toBeNull();
  });

  it("throws when the store doesn't support listByUser/destroyAllForUser", async () => {
    const bareStore = {
      get: async () => null,
      set: async () => {},
      destroy: async () => {},
    };
    const vigil = createVigil<User>({ strategies: [], session: { store: bareStore } });

    await expect(vigil.listSessions({ id: "1" })).rejects.toThrow();
    await expect(vigil.revokeAllSessions({ id: "1" })).rejects.toThrow();
  });
});

describe("authorize", () => {
  it("allows a matching role and rejects otherwise", async () => {
    const vigil = createVigil<User>({ strategies: [], session: false });

    const allowed = fakeRequest<User>({ user: { id: "1", role: "admin" } });
    const { error: allowedError } = await run(vigil.authorize("admin", "superadmin"), allowed);
    expect(allowedError).toBeUndefined();

    const denied = fakeRequest<User>({ user: { id: "1", role: "member" } });
    const { error: deniedError } = await run(vigil.authorize("admin"), denied);
    expect(isAuthError(deniedError) && deniedError.code).toBe("FORBIDDEN");
  });
});

describe("logout", () => {
  it("destroys the session and clears the cookie", async () => {
    const store = new MemorySessionStore();
    await store.set("sess-1", { subject: { id: "1" }, createdAt: Date.now() });

    const vigil = createVigil<User>({ strategies: [], session: { store, cookie: { name: "vigil.sid" } } });
    const req = fakeRequest<User>({ cookies: { "vigil.sid": "sess-1" } });

    const { res } = await run(vigil.logout(), req);
    expect(res.cleared).toContain("vigil.sid");
    expect(await store.get("sess-1")).toBeNull();
    expect(req.user).toBeNull();
  });
});

describe("csrf", () => {
  it("issues a token on safe methods and validates it on unsafe ones", async () => {
    const vigil = createVigil<User>({ strategies: [], session: false });

    const getReq = fakeRequest<User>({ method: "GET" });
    const { res: getRes } = await run(vigil.csrf(), getReq);
    const token = getRes.cookies["vigil.csrf"]!;
    expect(token).toBeDefined();
    expect(getReq.csrfToken?.()).toBe(token);

    const postReq = fakeRequest<User>({
      method: "POST",
      cookies: { "vigil.csrf": token },
      headers: { "x-csrf-token": token },
    });
    const { error: okError } = await run(vigil.csrf(), postReq);
    expect(okError).toBeUndefined();

    const badReq = fakeRequest<User>({
      method: "POST",
      cookies: { "vigil.csrf": token },
      headers: { "x-csrf-token": "wrong" },
    });
    const { error: badError } = await run(vigil.csrf(), badReq);
    expect(isAuthError(badError) && badError.code).toBe("CSRF_INVALID");
  });
});

describe("rateLimit", () => {
  it("blocks requests once the max is exceeded", async () => {
    const vigil = createVigil<User>({ strategies: [], session: false });
    const handler = vigil.rateLimit({ window: 60, max: 2, keyBy: "ip" });
    const req = fakeRequest<User>({ ip: "1.2.3.4" });

    expect((await run(handler, req)).error).toBeUndefined();
    expect((await run(handler, req)).error).toBeUndefined();
    const third = await run(handler, req);
    expect(isAuthError(third.error) && third.error.code).toBe("RATE_LIMITED");
  });
});
