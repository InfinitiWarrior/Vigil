import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import { SignJWT } from "jose";
import { createVigil, MemorySessionStore } from "@vigil/core";
import { LocalStrategy } from "@vigil/strategy-local";
import { JwtStrategy } from "@vigil/strategy-jwt";
import { toHono } from "@vigil/adapter-hono";

interface User {
  id: string;
  email: string;
  role: string;
}

const JWT_SECRET = "integration-test-secret-integration";

const accounts: (User & { password: string })[] = [
  { id: "1", email: "alice@example.com", password: "hunter2", role: "admin" },
];

function buildApp() {
  const local = new LocalStrategy<User>({
    usernameField: "email",
    verify: async (email, password) => {
      const found = accounts.find((u) => u.email === email);
      if (!found || found.password !== password) {
        return { success: false, reason: "Invalid credentials", status: 401 };
      }
      const { password: _password, ...user } = found;
      return { success: true, user };
    },
  });

  const jwt = new JwtStrategy<User>({
    secret: JWT_SECRET,
    algorithms: ["HS256"],
    verify: async (payload) => {
      const found = accounts.find((u) => u.id === payload.sub);
      if (!found) return { success: false, reason: "Unknown user" };
      const { password: _password, ...user } = found;
      return { success: true, user };
    },
  });

  const vigil = createVigil<User>({
    strategies: [local, jwt],
    session: { store: new MemorySessionStore(), cookie: { name: "vigil.sid" } },
  });

  const app = new Hono();

  app.post("/login", toHono(vigil.authenticate("local")), (c) => c.json({ user: c.get("user") }));

  app.get("/dashboard", toHono(vigil.requireAuth()), (c) => c.json({ user: c.get("user") }));

  app.get("/admin", toHono(vigil.requireAuth()), toHono(vigil.authorize("admin")), (c) => c.json({ ok: true }));

  app.get("/api/me", toHono(vigil.authenticate("jwt", { session: false })), (c) => c.json({ user: c.get("user") }));

  app.post("/logout", toHono(vigil.logout()), (c) => c.json({ ok: true }));

  app.onError((err, c) => {
    const status = (err as { status?: number }).status ?? 500;
    return c.json({ error: err.message }, status as Parameters<typeof c.json>[1]);
  });

  return app;
}

function extractCookie(response: Response, name: string): string | undefined {
  for (const value of response.headers.getSetCookie()) {
    if (value.startsWith(`${name}=`)) return value.split(";")[0]!.slice(name.length + 1);
  }
  return undefined;
}

describe("hono adapter integration", () => {
  it("logs in, sets a session cookie, and reaches a protected route", async () => {
    const app = buildApp();

    const login = await app.request("/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "alice@example.com", password: "hunter2" }),
    });
    expect(login.status).toBe(200);
    expect((await login.json()).user.email).toBe("alice@example.com");

    const sessionId = extractCookie(login, "vigil.sid");
    expect(sessionId).toBeTruthy();

    const dashboard = await app.request("/dashboard", {
      headers: { cookie: `vigil.sid=${sessionId}` },
    });
    expect(dashboard.status).toBe(200);
    expect((await dashboard.json()).user.id).toBe("1");
  });

  it("rejects bad credentials with 401", async () => {
    const app = buildApp();
    const res = await app.request("/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "alice@example.com", password: "wrong" }),
    });
    expect(res.status).toBe(401);
  });

  it("rejects unauthenticated access to protected routes", async () => {
    const app = buildApp();
    const res = await app.request("/dashboard");
    expect(res.status).toBe(401);
  });

  it("enforces role-based authorization", async () => {
    const app = buildApp();
    const login = await app.request("/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "alice@example.com", password: "hunter2" }),
    });
    const sessionId = extractCookie(login, "vigil.sid")!;

    const res = await app.request("/admin", { headers: { cookie: `vigil.sid=${sessionId}` } });
    expect(res.status).toBe(200);
  });

  it("logs out and revokes the session", async () => {
    const app = buildApp();
    const login = await app.request("/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "alice@example.com", password: "hunter2" }),
    });
    const sessionId = extractCookie(login, "vigil.sid")!;

    await app.request("/logout", { method: "POST", headers: { cookie: `vigil.sid=${sessionId}` } });

    const res = await app.request("/dashboard", { headers: { cookie: `vigil.sid=${sessionId}` } });
    expect(res.status).toBe(401);
  });

  it("authenticates JWT bearer tokens on stateless routes", async () => {
    const app = buildApp();
    const token = await new SignJWT({ sub: "1" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(JWT_SECRET));

    const res = await app.request("/api/me", { headers: { authorization: `Bearer ${token}` } });
    expect(res.status).toBe(200);
    expect((await res.json()).user.id).toBe("1");
  });
});
