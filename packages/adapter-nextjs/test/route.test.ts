import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { SignJWT } from "jose";
import { createVigil, MemorySessionStore } from "@vigil/core";
import { LocalStrategy } from "@vigil/strategy-local";
import { JwtStrategy } from "@vigil/strategy-jwt";
import { composeNextRoute, toNext } from "@vigil/adapter-nextjs";

interface User {
  id: string;
  email: string;
  role: string;
}

const JWT_SECRET = "integration-test-secret-integration";

const accounts: (User & { password: string })[] = [
  { id: "1", email: "alice@example.com", password: "hunter2", role: "admin" },
];

const sendUser = toNext<User>(async (req, res) => {
  res.json({ user: req.user });
});

const sendOk = toNext<User>(async (_req, res) => {
  res.json({ ok: true });
});

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

  const routes: Record<string, ReturnType<typeof composeNextRoute<User>>> = {
    "POST /login": composeNextRoute(toNext(vigil.authenticate("local")), sendUser),
    "GET /dashboard": composeNextRoute(toNext(vigil.requireAuth()), sendUser),
    "GET /admin": composeNextRoute(toNext(vigil.requireAuth()), toNext(vigil.authorize("admin")), sendOk),
    "GET /api/me": composeNextRoute(toNext(vigil.authenticate("jwt", { session: false })), sendUser),
    "POST /logout": composeNextRoute(toNext(vigil.logout()), sendOk),
  };

  return async (req: NextRequest): Promise<Response> => {
    const url = new URL(req.url);
    const handler = routes[`${req.method} ${url.pathname}`];
    if (!handler) return new Response(null, { status: 404 });
    return handler(req);
  };
}

function extractCookie(response: Response, name: string): string | undefined {
  for (const value of response.headers.getSetCookie()) {
    if (value.startsWith(`${name}=`)) return value.split(";")[0]!.slice(name.length + 1);
  }
  return undefined;
}

describe("Next.js Route Handler integration", () => {
  it("logs in, sets a session cookie, and reaches a protected route", async () => {
    const app = buildApp();

    const login = await app(
      new NextRequest("http://localhost/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "alice@example.com", password: "hunter2" }),
      }),
    );
    expect(login.status).toBe(200);
    expect((await login.json()).user.email).toBe("alice@example.com");

    const sessionId = extractCookie(login, "vigil.sid");
    expect(sessionId).toBeTruthy();

    const dashboard = await app(
      new NextRequest("http://localhost/dashboard", { headers: { cookie: `vigil.sid=${sessionId}` } }),
    );
    expect(dashboard.status).toBe(200);
    expect((await dashboard.json()).user.id).toBe("1");
  });

  it("rejects bad credentials with 401", async () => {
    const app = buildApp();
    const res = await app(
      new NextRequest("http://localhost/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "alice@example.com", password: "wrong" }),
      }),
    );
    expect(res.status).toBe(401);
  });

  it("rejects unauthenticated access to protected routes", async () => {
    const app = buildApp();
    const res = await app(new NextRequest("http://localhost/dashboard"));
    expect(res.status).toBe(401);
  });

  it("enforces role-based authorization", async () => {
    const app = buildApp();
    const login = await app(
      new NextRequest("http://localhost/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "alice@example.com", password: "hunter2" }),
      }),
    );
    const sessionId = extractCookie(login, "vigil.sid");

    const res = await app(new NextRequest("http://localhost/admin", { headers: { cookie: `vigil.sid=${sessionId}` } }));
    expect(res.status).toBe(200);
  });

  it("logs out and revokes the session", async () => {
    const app = buildApp();
    const login = await app(
      new NextRequest("http://localhost/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "alice@example.com", password: "hunter2" }),
      }),
    );
    const sessionId = extractCookie(login, "vigil.sid");

    await app(
      new NextRequest("http://localhost/logout", { method: "POST", headers: { cookie: `vigil.sid=${sessionId}` } }),
    );

    const res = await app(
      new NextRequest("http://localhost/dashboard", { headers: { cookie: `vigil.sid=${sessionId}` } }),
    );
    expect(res.status).toBe(401);
  });

  it("authenticates JWT bearer tokens on stateless routes", async () => {
    const app = buildApp();
    const token = await new SignJWT({ sub: "1" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(JWT_SECRET));

    const res = await app(
      new NextRequest("http://localhost/api/me", { headers: { authorization: `Bearer ${token}` } }),
    );
    expect(res.status).toBe(200);
    expect((await res.json()).user.id).toBe("1");
  });
});
