import { describe, expect, it } from "vitest";
import Fastify from "fastify";
import { SignJWT } from "jose";
import { createVigil, MemorySessionStore } from "@vigil/core";
import { LocalStrategy } from "@vigil/strategy-local";
import { JwtStrategy } from "@vigil/strategy-jwt";
import { toFastify } from "@vigil/adapter-fastify";

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

  const app = Fastify();

  app.post("/login", { preHandler: toFastify(vigil.authenticate("local")) }, async (request) => {
    return { user: request.user };
  });

  app.get("/dashboard", { preHandler: toFastify(vigil.requireAuth()) }, async (request) => {
    return { user: request.user };
  });

  app.get(
    "/admin",
    { preHandler: [toFastify(vigil.requireAuth()), toFastify(vigil.authorize("admin"))] },
    async () => ({ ok: true }),
  );

  app.get(
    "/api/me",
    { preHandler: toFastify(vigil.authenticate("jwt", { session: false })) },
    async (request) => ({ user: request.user }),
  );

  app.post("/logout", { preHandler: toFastify(vigil.logout()) }, async () => ({ ok: true }));

  app.setErrorHandler((err, _request, reply) => {
    const status = (err as { status?: number }).status ?? 500;
    reply.status(status).send({ error: err.message });
  });

  return app;
}

function extractCookie(setCookieHeaders: string | string[] | undefined, name: string): string | undefined {
  const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : setCookieHeaders ? [setCookieHeaders] : [];
  for (const header of headers) {
    if (header.startsWith(`${name}=`)) return header.split(";")[0]!.slice(name.length + 1);
  }
  return undefined;
}

describe("fastify adapter integration", () => {
  it("logs in, sets a session cookie, and reaches a protected route", async () => {
    const app = buildApp();

    const login = await app.inject({
      method: "POST",
      url: "/login",
      payload: { email: "alice@example.com", password: "hunter2" },
    });
    expect(login.statusCode).toBe(200);
    expect(login.json().user.email).toBe("alice@example.com");

    const sessionId = extractCookie(login.headers["set-cookie"], "vigil.sid");
    expect(sessionId).toBeTruthy();

    const dashboard = await app.inject({
      method: "GET",
      url: "/dashboard",
      cookies: { "vigil.sid": sessionId! },
    });
    expect(dashboard.statusCode).toBe(200);
    expect(dashboard.json().user.id).toBe("1");
  });

  it("rejects bad credentials with 401", async () => {
    const app = buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/login",
      payload: { email: "alice@example.com", password: "wrong" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("rejects unauthenticated access to protected routes", async () => {
    const app = buildApp();
    const res = await app.inject({ method: "GET", url: "/dashboard" });
    expect(res.statusCode).toBe(401);
  });

  it("enforces role-based authorization", async () => {
    const app = buildApp();
    const login = await app.inject({
      method: "POST",
      url: "/login",
      payload: { email: "alice@example.com", password: "hunter2" },
    });
    const sessionId = extractCookie(login.headers["set-cookie"], "vigil.sid")!;

    const res = await app.inject({ method: "GET", url: "/admin", cookies: { "vigil.sid": sessionId } });
    expect(res.statusCode).toBe(200);
  });

  it("logs out and revokes the session", async () => {
    const app = buildApp();
    const login = await app.inject({
      method: "POST",
      url: "/login",
      payload: { email: "alice@example.com", password: "hunter2" },
    });
    const sessionId = extractCookie(login.headers["set-cookie"], "vigil.sid")!;

    await app.inject({ method: "POST", url: "/logout", cookies: { "vigil.sid": sessionId } });

    const res = await app.inject({ method: "GET", url: "/dashboard", cookies: { "vigil.sid": sessionId } });
    expect(res.statusCode).toBe(401);
  });

  it("authenticates JWT bearer tokens on stateless routes", async () => {
    const app = buildApp();
    const token = await new SignJWT({ sub: "1" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(JWT_SECRET));

    const res = await app.inject({
      method: "GET",
      url: "/api/me",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().user.id).toBe("1");
  });
});
