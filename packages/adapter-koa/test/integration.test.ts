import { describe, expect, it } from "vitest";
import Koa from "koa";
import Router from "@koa/router";
import request from "supertest";
import { SignJWT } from "jose";
import { createVigil, MemorySessionStore } from "@vigil/core";
import { LocalStrategy } from "@vigil/strategy-local";
import { JwtStrategy } from "@vigil/strategy-jwt";
import { toKoa } from "@vigil/adapter-koa";

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

  const app = new Koa();
  const router = new Router();

  router.post("/login", toKoa(vigil.authenticate("local")), (ctx) => {
    ctx.body = { user: ctx.state.user };
  });

  router.get("/dashboard", toKoa(vigil.requireAuth()), (ctx) => {
    ctx.body = { user: ctx.state.user };
  });

  router.get("/admin", toKoa(vigil.requireAuth()), toKoa(vigil.authorize("admin")), (ctx) => {
    ctx.body = { ok: true };
  });

  router.get("/api/me", toKoa(vigil.authenticate("jwt", { session: false })), (ctx) => {
    ctx.body = { user: ctx.state.user };
  });

  router.post("/logout", toKoa(vigil.logout()), (ctx) => {
    ctx.body = { ok: true };
  });

  app.use(async (ctx, next) => {
    try {
      await next();
    } catch (err) {
      const status = (err as { status?: number } | undefined)?.status ?? 500;
      ctx.status = status;
      ctx.body = { error: (err as Error)?.message ?? "error" };
    }
  });
  app.use(router.routes());

  return app.callback();
}

describe("koa adapter integration", () => {
  it("logs in, sets a session cookie, and reaches a protected route", async () => {
    const agent = request.agent(buildApp());

    const login = await agent.post("/login").send({ email: "alice@example.com", password: "hunter2" });
    expect(login.status).toBe(200);
    expect(login.body.user.email).toBe("alice@example.com");
    expect(login.headers["set-cookie"]?.[0]).toMatch(/vigil\.sid=/);

    const dashboard = await agent.get("/dashboard");
    expect(dashboard.status).toBe(200);
    expect(dashboard.body.user.id).toBe("1");
  });

  it("rejects bad credentials with 401", async () => {
    const res = await request(buildApp()).post("/login").send({ email: "alice@example.com", password: "wrong" });
    expect(res.status).toBe(401);
  });

  it("rejects unauthenticated access to protected routes", async () => {
    const res = await request(buildApp()).get("/dashboard");
    expect(res.status).toBe(401);
  });

  it("enforces role-based authorization", async () => {
    const agent = request.agent(buildApp());
    await agent.post("/login").send({ email: "alice@example.com", password: "hunter2" });
    const res = await agent.get("/admin");
    expect(res.status).toBe(200);
  });

  it("logs out and revokes the session", async () => {
    const agent = request.agent(buildApp());
    await agent.post("/login").send({ email: "alice@example.com", password: "hunter2" });
    await agent.post("/logout");
    const res = await agent.get("/dashboard");
    expect(res.status).toBe(401);
  });

  it("authenticates JWT bearer tokens on stateless routes", async () => {
    const token = await new SignJWT({ sub: "1" })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(JWT_SECRET));

    const res = await request(buildApp()).get("/api/me").set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe("1");
  });
});
