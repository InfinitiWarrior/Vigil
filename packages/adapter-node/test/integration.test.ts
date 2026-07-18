import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import request from "supertest";
import { SignJWT } from "jose";
import { createVigil, MemorySessionStore } from "@vigil/core";
import { LocalStrategy } from "@vigil/strategy-local";
import { JwtStrategy } from "@vigil/strategy-jwt";
import { composeNode, toNode, type NodeHandler, type VigilNodeRequest } from "@vigil/adapter-node";

interface User {
  id: string;
  email: string;
  role: string;
}

const JWT_SECRET = "integration-test-secret-integration";

const accounts: (User & { password: string })[] = [
  { id: "1", email: "alice@example.com", password: "hunter2", role: "admin" },
];

function json(res: ServerResponse, body: unknown): void {
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

function route(
  method: string,
  path: string,
  ...handlers: NodeHandler[]
): { method: string; path: string; dispatch: ReturnType<typeof composeNode> } {
  return { method, path, dispatch: composeNode(...handlers) };
}

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

  const routes = [
    route("POST", "/login", toNode(vigil.authenticate("local")), (req, res) => {
      json(res, { user: (req as VigilNodeRequest<User>).user });
    }),
    route("GET", "/dashboard", toNode(vigil.requireAuth()), (req, res) => {
      json(res, { user: (req as VigilNodeRequest<User>).user });
    }),
    route("GET", "/admin", toNode(vigil.requireAuth()), toNode(vigil.authorize("admin")), (_req, res) => {
      json(res, { ok: true });
    }),
    route("GET", "/api/me", toNode(vigil.authenticate("jwt", { session: false })), (req, res) => {
      json(res, { user: (req as VigilNodeRequest<User>).user });
    }),
    route("POST", "/logout", toNode(vigil.logout()), (_req, res) => {
      json(res, { ok: true });
    }),
  ];

  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const path = (req.url ?? "/").split("?")[0];
    const matched = routes.find((r) => r.method === req.method && r.path === path);
    if (!matched) {
      res.statusCode = 404;
      res.end();
      return;
    }
    matched.dispatch(req, res);
  });
}

describe("node adapter integration", () => {
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
