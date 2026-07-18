import express from "express";
import { SignJWT } from "jose";
import { createVigil, MemorySessionStore } from "@vigil/core";
import { LocalStrategy } from "@vigil/strategy-local";
import { JwtStrategy } from "@vigil/strategy-jwt";
import { toExpress } from "@vigil/adapter-express";

interface User {
  id: string;
  email: string;
  role: "admin" | "member";
}

// Stand-in for a real database — Vigil never touches storage itself.
const users: (User & { password: string })[] = [
  { id: "1", email: "alice@example.com", password: "hunter2", role: "admin" },
  { id: "2", email: "bob@example.com", password: "hunter2", role: "member" },
];

const JWT_SECRET = process.env.JWT_SECRET ?? "dev-only-secret-change-me";

const local = new LocalStrategy<User>({
  usernameField: "email",
  verify: async (email, password) => {
    const found = users.find((u) => u.email === email);
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
    const found = users.find((u) => u.id === payload.sub);
    if (!found) return { success: false, reason: "Unknown user" };
    const { password: _password, ...user } = found;
    return { success: true, user };
  },
});

const vigil = createVigil<User>({
  strategies: [local, jwt],
  session: {
    store: new MemorySessionStore(), // dev only — swap in @vigil/session-redis for production
    cookie: { name: "vigil.sid", maxAge: 86400 },
  },
});

const app = express();
app.use(express.json());

// Session-based login: sets a vigil.sid cookie on success. rateLimit() is
// applied first — vigil.authenticate() has no automatic brute-force
// protection on its own (see SECURITY.md), so a login route should always
// be paired with something like this. keyBy: "body.email" rate-limits per
// attempted account rather than per IP, which also blunts credential
// stuffing across many IPs against one account.
app.post(
  "/login",
  toExpress(vigil.rateLimit({ window: 60, max: 5, keyBy: "body.email" })),
  toExpress(vigil.authenticate("local")),
  (req, res) => {
    res.json({ user: req.user });
  },
);

// Issues a short-lived JWT for the currently logged-in session — demonstrates
// mixing session auth (to establish who you are) with stateless bearer auth
// (for, e.g., a separate API host that shouldn't share cookies).
app.post("/token", toExpress(vigil.requireAuth()), async (req, res) => {
  const user = req.user as User;
  const token = await new SignJWT({ sub: user.id })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("15m")
    .sign(new TextEncoder().encode(JWT_SECRET));
  res.json({ token });
});

app.get("/dashboard", toExpress(vigil.requireAuth()), (req, res) => {
  res.json({ user: req.user });
});

app.get("/admin", toExpress(vigil.requireAuth()), toExpress(vigil.authorize("admin")), (req, res) => {
  res.json({ ok: true, user: req.user });
});

// Stateless API route: no cookie needed, just `Authorization: Bearer <token>`.
app.get("/api/me", toExpress(vigil.authenticate("jwt", { session: false })), (req, res) => {
  res.json({ user: req.user });
});

app.post("/logout", toExpress(vigil.logout()), (_req, res) => {
  res.json({ ok: true });
});

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const status = (err as { status?: number } | undefined)?.status ?? 500;
  res.status(status).json({ error: (err as Error)?.message ?? "error" });
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  console.log(`Vigil example listening on http://localhost:${port}`);
});
