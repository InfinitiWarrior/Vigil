# Vigil

**Modern authentication middleware for Node.js.** A typed, async/await-native
replacement for the parts of Passport.js that were middleware — not a full
auth platform. Vigil verifies requests. It doesn't own your database,
generate UI, or manage users.

See [DESIGN.md](./DESIGN.md) for the full design doc and roadmap. This
README covers what's actually built and how to use it today.

## Status: v0.1 (MVP)

Implemented and tested:

- `@vigil/core` — engine, types, crypto helpers, in-memory session/rate-limit stores
- `@vigil/strategy-local` — username/password
- `@vigil/strategy-jwt` — JWT bearer tokens (built on [`jose`](https://github.com/panva/jose))
- `@vigil/adapter-express` — Express middleware adapter
- `@vigil/test` — mock strategies and test harness

Everything else in DESIGN.md (OAuth2, WebAuthn, magic links, TOTP, SAML,
Fastify/Hono/Koa adapters, Redis session store) is roadmap, not yet built.

## Quick start

```bash
pnpm add @vigil/core @vigil/strategy-local @vigil/strategy-jwt @vigil/adapter-express express
pnpm add @node-rs/argon2   # only needed if you use vigil's crypto.hashPassword/verifyPassword
```

```typescript
import express from "express";
import { createVigil, MemorySessionStore } from "@vigil/core";
import { LocalStrategy } from "@vigil/strategy-local";
import { JwtStrategy } from "@vigil/strategy-jwt";
import { toExpress } from "@vigil/adapter-express";

interface User {
  id: string;
  email: string;
  role: string;
}

const local = new LocalStrategy<User>({
  usernameField: "email",
  verify: async (email, password) => {
    const user = await db.users.findByEmail(email);
    if (!user) return { success: false, reason: "User not found" };
    const valid = await crypto.verifyPassword(user.passwordHash, password);
    if (!valid) return { success: false, reason: "Invalid password" };
    return { success: true, user };
  },
});

const jwt = new JwtStrategy<User>({
  secret: process.env.JWT_SECRET!,
  algorithms: ["HS256"],
  verify: async (payload) => {
    const user = await db.users.findById(payload.sub);
    if (!user) return { success: false, reason: "User not found" };
    return { success: true, user };
  },
});

const vigil = createVigil<User>({
  strategies: [local, jwt],
  session: {
    store: new MemorySessionStore(), // dev only — implement SessionStore against Redis/Postgres for prod
    cookie: { name: "vigil.sid", maxAge: 86400 },
  },
});

const app = express();
app.use(express.json());

// Session login
app.post("/login", toExpress(vigil.authenticate("local")), (req, res) => {
  res.json({ user: req.user });
});

app.get("/dashboard", toExpress(vigil.requireAuth()), (req, res) => {
  res.json({ user: req.user });
});

app.delete(
  "/admin/users/:id",
  toExpress(vigil.requireAuth()),
  toExpress(vigil.authorize("admin")),
  handler,
);

app.post("/logout", toExpress(vigil.logout({ redirectTo: "/" })));

// Stateless API auth
app.get("/api/me", toExpress(vigil.authenticate("jwt", { session: false })), (req, res) => {
  res.json({ user: req.user });
});

app.use((err, req, res, next) => {
  const status = err.status ?? 500;
  res.status(status).json({ error: err.code ?? "ERROR", message: err.message });
});
```

## Development

```bash
pnpm install
pnpm build       # tsup build of every package (esm + cjs + .d.ts)
pnpm typecheck   # tsc --noEmit per package
pnpm test        # vitest, runs against source via path aliases (no build required)
```

Monorepo layout: pnpm workspaces, one package per `packages/*`, each with its
own `package.json`/`tsconfig.json` and a `tsup` build producing dual
ESM/CJS output plus type declarations.

## Notable implementation decisions

- **Argon2id is an optional dependency, not a hard one.** `@vigil/core`'s
  engine has zero runtime dependencies. `crypto.hashPassword`/`verifyPassword`
  dynamically `import()` `@node-rs/argon2` only when called, with a clear
  error if it isn't installed — so the core package stays dependency-free
  for anyone not using its password hashing helpers.
- **`vigil.requireAuth()`/`optionalAuth()` load the session, `authenticate()`
  establishes it.** There's no separate `passport.session()` middleware;
  session-cookie lookup is folded into the guards.
- **CSRF uses the double-submit cookie pattern** (readable cookie + header/body
  token comparison), not server-side token storage.
- **Rate limiting and session stores default to in-memory implementations**
  suitable for development and single-process deployments; swap in Redis/etc.
  via the `SessionStore`/`RateLimitStore` interfaces for production.
