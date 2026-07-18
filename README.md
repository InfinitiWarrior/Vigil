# Vigil

**Modern authentication middleware for Node.js.** A typed, async/await-native
replacement for the parts of Passport.js that were middleware — not a full
auth platform. Vigil verifies requests. It doesn't own your database,
generate UI, or manage users.

See [DESIGN.md](./DESIGN.md) for the full design doc and roadmap. This
README covers what's actually built and how to use it today.

## Status

Every strategy and adapter from DESIGN.md's original roadmap is implemented
and tested (172 tests across 19 packages), plus several things beyond it:

- `@vigil/core` — engine, types, crypto helpers, CSRF and rate-limit
  middleware, in-memory session/rate-limit stores. Sessions are rolling
  (sliding expiration) by default; `vigil.listSessions()`/
  `revokeAllSessions()` support "sign out everywhere" for stores that index
  by user; `vigil.getUserBySessionId()` resolves a user outside a normal
  request/response cycle (see the Next.js Server Component example below).
- Strategies: `strategy-local`, `strategy-jwt` (built on
  [`jose`](https://github.com/panva/jose)), `strategy-oauth2`
  (Google/GitHub/Apple/Microsoft/Discord/GitLab presets, PKCE by default),
  `strategy-apikey`, `strategy-totp` (with replay protection), `strategy-magic-link`,
  `strategy-webauthn`, `strategy-saml`
- Adapters: `adapter-express`, `adapter-fastify`, `adapter-hono`,
  `adapter-koa`, `adapter-node` (raw `node:http`, no framework dependency),
  `adapter-bun` (Bun.serve / Fetch API), `adapter-cloudflare` (Workers /
  Fetch API), `adapter-nextjs` (App Router: middleware, Route Handlers, and
  Server Components)
- `@vigil/session-redis` — Redis-backed `SessionStore` and `RateLimitStore`
- `@vigil/test` — mock strategies and test harness

See [SECURITY.md](./SECURITY.md) for an OWASP-guided self-audit of the auth-
critical code paths. Not yet built: a Deno adapter, community strategies
(see DESIGN.md's v1.x+ roadmap).

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

app.delete("/admin/users/:id", toExpress(vigil.requireAuth()), toExpress(vigil.authorize("admin")), handler);

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

### Next.js (App Router)

`@vigil/adapter-nextjs` covers all three places Next.js needs auth: edge
middleware, Route Handlers, and Server Components (which have no
Request/Response cycle to run middleware against at all).

```typescript
// lib/vigil.ts — shared instance, imported by middleware.ts, route handlers, and Server Components
export const vigil = createVigil<User>({ strategies: [local], session: { store, cookie: { name: "vigil.sid" } } });
```

```typescript
// middleware.ts — gate a whole route group at the edge
import { composeNextMiddleware, toNext } from "@vigil/adapter-nextjs";
import { vigil } from "./lib/vigil";

export default composeNextMiddleware(toNext(vigil.requireAuth({ redirectTo: "/login" })));
export const config = { matcher: "/dashboard/:path*" };
```

```typescript
// app/api/login/route.ts
import { composeNextRoute, toNext } from "@vigil/adapter-nextjs";
import { vigil } from "@/lib/vigil";

export const POST = composeNextRoute(
  toNext(vigil.authenticate("local")),
  toNext(async (req, res) => res.json({ user: req.user })),
);
```

```typescript
// app/dashboard/page.tsx — Server Component: no request object, so this
// reads the session cookie via next/headers instead.
import { getVigilUser } from "@vigil/adapter-nextjs";
import { vigil } from "@/lib/vigil";

export default async function DashboardPage() {
  const user = await getVigilUser(vigil);
  if (!user) redirect("/login");
  return <p>Welcome, {user.email}</p>;
}
```

## Development

```bash
pnpm install
pnpm build       # tsup build of every package (esm + cjs + .d.ts)
pnpm typecheck   # tsc --noEmit per package
pnpm test        # vitest, runs against source via path aliases (no build required)
pnpm lint        # eslint
pnpm format      # prettier --write
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full contribution workflow.

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
  suitable for development and single-process deployments; swap in
  `@vigil/session-redis` (or your own `SessionStore`/`RateLimitStore`) for
  production.
- **Authentication failure messages are generic by default.** A strategy's
  `verify()` might return "User not found" vs. "Invalid password" — Vigil
  doesn't send that distinction to the client unless `authenticate()` is
  called with `{ exposeFailureReason: true }`, since differing messages are
  a classic user-enumeration leak. The real reason is always available on
  `AuthError.detail` for logging/hooks.
- **Cookies' `Secure` attribute is detected from the request, not just
  `NODE_ENV`.** Every adapter populates `VigilRequest.secure` from the
  actual connection (TLS, or a trusted `X-Forwarded-Proto`), so a production
  deployment that forgets to set `NODE_ENV=production` doesn't silently ship
  cookies without `Secure`.
