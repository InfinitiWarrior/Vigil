# Vigil

**Modern authentication middleware for Node.js.**
A ground-up replacement for Passport.js built on TypeScript, async/await, and the current auth landscape.

---

## Why "Vigil"

Latin *vigilia*: a watchful guard, one who stays alert. Five characters, no collisions with major JS ecosystem projects, communicates exactly what authentication middleware does: it watches every request and decides who gets through. The name also carries a quiet, understated tone that matches the design philosophy: do the job well, stay out of the way.

Alternative names if `vigil` is taken on npm: **Rampart**, **Gatehouse**, **Wardpost**.

---

## Positioning

Passport.js still gets ~7.5 million weekly downloads (fact, npm trends July 2026). Better Auth has absorbed Auth.js/NextAuth and dominates the "full auth solution" space (fact, confirmed June 2026). But Better Auth is a complete system: it owns your database schema, sessions, user management, and UI. Passport was never that. Passport was middleware. It sat between the request and your route handler and answered one question: *is this request authenticated?*

That middleware layer is what's dead. Better Auth, Clerk, WorkOS, Supabase Auth are all full platforms. Vigil is not a platform. It is a library. It verifies requests. It doesn't touch your database. It doesn't generate UI. It doesn't manage users. It authenticates.

**Vigil's niche:** developers who use Express, Fastify, Hono, Koa, or raw Node.js and want a clean, typed, modern middleware that handles authentication strategies without absorbing their entire backend architecture.

---

## Design Principles

1. **TypeScript from line one.** Not typed after the fact. Generic strategy types, typed user objects, typed middleware chains. Full autocomplete everywhere.
2. **Async/await native.** No callbacks. No `done(null, user)`. Every strategy returns a Promise.
3. **Framework agnostic via adapters.** Core logic knows nothing about Express or Fastify. Thin adapter layers translate framework-specific request/response objects.
4. **Zero opinions on storage.** Vigil never touches a database. It provides interfaces (session store, user lookup) that you implement with whatever you use.
5. **Secure defaults.** PKCE on by default for OAuth. HttpOnly + Secure + SameSite cookies by default. Argon2id for any password hashing utilities. Developers opt out of security, never opt in.
6. **Minimal dependencies.** Core has zero runtime dependencies. Strategies import only what they need (e.g., `jose` for JWT).

---

## Architecture

```
@vigil/core           Core middleware engine, strategy interface, types
@vigil/strategy-local       Username/password strategy
@vigil/strategy-oauth2      Generic OAuth 2.0 / OIDC with provider presets
@vigil/strategy-jwt         JWT Bearer token strategy
@vigil/strategy-apikey      API key strategy
@vigil/strategy-webauthn    Passkeys / WebAuthn strategy
@vigil/strategy-magic-link  Passwordless email link strategy
@vigil/strategy-totp        TOTP second-factor strategy
@vigil/strategy-saml        SAML 2.0 for enterprise SSO
@vigil/adapter-express      Express middleware adapter
@vigil/adapter-fastify      Fastify plugin adapter
@vigil/adapter-hono         Hono middleware adapter
@vigil/adapter-koa          Koa middleware adapter
@vigil/adapter-node         Raw Node.js http adapter
@vigil/adapter-bun          Bun.serve adapter
@vigil/adapter-cloudflare   Cloudflare Workers adapter
@vigil/test                 Mock strategies + test helpers
```

Each package is independently installable. A developer using Express with JWT auth installs exactly: `@vigil/core`, `@vigil/strategy-jwt`, `@vigil/adapter-express`.

---

## Core API (`@vigil/core`)

### `createVigil(config)`

Factory function. Returns the middleware engine instance.

```typescript
import { createVigil } from '@vigil/core';

const vigil = createVigil({
  strategies: [localStrategy, googleOAuth, jwtStrategy],
  session: {
    store: redisSessionStore,     // implements SessionStore interface
    cookie: {
      name: 'vigil.sid',
      maxAge: 86400,              // seconds
      httpOnly: true,             // default: true
      secure: true,               // default: true in production
      sameSite: 'lax',            // default: 'lax'
    },
  },
  serialize: (user) => user.id,
  deserialize: async (id) => db.users.findById(id),
  hooks: { ... },                 // optional lifecycle hooks
});
```

### `vigil.authenticate(strategyName, options?)`

Returns framework-agnostic middleware. The adapter wraps this for Express/Fastify/etc.

```typescript
// With Express adapter
import { toExpress } from '@vigil/adapter-express';

app.post('/login', toExpress(vigil.authenticate('local')), (req, res) => {
  res.json({ user: req.user });
});
```

Options:
- `successRedirect?: string` — redirect on success
- `failureRedirect?: string` — redirect on failure
- `failureMessage?: boolean | string` — attach failure reason to session
- `session?: boolean` — whether to establish a session (default: true)
- `scope?: string[]` — OAuth scopes to request
- `state?: boolean` — whether to validate OAuth state param (default: true)

### `vigil.requireAuth(options?)`

Guard middleware. Returns 401 if no authenticated user on the request.

```typescript
app.get('/dashboard', toExpress(vigil.requireAuth()), handler);
```

Options:
- `redirectTo?: string` — redirect instead of 401
- `message?: string` — custom 401 message

### `vigil.optionalAuth()`

Attaches user to request if session exists, continues regardless.

```typescript
app.get('/feed', toExpress(vigil.optionalAuth()), handler);
// req.user is User | null
```

### `vigil.authorize(...roles)`

RBAC (role-based access control) guard. Runs after authentication.

```typescript
app.delete('/admin/user/:id',
  toExpress(vigil.requireAuth()),
  toExpress(vigil.authorize('admin', 'superadmin')),
  handler
);
```

### `vigil.logout(options?)`

Destroys session, clears cookies, optionally revokes tokens.

```typescript
app.post('/logout', toExpress(vigil.logout({ redirectTo: '/' })));
```

### `vigil.csrf()`

CSRF protection middleware. Generates and validates tokens.

```typescript
app.use(toExpress(vigil.csrf()));
// Token available at req.csrfToken()
```

### `vigil.rateLimit(options)`

Per-route rate limiting, designed for auth endpoints.

```typescript
app.post('/login',
  toExpress(vigil.rateLimit({
    window: 900,           // 15 minutes in seconds
    max: 10,               // max attempts per window
    keyBy: 'ip',           // 'ip' | 'body.email' | custom function
    store: redisStore,     // implements RateLimitStore interface
  })),
  toExpress(vigil.authenticate('local')),
  handler
);
```

---

## Strategy Interface

Every strategy implements this interface:

```typescript
interface Strategy<TUser = unknown, TOptions = unknown> {
  name: string;
  authenticate(
    request: VigilRequest,
    options?: TOptions
  ): Promise<AuthResult<TUser>>;
}

type AuthResult<TUser> =
  | { success: true; user: TUser }
  | { success: false; reason: string; status?: number }
  | { redirect: string; status?: number };  // for OAuth redirects
```

No `done` callback. No `this` context tricks. Return a typed result.

---

## Built-in Strategies: Full Specifications

### 1. Local Strategy (`@vigil/strategy-local`)

Username/password authentication.

```typescript
import { LocalStrategy } from '@vigil/strategy-local';

const local = new LocalStrategy({
  usernameField: 'email',            // default: 'username'
  passwordField: 'password',         // default: 'password'
  verify: async (username, password) => {
    const user = await db.users.findByEmail(username);
    if (!user) return { success: false, reason: 'User not found' };
    const valid = await vigil.crypto.verify(user.passwordHash, password);
    if (!valid) return { success: false, reason: 'Invalid password' };
    return { success: true, user };
  },
});
```

Features:
- Pluggable field names (works with any form shape)
- Returns typed AuthResult (no boolean ambiguity)
- Password hashing utilities exposed via `@vigil/core` crypto module
- Timing-safe comparison to prevent timing attacks

### 2. OAuth 2.0 / OIDC Strategy (`@vigil/strategy-oauth2`)

Generic OAuth 2.0 with OpenID Connect support and provider presets.

```typescript
import { OAuth2Strategy, providers } from '@vigil/strategy-oauth2';

const google = new OAuth2Strategy({
  ...providers.google,               // pre-filled endpoints + scopes
  clientId: process.env.GOOGLE_ID,
  clientSecret: process.env.GOOGLE_SECRET,
  callbackURL: '/auth/google/callback',
  scope: ['openid', 'email', 'profile'],
  pkce: true,                        // default: true
  verify: async (tokens, profile) => {
    let user = await db.users.findByProviderId('google', profile.id);
    if (!user) user = await db.users.create({ ... });
    return { success: true, user };
  },
});
```

Built-in provider presets (pre-configured endpoints, default scopes):
- Google
- GitHub
- Apple
- Microsoft / Azure AD
- Discord
- Twitter/X
- LinkedIn
- Facebook
- Spotify
- Twitch
- Slack
- GitLab
- Bitbucket

Each preset is a plain object of URLs and default scopes. No magic, fully overridable.

Features:
- PKCE on by default (RFC 7636)
- State parameter validation on by default
- Nonce validation for OIDC
- Automatic token refresh with `refreshToken` flow
- ID token verification (for OIDC)
- Normalized profile object across providers

### 3. JWT Strategy (`@vigil/strategy-jwt`)

Bearer token authentication for APIs.

```typescript
import { JwtStrategy } from '@vigil/strategy-jwt';

const jwt = new JwtStrategy({
  secret: process.env.JWT_SECRET,     // or asymmetric key pair
  algorithms: ['HS256'],              // explicit, no default 'none'
  issuer: 'myapp',                    // optional validation
  audience: 'myapp-api',             // optional validation
  extractFrom: 'header',             // 'header' | 'cookie' | 'query' | custom fn
  verify: async (payload) => {
    const user = await db.users.findById(payload.sub);
    if (!user) return { success: false, reason: 'User not found' };
    return { success: true, user };
  },
});
```

Features:
- `algorithm: 'none'` is rejected by default (a real vulnerability in many JWT libs)
- Supports HMAC, RSA, ECDSA, EdDSA
- JWKS (JSON Web Key Set) endpoint support for key rotation
- Token extraction from Authorization header, cookies, or custom locations
- Clock tolerance configuration for distributed systems
- Built on `jose` library (maintained, audited, zero-dep)

### 4. API Key Strategy (`@vigil/strategy-apikey`)

For machine-to-machine and developer API authentication.

```typescript
import { ApiKeyStrategy } from '@vigil/strategy-apikey';

const apikey = new ApiKeyStrategy({
  extractFrom: 'header',              // 'header' | 'query' | custom fn
  headerName: 'X-API-Key',           // default
  verify: async (key) => {
    const record = await db.apiKeys.findByHash(hash(key));
    if (!record || record.revoked) return { success: false, reason: 'Invalid key' };
    return { success: true, user: record.owner };
  },
});
```

Features:
- Key generation utility (`vigil.crypto.generateApiKey()`)
- Keys are always stored hashed, never raw
- Optional prefix format (e.g., `vgl_live_abc123`) for easy identification
- Scope/permission attachment per key

### 5. WebAuthn / Passkeys Strategy (`@vigil/strategy-webauthn`)

FIDO2 passwordless authentication.

```typescript
import { WebAuthnStrategy } from '@vigil/strategy-webauthn';

const webauthn = new WebAuthnStrategy({
  rpName: 'My Application',
  rpId: 'myapp.com',
  origin: 'https://myapp.com',
  challengeStore: redisChallengeStore,   // implements ChallengeStore
  credentialStore: {                     // implements CredentialStore
    get: (credentialId) => db.credentials.find(credentialId),
    save: (userId, credential) => db.credentials.create(userId, credential),
    list: (userId) => db.credentials.findByUser(userId),
  },
});
```

Exposes two phases:
- `webauthn.registrationOptions(userId)` — generate registration challenge
- `webauthn.registrationVerify(response)` — verify and store credential
- `webauthn.authenticationOptions(userId?)` — generate auth challenge
- `webauthn.authenticate(request)` — verify assertion (standard Strategy interface)

Features:
- Passkey support (resident keys / discoverable credentials)
- Platform authenticator detection
- Multiple credentials per user
- Attestation (direct verification of authenticator, optional) and assertion (login verification)
- Built on `@simplewebauthn/server`

### 6. Magic Link Strategy (`@vigil/strategy-magic-link`)

Passwordless email authentication.

```typescript
import { MagicLinkStrategy } from '@vigil/strategy-magic-link';

const magic = new MagicLinkStrategy({
  tokenStore: redisTokenStore,        // implements TokenStore
  tokenTTL: 600,                      // 10 minutes, in seconds
  sendLink: async (email, url, token) => {
    await emailService.send({
      to: email,
      subject: 'Sign in to MyApp',
      body: `Click here to sign in: ${url}`,
    });
  },
  verify: async (email) => {
    let user = await db.users.findByEmail(email);
    if (!user) user = await db.users.create({ email });
    return { success: true, user };
  },
});
```

Exposes two phases:
- `magic.sendToken(request)` — generate token, call `sendLink`
- `magic.authenticate(request)` — verify token from callback URL

Features:
- Single-use tokens (consumed on verification)
- Configurable TTL
- Token hashing in store (tokens are secrets)
- Rate limiting hook (to prevent email flooding)

### 7. TOTP Strategy (`@vigil/strategy-totp`)

Time-based one-time password for second-factor authentication.

```typescript
import { TotpStrategy } from '@vigil/strategy-totp';

const totp = new TotpStrategy({
  issuer: 'MyApp',
  digits: 6,                          // default: 6
  period: 30,                         // seconds, default: 30
  window: 1,                          // accept codes +/- 1 period
  secretStore: {
    get: (userId) => db.totpSecrets.find(userId),
    save: (userId, secret) => db.totpSecrets.create(userId, secret),
  },
});
```

Exposes:
- `totp.generateSecret(userId)` — returns secret + QR code URI
- `totp.authenticate(request)` — verify code (standard Strategy interface)
- `totp.verifySetup(userId, code)` — confirm setup with initial code

Features:
- QR code URI generation for authenticator apps
- Backup codes generation and verification
- Secret encryption at rest (you provide the key)
- Window tolerance for clock drift

### 8. SAML Strategy (`@vigil/strategy-saml`)

SAML 2.0 for enterprise SSO.

```typescript
import { SamlStrategy } from '@vigil/strategy-saml';

const saml = new SamlStrategy({
  entryPoint: 'https://idp.example.com/sso',
  issuer: 'myapp-sp',
  cert: idpCertificate,
  callbackURL: '/auth/saml/callback',
  verify: async (profile) => {
    const user = await db.users.findByEmail(profile.email);
    if (!user) return { success: false, reason: 'No account' };
    return { success: true, user };
  },
});
```

Features:
- SP-initiated (where your app starts the login flow) and IdP-initiated (where the identity provider starts it) SSO
- Signed assertions
- Encrypted assertions (optional)
- Single logout (SLO)
- Metadata XML generation (`saml.metadata()`)
- Clock skew tolerance

---

## Session System

Vigil's session system is pluggable. You provide a store; Vigil handles serialization, cookies, and lifecycle.

### SessionStore Interface

```typescript
interface SessionStore {
  get(sessionId: string): Promise<SessionData | null>;
  set(sessionId: string, data: SessionData, ttl?: number): Promise<void>;
  destroy(sessionId: string): Promise<void>;
  touch?(sessionId: string, ttl: number): Promise<void>;  // optional: extend TTL
}
```

Vigil ships reference implementations (separate packages) for:
- `@vigil/session-memory` — in-memory (dev only)
- `@vigil/session-redis` — Redis / Valkey
- `@vigil/session-cookie` — encrypted cookie (no server state)

### Stateless Mode

For APIs that don't need sessions, disable sessions entirely:

```typescript
const vigil = createVigil({
  strategies: [jwtStrategy],
  session: false,   // no session management at all
});
```

---

## Lifecycle Hooks

```typescript
const vigil = createVigil({
  // ...
  hooks: {
    onAuthenticate: async (strategyName, request) => {
      // Runs before any strategy. Can short-circuit with a rejection.
      // Use case: global IP blocklist, maintenance mode.
    },
    onSuccess: async (user, strategyName, request) => {
      // Runs after successful authentication.
      // Use case: update last-login timestamp, audit logging.
    },
    onFailure: async (reason, strategyName, request) => {
      // Runs after failed authentication.
      // Use case: increment failed attempt counter, alert on brute force.
    },
    onSerialize: async (user) => {
      // Custom serialization. Default: uses top-level `serialize`.
    },
    onDeserialize: async (serialized) => {
      // Custom deserialization. Default: uses top-level `deserialize`.
    },
    onLogout: async (user, request) => {
      // Runs on logout. Use case: revoke refresh tokens, audit log.
    },
  },
});
```

---

## Crypto Module (`@vigil/core/crypto`)

Utility functions exposed for common auth operations. Not a strategy, just helpers.

```typescript
import { crypto } from '@vigil/core';

// Password hashing (Argon2id by default)
const hash = await crypto.hashPassword('plaintext');
const valid = await crypto.verifyPassword(hash, 'plaintext');

// Secure random tokens
const token = crypto.generateToken(32);          // 32 bytes, hex encoded
const urlSafe = crypto.generateToken(32, 'base64url');

// API key generation with prefix
const key = crypto.generateApiKey('vgl_live');   // "vgl_live_a8f3b9c1d2..."

// HMAC
const signature = crypto.hmac('sha256', secret, data);

// Timing-safe comparison
const equal = crypto.timingSafeEqual(a, b);
```

---

## Testing Utilities (`@vigil/test`)

```typescript
import { mockStrategy, mockUser, testRequest } from '@vigil/test';

// Create a strategy that always succeeds with a given user
const alwaysAdmin = mockStrategy('mock', { id: '1', role: 'admin' });

// Create a strategy that always fails
const alwaysDenied = mockStrategy('mock', null, 'Access denied');

// Build a fake authenticated request
const req = testRequest({ user: mockUser({ id: '1', email: 'a@b.com' }) });

// Assert helpers
import { expectAuthenticated, expectRejected } from '@vigil/test';

const result = await vigil.authenticate('local').handle(req);
expectAuthenticated(result);       // throws if not success
expectRejected(result, 401);       // throws if not failure with 401
```

---

## Custom Strategy Example

Building your own strategy is one interface:

```typescript
import { Strategy, AuthResult } from '@vigil/core';

class HeaderTokenStrategy implements Strategy<MyUser> {
  name = 'header-token';

  async authenticate(request: VigilRequest): Promise<AuthResult<MyUser>> {
    const token = request.headers['x-custom-token'];
    if (!token) {
      return { success: false, reason: 'No token provided', status: 401 };
    }
    const user = await myTokenLookup(token);
    if (!user) {
      return { success: false, reason: 'Invalid token', status: 401 };
    }
    return { success: true, user };
  }
}
```

---

## Multi-Strategy Chains

Authenticate with the first strategy that succeeds:

```typescript
app.get('/api/resource',
  toExpress(vigil.authenticate(['jwt', 'apikey'], { failFast: false })),
  handler
);
```

Require multiple factors (MFA):

```typescript
app.post('/transfer',
  toExpress(vigil.requireAuth()),                    // must be logged in
  toExpress(vigil.authenticate('totp', {             // must provide TOTP
    session: false,
  })),
  handler
);
```

---

## Error Handling

Vigil never throws unhandled errors. All failures are typed:

```typescript
import { AuthError, isAuthError } from '@vigil/core';

// In Express error handler
app.use((err, req, res, next) => {
  if (isAuthError(err)) {
    res.status(err.status).json({
      error: err.code,         // 'UNAUTHENTICATED' | 'FORBIDDEN' | 'RATE_LIMITED' | ...
      message: err.message,
    });
  }
});
```

Error codes are a closed enum (a fixed set of values), fully typed:

```typescript
type AuthErrorCode =
  | 'UNAUTHENTICATED'        // no valid credentials
  | 'FORBIDDEN'              // authenticated but not authorized
  | 'RATE_LIMITED'            // too many attempts
  | 'CSRF_INVALID'           // CSRF token mismatch
  | 'SESSION_EXPIRED'        // session no longer valid
  | 'STRATEGY_ERROR'         // strategy threw unexpectedly
  | 'TOKEN_EXPIRED'          // JWT or magic link expired
  | 'TOKEN_INVALID';         // JWT or magic link malformed
```

---

## What Vigil Does NOT Do

These are explicit non-goals. Vigil stays in its lane.

- **No database ORM or schema.** You write your own user lookup functions.
- **No user registration flows.** That's application logic, not middleware.
- **No email sending.** You provide a `sendLink` function; Vigil calls it.
- **No UI components.** No login forms, no React components.
- **No hosted service.** No cloud dashboard, no SaaS pricing tier.
- **No user management.** No password reset, no email verification, no profile updates.

Vigil authenticates requests. Everything else is your app.

---

## Package Roadmap

### v0.1 (MVP)
- `@vigil/core` with strategy interface + session system
- `@vigil/strategy-local`
- `@vigil/strategy-jwt`
- `@vigil/adapter-express`
- `@vigil/test`
- Full TypeScript types
- README + getting started guide

### v0.5 (OAuth + More Adapters)
- `@vigil/strategy-oauth2` with Google/GitHub/Apple presets
- `@vigil/adapter-fastify`
- `@vigil/adapter-hono`
- `@vigil/session-redis`
- Rate limiting middleware
- CSRF middleware

### v1.0 (Production Ready)
- All 8 strategies
- All 7 adapters
- Full test suite (unit + integration)
- Security audit (at minimum self-audit against OWASP guidelines)
- API documentation site
- Migration guide from Passport.js

### v1.x+ (Post-Launch)
- `@vigil/strategy-apikey`
- `@vigil/strategy-webauthn`
- `@vigil/strategy-magic-link`
- `@vigil/strategy-totp`
- `@vigil/strategy-saml`
- Adapter for Deno
- Adapter for Cloudflare Workers
- Community strategies (contribute your own)

---

## Migration from Passport.js

Vigil should ship a migration guide covering these direct mappings:

| Passport.js | Vigil |
|---|---|
| `passport.initialize()` | `createVigil(config)` |
| `passport.session()` | Built into `createVigil` session config |
| `passport.authenticate('local')` | `vigil.authenticate('local')` |
| `passport.serializeUser(fn)` | `serialize` option in config |
| `passport.deserializeUser(fn)` | `deserialize` option in config |
| `new Strategy((username, pw, done) => ...)` | `new LocalStrategy({ verify: async (u, p) => ... })` |
| `done(null, user)` | `return { success: true, user }` |
| `done(null, false, { message })` | `return { success: false, reason: message }` |
| `req.isAuthenticated()` | `req.user !== null` (or `vigil.requireAuth()` middleware) |
| `req.logout()` | `vigil.logout()` middleware |

---

## Competitive Landscape (as of July 2026)

| | Vigil | Passport.js | Better Auth | Auth0/WorkOS |
|---|---|---|---|---|
| Type | Middleware | Middleware | Full solution | Hosted platform |
| TypeScript | Native | Afterthought | Native | SDK |
| Async/Await | Yes | Callbacks | Yes | Yes |
| Owns database | No | No | Yes | Yes (hosted) |
| Session mgmt | Pluggable | External | Built-in | Built-in |
| Framework lock | None | Express-ish | React-ish | None |
| User management | No | No | Yes | Yes |
| Pricing | Free (MIT) | Free (MIT) | Free + paid | Free tier + paid |
| Maintenance | Active | Effectively dead | Active (YC-backed) | Corporate |

---

## Implementation notes (v0.1)

The sections above are the original design doc, kept verbatim as the source
of truth for intent. A few places where the actual `packages/` implementation
made a concrete call the doc left open:

- **Zero-dependency core, with one carve-out.** Argon2id needs a real
  implementation (Node has no built-in argon2), so `crypto.hashPassword` /
  `verifyPassword` lazily `import()` the optional dependency
  `@node-rs/argon2` at call time. The rest of `@vigil/core` has zero runtime
  dependencies, so anyone not using password hashing never needs to install it.
- **`@vigil/test`'s API is concrete, not the doc's sketch.** The doc's
  `vigil.authenticate('local').handle(req)` / bare `expectAuthenticated(result)`
  pseudocode doesn't match `VigilHandler`'s actual `(req, res, next)` shape.
  The real package exports `runHandler(handler, req, res?)`, which runs a
  handler and returns `{ req, res, error, nextCalled }`, plus
  `expectAuthenticated`/`expectRejected` that assert against that outcome.
- **JWKS support** is implemented via `jwksUri` + `jose`'s
  `createRemoteJWKSet`, for the asymmetric/key-rotation case the doc mentions.
- **v0.1 ships `MemorySessionStore`/`MemoryRateLimitStore`** in `@vigil/core`
  (not a separate `@vigil/session-memory` package as the roadmap implies)
  so `authenticate()`+`requireAuth()` and `rateLimit()` work out of the box in
  dev without pulling in Redis. Swap them for real stores in production.
