---
"@vigil/adapter-express": patch
"@vigil/adapter-fastify": patch
"@vigil/adapter-hono": patch
"@vigil/adapter-koa": patch
"@vigil/adapter-node": patch
"@vigil/adapter-bun": patch
"@vigil/adapter-cloudflare": patch
"@vigil/adapter-nextjs": minor
"@vigil/session-redis": minor
"@vigil/strategy-apikey": minor
"@vigil/strategy-oauth2": minor
---

Close out the remaining feature gaps and security-audit findings from a follow-up review, and add a Next.js adapter.

### Added

- `@vigil/adapter-nextjs` — App Router support: `composeNextMiddleware`/`toNext` for `middleware.ts`, `composeNextRoute` for Route Handlers, and `getVigilUser()` for Server Components (which have no Request/Response cycle to run middleware against).
- `@vigil/core`: sessions are rolling (sliding expiration) by default — `requireAuth()`/`optionalAuth()`/`logout()` now call `SessionStore.touch()` on load when a `maxAge` is configured, instead of that method going unused. Set `session.rolling: false` for the old absolute-expiration behavior.
- `@vigil/core`: `vigil.listSessions(user)` / `vigil.revokeAllSessions(user)` — "sign out everywhere," for `SessionStore`s that implement the new optional `listByUser`/`destroyAllForUser`.
- `@vigil/core`: `vigil.getUserBySessionId(sessionId)` and `vigil.sessionCookieName()` (now public) — resolve a user or the session cookie's name without a full request/response cycle.
- `@vigil/session-redis`: `RedisRateLimitStore` (`RedisLike` gains optional `sadd`/`srem`/`smembers` for the session-listing feature above).
- `@vigil/strategy-oauth2`: `microsoftOAuth2`, `discordOAuth2`, `gitlabOAuth2` presets.
- `@vigil/strategy-apikey`: `compareApiKeyHash()` — constant-time comparison helper for `verify()` callbacks.

### Security hardening

- `@vigil/core`: `authenticate()`'s public failure message is now a generic "Authentication failed" by default instead of passing a strategy's `verify()` reason straight through (classic user-enumeration leak) — opt back in with `{ exposeFailureReason: true }`. The real reason is always on `AuthError.detail`. A thrown strategy exception's message is _always_ hidden from the client.
- `VigilRequest` gains a `secure` field, populated by every adapter from the actual connection (TLS, or a trusted `X-Forwarded-Proto`) — cookies' `Secure` attribute now defaults from this instead of relying solely on `NODE_ENV`, so a deployment that forgets to set `NODE_ENV=production` doesn't silently ship insecure cookies.
- CI now runs `pnpm audit --audit-level=high` on every push/PR, and Dependabot is configured for weekly dependency updates.

See `SECURITY.md` for the full self-audit this closes out.

**Breaking**: `SessionStore` implementations gain two new optional methods (`listByUser`/`destroyAllForUser`) — only required if you use the new `listSessions()`/`revokeAllSessions()`.

Note: `@vigil/core` itself (where most of the above actually lives — rolling sessions, generic failure messages, `secure` cookie detection, `listSessions()`/`revokeAllSessions()`/`getUserBySessionId()`) is intentionally left un-versioned by this changeset. Nearly every package here lists `@vigil/core` as a `peerDependency`, and changesets forces a `major` bump on every peer-dependent the moment a peer itself bumps — including packages whose code didn't change in this batch at all. Add a `"@vigil/core": minor` (or higher) changeset yourself when you're ready to accept that ecosystem-wide cascade; don't add one without expecting it. Until then, `@vigil/core`'s new functionality is in `main` and fully tested, just not yet versioned for release.
