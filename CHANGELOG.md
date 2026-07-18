# Changelog

This is a narrative, repo-level summary — not the authoritative per-package
version history. Packages are versioned independently via
[changesets](https://github.com/changesets/changesets); once released, each
package under `packages/*` gets its own generated `CHANGELOG.md` documenting
its exact version-by-version changes. Format here loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- `@vigil/adapter-koa` — Koa middleware adapter.
- `@vigil/adapter-node` — raw `node:http` adapter, no framework dependency.
- `@vigil/adapter-bun` — Bun.serve (Fetch API) adapter.
- `@vigil/adapter-cloudflare` — Cloudflare Workers (Fetch API) adapter.
- `SECURITY.md` — OWASP-guided self-audit of the auth-critical code paths,
  plus a vulnerability reporting policy.
- `CONTRIBUTING.md` — contribution workflow and package-authoring conventions.
- GitHub Actions CI (`.github/workflows/ci.yml`) — lint, format check,
  typecheck, test, and build on every push/PR against `main`.
- A release workflow (`.github/workflows/release.yml`) using
  [changesets/action](https://github.com/changesets/action) to open
  "Version Packages" PRs and publish to npm on merge.
- ESLint (flat config) and Prettier, with `lint`/`format`/`format:check`
  root scripts.
- `publishConfig` on every package, in preparation for publishing to npm.

### Fixed

- `@vigil/strategy-totp` — TOTP codes could be replayed for as long as they
  remained inside the drift window, since nothing tracked which time-step
  had last been used. `TotpSecretStore` now requires
  `getLastUsedStep`/`setLastUsedStep`; a code matching an already-used (or
  earlier) step is rejected. See SECURITY.md.
- `@vigil/session-redis` — `RedisSessionStore.set()` issued a plain `SET`
  followed by a separate `EXPIRE`, leaving a window where a freshly created
  session existed in Redis with no TTL if the process crashed in between.
  `RedisLike.set` now takes the TTL directly so it can be applied
  atomically. See SECURITY.md.

## 0.1.0 — 2026-07-16

### Added

- `@vigil/core` — engine, types, `AuthError`, crypto helpers (Argon2id
  password hashing, HMAC, timing-safe comparison), in-memory session and
  rate-limit stores, `csrf()` and `rateLimit()` middleware.
- `@vigil/strategy-local` — username/password.
- `@vigil/strategy-jwt` — JWT bearer, HMAC or JWKS, via `jose`.
- `@vigil/strategy-oauth2` — Google/GitHub/Apple presets, PKCE by default.
- `@vigil/strategy-apikey` — API key auth with a SHA-256 lookup-hash helper.
- `@vigil/strategy-totp` — RFC 6238 TOTP.
- `@vigil/strategy-magic-link` — single-use, hashed, TTL-bound sign-in links.
- `@vigil/strategy-webauthn` — WebAuthn/passkeys, built on `@simplewebauthn/server`.
- `@vigil/strategy-saml` — SAML SSO, built on `@node-saml/node-saml`.
- `@vigil/adapter-express` — Express middleware adapter.
- `@vigil/adapter-fastify` — Fastify plugin adapter.
- `@vigil/adapter-hono` — Hono middleware adapter.
- `@vigil/session-redis` — Redis-backed `SessionStore`.
- `@vigil/test` — mock strategies and assertion helpers.
