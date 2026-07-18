---
"@vigil/adapter-bun": minor
"@vigil/adapter-cloudflare": minor
"@vigil/adapter-koa": minor
"@vigil/adapter-node": minor
"@vigil/session-redis": minor
"@vigil/strategy-totp": minor
---

Add the remaining adapters from DESIGN.md's roadmap and fix two auth-relevant bugs found during a security self-audit.

- Add `@vigil/adapter-koa`, `@vigil/adapter-node` (raw `node:http`, no framework dependency), `@vigil/adapter-bun`, and `@vigil/adapter-cloudflare` — every adapter in DESIGN.md's original roadmap is now implemented.
- **`@vigil/strategy-totp`**: `TotpSecretStore` now requires `getLastUsedStep`/`setLastUsedStep` so `TotpStrategy` can reject a code that's already been used within the drift window (RFC 6238 §5.2 replay protection). Added `MemoryTotpSecretStore` and `verifyTotpCodeStep` (like `verifyTotpCode`, but returns the matched time-step). **Breaking**: existing `TotpSecretStore` implementations need the two new methods.
- **`@vigil/session-redis`**: `RedisLike.set` now takes an optional `ttlSeconds` third argument, so `RedisSessionStore.set()` can set a session's value and expiry in one atomic call instead of a separate `SET` + `EXPIRE` (which left a window where a freshly created session had no TTL if the process crashed in between). **Breaking**: `RedisLike` implementations must set `ttlSeconds` atomically when given — see the interface's doc comment for ioredis/node-redis wrapper examples.

All other packages in the monorepo move to the same version to stay on a single lockstep release line (`fixed` group in `.changeset/config.json`), even though their code didn't change in this batch.
