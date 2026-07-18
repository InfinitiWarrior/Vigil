# Security

## Reporting a vulnerability

Please report suspected vulnerabilities privately — open a
[GitHub security advisory](https://github.com/InfinitiWarrior/Vigil/security/advisories/new)
rather than a public issue. We'll acknowledge within a few business days.

## Self-audit (OWASP-guided)

This is a self-audit of `packages/*` against the OWASP Top 10 and common
authentication-specific pitfalls (OWASP ASVS chapters on authentication,
session management, and CSRF). It's an internal review, not an independent
third-party assessment — treat it as a documented starting point, not a
certification. Last reviewed: 2026-07-18 — TOTP replay protection,
`RedisSessionStore` atomicity, generic-by-default failure messages,
request-aware `Secure` cookie detection, and CI dependency scanning were all
fixed the same day — against the packages listed in `DESIGN.md`'s v1.0
roadmap.

### Mitigations already in place

- **Password storage** (`@vigil/core/crypto`) — hashing goes through
  Argon2id (`@node-rs/argon2`), the OWASP-recommended algorithm for password
  storage, at that library's default cost parameters. Vigil never stores or
  compares raw passwords itself; `verifyPassword` delegates to argon2's own
  constant-time comparison.
- **Constant-time comparisons** — `crypto.timingSafeEqual`, TOTP code
  verification, and CSRF token verification all use `node:crypto`'s
  `timingSafeEqual`. Mismatched-length inputs still run a same-length dummy
  comparison first (`packages/core/src/crypto.ts`) so a length check isn't
  itself a timing oracle.
- **Session fixation** — `establishIdentity` (`packages/core/src/vigil.ts`)
  mints a fresh 256-bit session ID (`generateToken(32)`, from
  `crypto.randomBytes`) on every successful `authenticate()` call. A session
  ID is never reused across a login, so there's no fixation window.
  Session cookies default to `httpOnly: true`, `sameSite: "lax"`, and
  `secure` when `NODE_ENV=production`.
- **CSRF** (`vigil.csrf()`) — double-submit-cookie pattern: a non-`httpOnly`
  cookie token (so client JS can read and resubmit it) is compared
  constant-time against a header or body token on unsafe methods only
  (`SAFE_METHODS` excludes GET/HEAD/OPTIONS from the check).
- **JWT** (`@vigil/strategy-jwt`) — `algorithms` is a required, explicit
  allowlist with no default, so there's no accidental `alg: none` or
  HMAC/RSA confusion path; verification goes through `jose`, not a
  hand-rolled parser.
- **OAuth2** (`@vigil/strategy-oauth2`) — PKCE (S256) is on by default, the
  authorization `state` parameter is single-use (`consume()` deletes on
  read) and TTL-bound, closing both CSRF and authorization-code-replay on
  the callback. The Apple preset verifies the `id_token`'s signature via
  `jose` + Apple's JWKS before trusting any claim; the Google preset avoids
  the question by fetching the profile from Google's `userinfo` endpoint
  over TLS with the access token rather than trusting an unverified
  `id_token`.
- **WebAuthn & SAML** — both strategies delegate all protocol-level
  cryptography (attestation/assertion signature verification, XML
  canonicalization and signature verification, replay-counter semantics) to
  audited upstream libraries (`@simplewebauthn/server`,
  `@node-saml/node-saml`) instead of hand-rolling it. This is the single
  highest-leverage security decision in these two packages — SAML's XML
  signature-wrapping and XXE classes of bugs, and WebAuthn's attestation
  parsing, are exactly the kind of protocol-crypto code that's easy to get
  subtly, critically wrong from scratch.
- **One-time tokens** — magic-link tokens, OAuth `state`, and WebAuthn
  challenges are all consumed atomically (read-and-delete in one store
  call) and TTL-bound, so none of them can be replayed after first use or
  after expiry. Magic-link tokens are hashed (SHA-256) before being
  persisted, so a leaked token store doesn't hand out working sign-in
  links — only the raw token, delivered once via `sendLink`, is usable.
- **API keys** (`@vigil/strategy-apikey`) — `hashApiKey` uses a fast SHA-256
  digest rather than Argon2, which is correct here: API keys are already
  high-entropy random values (unlike user-chosen passwords), so a fast,
  indexable hash is the appropriate tool and doesn't sacrifice brute-force
  resistance.
- **TOTP replay protection** (`@vigil/strategy-totp`) — `TotpSecretStore`
  tracks the time-step index of the last code accepted per user
  (`getLastUsedStep`/`setLastUsedStep`); `TotpStrategy.authenticate()`
  rejects a code whose matched step is at or before that value, per RFC
  6238 §5.2. A shoulder-surfed or logged code can't be replayed even while
  it's still inside the drift window.
- **`RedisSessionStore.set()` is atomic** (`@vigil/session-redis`) — value
  and expiry are set in one call to `RedisLike.set(key, value, ttlSeconds)`,
  which implementations must perform atomically (e.g. `SET ... EX`). There's
  no window where a freshly created session key exists in Redis with no TTL.
- **Failure-reason strings are generic by default.** A strategy's `verify()`
  might return "User not found" vs. "Invalid password" — since 2026-07-18,
  `authenticate()`'s public `AuthError.message` is a generic "Authentication
  failed" unless the caller explicitly opts in with
  `{ exposeFailureReason: true }`. The real reason is always preserved on
  `AuthError.detail` for hooks/logging, so nothing is lost — it just isn't
  sent to the client by default. A thrown strategy exception's message is
  _always_ hidden from the client regardless of that option, since a thrown
  error is virtually always an internal detail (a bug, an outage), never
  something meant for the end user.
- **`Secure` cookie detection is request-aware, not just `NODE_ENV`-based.**
  Every adapter populates `VigilRequest.secure` from the actual connection
  (a real TLS socket for Express/Koa/raw `node:http`; a trusted
  `X-Forwarded-Proto: https` or the request URL's scheme for the
  Fetch-API-based adapters), and `defaultCookieOptions()` prefers that over
  `NODE_ENV`. A production deployment that forgets to set
  `NODE_ENV=production` no longer silently ships cookies without `Secure`.
- **CI scans for dependency vulnerabilities.** `pnpm audit --audit-level=high`
  runs on every push/PR (`.github/workflows/ci.yml`) and fails the build on
  high/critical advisories; Dependabot (`.github/dependabot.yml`) opens
  weekly update PRs for lower-severity findings and the GitHub Actions
  workflows themselves.

### Known gaps and recommendations

These aren't necessarily bugs — several are deliberate scope boundaries
consistent with "Vigil doesn't own your database" — but they're worth
tracking and documenting explicitly rather than assuming they're covered:

1. **Brute-force protection is opt-in, by design.** `vigil.rateLimit()`
   exists but isn't automatically attached to `authenticate("local")` or
   `MagicLinkStrategy.sendToken()` — an app that doesn't explicitly wire it
   onto its login/send-link routes has no built-in throttling.
   `examples/express-basic` now demonstrates the recommended pattern
   (`rateLimit()` keyed by the attempted account, layered in front of
   `authenticate()`, on the `/login` route) — copy that rather than treating
   rate limiting as something Vigil handles for you.

### Explicitly out of scope

Consistent with Vigil's stated positioning ("verifies requests; doesn't
touch your database, generate UI, or manage users" — see `DESIGN.md`'s
Positioning section), these remain the application's responsibility and
aren't assessed here:
password/credential storage schema, account lockout policy, email/SMS
delivery security for magic links and TOTP enrollment, and authorization
logic beyond the basic role check in `vigil.authorize()`.
