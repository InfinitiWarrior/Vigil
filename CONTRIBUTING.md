# Contributing to Vigil

## Setup

```bash
pnpm install
```

Requires Node 20+ and pnpm (see `packageManager` in `package.json` for the
exact version).

## Workflow

```bash
pnpm test        # vitest — runs against packages/*/src directly, no build required
pnpm typecheck    # tsc --noEmit, every package
pnpm lint         # eslint
pnpm format       # prettier --write
pnpm build        # tsup, every package (only needed to sanity-check packaging)
```

Run `pnpm test`, `pnpm typecheck`, and `pnpm lint` before opening a PR — CI
(`.github/workflows/ci.yml`) runs all of `lint`, `format:check`, `typecheck`,
`test`, and `build` on every push and pull request against `main`.

## Releasing

Packages are versioned independently via
[changesets](https://github.com/changesets/changesets), not in lockstep —
most PRs that change a package's behavior should include a changeset:

```bash
pnpm changeset   # interactive: pick affected packages + bump type, write a summary
```

Use `patch` for bug fixes, `minor` for backwards-compatible features, and
`major` for breaking changes. If a PR only touches docs, tests, tooling, or a
package's internals with no observable behavior change, it doesn't need one.

On merge to `main`, `.github/workflows/release.yml` (via
[changesets/action](https://github.com/changesets/action)) either opens a
"Version Packages" PR consuming the pending changesets, or — if such a PR was
just merged — builds and publishes the bumped packages to npm.

That workflow needs an `NPM_TOKEN` repository secret (an npm automation
token with publish access to the `@vigil` org) before it can actually
publish — add it under Settings → Secrets and variables → Actions. Until
then, the workflow will still open "Version Packages" PRs correctly; only
the final `npm publish` step will fail.

## Adding a new package

Every package under `packages/*` follows the same shape:

- `package.json` — `type: module`, dual ESM/CJS + `.d.ts` via `tsup`, a
  `publishConfig: { "access": "public" }` block, and `build`/`typecheck`
  scripts matching the existing packages' scripts verbatim.
- `tsconfig.json` — extends `../../tsconfig.base.json`, sets `outDir: dist`,
  `rootDir: src`.
- `src/index.ts` — the package's public entrypoint.
- `test/*.test.ts` — vitest tests.

New packages also need an entry in the root `vitest.config.ts`'s `resolve.alias`
map, pointing `@vigil/<name>` at `./packages/<name>/src/index.ts`, so tests
across the monorepo resolve it from source rather than a built `dist/`.

If you're adding a new adapter, the existing adapters
(`adapter-express`/`adapter-fastify` for callback-style frameworks,
`adapter-hono`/`adapter-bun`/`adapter-cloudflare` for Fetch API–based
runtimes) are the reference implementations — an adapter's job is to
translate the target framework's request/response objects into `VigilRequest`
/`VigilResponse` (`@vigil/core`'s `types.ts`) and back, nothing more.

## Design context

- [`DESIGN.md`](./DESIGN.md) is the original design doc: positioning, full
  API surface, and roadmap. Its final section, "Implementation notes,"
  documents where the shipped code deviated from the doc's pseudocode.
- [`README.md`](./README.md) is the grounded, accurate quick-start for
  what's built today.
- [`SECURITY.md`](./SECURITY.md) is a self-audit against OWASP guidelines,
  covering the auth-critical code paths (password hashing, session
  handling, CSRF, JWT/OAuth2/WebAuthn/SAML strategies) plus known gaps.

## Reporting security issues

Don't open a public issue — see [SECURITY.md](./SECURITY.md#reporting-a-vulnerability).
