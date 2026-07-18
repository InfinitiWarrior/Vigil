# Express + Vigil: session login, JWT bearer auth, and RBAC

A minimal, runnable Express app demonstrating:

- Session login via `@vigil/strategy-local`, rate-limited per attempted
  account (`POST /login`)
- Issuing a short-lived JWT for the logged-in session (`POST /token`)
- A session-protected route (`GET /dashboard`)
- Role-based authorization (`GET /admin`, admin-only)
- Stateless JWT bearer auth on a separate route (`GET /api/me`)
- Logout (`POST /logout`)

## Run it

This example is a pnpm workspace member (see the root `pnpm-workspace.yaml`)
and depends on the `@vigil/*` packages by workspace reference, not by
version off npm — clone the whole repo and run it from there:

```bash
pnpm install       # from the repo root
pnpm build         # builds @vigil/core and friends this example imports from dist/
pnpm --filter vigil-example-express-basic dev
```

Then, in another terminal:

```bash
# Log in — saves the session cookie to cookies.txt
curl -c cookies.txt -X POST http://localhost:3000/login \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"hunter2"}'

# Hit a session-protected route
curl -b cookies.txt http://localhost:3000/dashboard

# Hit the admin-only route (alice is an admin — try bob@example.com for a 403)
curl -b cookies.txt http://localhost:3000/admin

# Mint a JWT from the session, then use it statelessly (no cookie)
TOKEN=$(curl -b cookies.txt -s -X POST http://localhost:3000/token | jq -r .token)
curl http://localhost:3000/api/me -H "Authorization: Bearer $TOKEN"

# Log out
curl -b cookies.txt -X POST http://localhost:3000/logout

# Trigger the login rate limit (6th attempt within 60s for the same email gets a 429)
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:3000/login \
    -H 'content-type: application/json' \
    -d '{"email":"alice@example.com","password":"wrong"}'
done
```

This example uses `@vigil/adapter-express` and an in-memory user list — see
the root [README.md](../../README.md) for the full package list, and
[SECURITY.md](../../SECURITY.md) for guidance on what else changes before
this goes to production (real password storage, a persistent session store
and rate-limit store — `@vigil/session-redis` ships both, etc.).
