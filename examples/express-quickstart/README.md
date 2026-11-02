# @okeav/idp-core — Express quickstart

Runnable in under 5 minutes. One file (`server.js`), zero required manual config.

## 1. Start Mongo + Redis

From the repo root (one level up from this folder):

```bash
docker compose up -d
```

This starts a single-node MongoDB replica set (required for this package's
transactions — see the main README) with `rs.initiate()` already run for
you, plus Redis. Nothing else to configure.

## 2. Install and run

```bash
cd examples/express-quickstart
cp .env.example .env
npm install
npm start
```

`npm start` runs `node --env-file=.env server.js`, which requires **Node 20.6+**.
The copied `.env` sets `NODE_ENV=development`, which is what lets the quickstart
fall back to its public DEV-ONLY secrets; without it (unset counts as production)
it refuses to start until every secret is set.
On an older Node, either upgrade, or export the `.env` values into your shell
yourself and run `node server.js` directly.

You should see:

```
Quickstart IDP listening on http://localhost:3000
```

## 3. Try it

```bash
# Register
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"Str0ng!Passw0rd"}'
# -> { "status": "ok", "verificationTicket": "..." } — the same answer for any address.
#    The ticket is also set as a cookie; curl keeps no cookies, so pass it back as "ticket"
#    below and your code attempts get their own budget instead of the per-address one.

# The server console prints the verification code (no real mailer wired up):
#   [dev email] Verify you@example.com — code: 123456 (or token: ...)

curl -X POST http://localhost:3000/auth/register/verify-email \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","code":"123456","ticket":"<verificationTicket>"}'

curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"Str0ng!Passw0rd"}'
# -> { "accessToken": "...", "refreshToken": "...", "userId": "..." }
#    (curl sends no Origin / Sec-Fetch-Site header, so refreshToken is in the body;
#     a browser gets it only as the httpOnly refresh cookie — cookies.refreshTokenInBody: 'auto')

# Rotate the refresh token (the old one stops working), then sign out with the new one:
curl -X POST http://localhost:3000/auth/session/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refreshToken>"}'

curl -X POST http://localhost:3000/auth/session/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<the new refreshToken>"}'
```

Every request handled goes through `server.js`'s `onAuditLog` hook and prints
a line to the console — watch the server terminal while you try things.

## What to look at next

- `server.js` — every config field is commented with what it does and why a default was chosen.
- `../../README.md` — full configuration reference, hooks, storage/cache adapters, service-mesh feature.
- `../../docker-compose.yml` — the Mongo/Redis stack this example runs against.

## This is a quickstart, not a production config

- The signing key is ephemeral by default (regenerated every restart — see `.env.example` for how to pin one).
- `emailHashPepper`/`tokenHashSecret` are placeholder values — generate real random secrets for anything beyond your own laptop.
- The cache adapter is `memory` (single-instance only) — switch to `redis` before running more than one instance.
- No rate limiting, HTTPS, or CORS is configured — this is Express's and your app's job, same as with any Express server.
