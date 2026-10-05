---
title: "Middleware"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "middleware", "express"]
description: "authContextMiddleware, serviceContextMiddleware, requireServiceCallerMiddleware, validateBody/validateQuery, and cookieParser."
---

# Middleware

## `authContextMiddleware(opts?)`

```ts
function authContextMiddleware(opts?: { issuer?: string; optional?: boolean }): RequestHandler
```

Authenticates the caller and sets `req.auth = { userId, email, claims, tokenMeta }`, where
`claims` is whatever opaque object the consumer put on the token at issuance and `tokenMeta =
{ issuedAt, expiresAt, jti }`.

Accepts either the `access_token` cookie (browser flows, paired with `cookieParser()`) or an
`Authorization: Bearer <token>` header (API/service clients) — cookie wins if both are present.

Steps: extract token → `verifyAccessToken` → revocation check (below) → set `req.auth`.

### Revocation check (`config.session.verifyOnEachRequest`)

**On (the default since 0.3.0)**: the middleware looks up the token's session row by `jti`
(`sessionRepository.findByJti` — each session's `jti` equals its paired access token's `jti`) on
every request, and rejects 401 `TOKEN_REVOKED` if the row is missing, revoked, expired, or belongs
to a different user. Logout, logout-all, password reset/change, session revocation, account
deletion, OIDC end-session, and refresh rotation all revoke session rows, so each takes effect on
**every instance immediately**, not just the one that handled it.

- The revocation cache (`revoked-refresh-token:<jti>`) is a fast path only: a cache hit
  short-circuits with `TOKEN_REVOKED`; a miss never skips the storage check. A cache error is
  logged and the storage check decides.
- A storage error fails closed: 503 `SESSION_STORE_UNAVAILABLE`.
- **Cost**: one indexed storage read per authenticated request (Mongo: the `{ jti: 1 }` index on
  the sessions collection; `@okeav/idp-core-postgres`: `idp_sessions_jti_idx`).
- Tokens with no session row carry a `sessionless: true` claim and skip the storage check (cache
  check only): `client_credentials` grant tokens, and tokens minted with the public
  `issueAccessToken()`/`issueOAuth2AccessToken()` exports (see
  [Tokens & Signing](tokens-rs256.md)). Tokens from login, MFA, SSO, magic link, WebAuthn,
  refresh, and the `authorization_code`/`refresh_token` OAuth2 grants are session-bound.
- A storage adapter whose `sessionRepository` has no `findByJti` falls back to the cache-only
  behaviour below, with a startup warning.

**Off** (`session: { verifyOnEachRequest: false }`, env `IDP_SESSION_VERIFY_ON_EACH_REQUEST=false`
— 0.2.x behaviour): only the revocation cache is checked (fail-closed: a cache error → 503
`CACHE_UNAVAILABLE` — see [Cache Interface](cache-interface.md)). Single-session revocations
(logout, refresh rotation, session revoke, OAuth2 token revoke) write that cache — visible to other
instances only with a shared (Redis) cache — but the bulk ones (logout-all, password
reset/change, revoke-all, account deletion, OIDC end-session) don't write it at all, so those
users' access tokens stay valid until they expire — up to `ttls.accessToken` (default 1 hour).
This trades that revocation lag for the per-request read.

**`opts.optional: true`** populates `req.auth` when a valid token is present but calls `next()`
with no error (and `req.auth` left `undefined`) when **no token is presented at all**, instead of
rejecting. A malformed/expired/revoked token still rejects even in optional mode — "optional"
means "anonymous is allowed," not "an invalid token is silently ignored." Used by
`/oauth2/authorize` (behaves differently for logged-in vs. anonymous callers) and
`/oidc/end-session`.

Throws:
- `AUTH_REQUIRED` (401) — no token presented, `optional` not set.
- Whatever `verifyAccessToken` throws (`TOKEN_EXPIRED`, `INVALID_TOKEN`, both 401) for a present-
  but-invalid token.
- `TOKEN_REVOKED` (401) — token's `jti` found in the revocation cache, or its session row is
  missing/revoked/expired/another user's.
- `SESSION_STORE_UNAVAILABLE` (503) — `findByJti` errored (verification on).
- `CACHE_UNAVAILABLE` (503) — cache adapter errored during the revocation check (verification off,
  or a `sessionless` token).

Every rejection is logged via `logger.warn({ err, path: req.originalUrl }, 'authContextMiddleware rejected request')`
before being passed to `next(err)`.

## `serviceContextMiddleware(opts?)`

```ts
function serviceContextMiddleware(opts?: { ownServiceName?: string }): RequestHandler
```

Authenticates an inbound service-to-service request against this IDP's own service-key registry
(in-process — no HTTP round trip) and sets `req.serviceCaller`. **The shape is mode-dependent, not
uniform**: under `source: 'token'` it's `{ name, scopes, region, source }` (as shown); under
`source: 'legacy-secret'` it's only `{ name, source }` — no `scopes`/`region` keys at all, not even
empty. Code that unconditionally reads `req.serviceCaller.scopes` will throw under the
legacy-secret fallback, which is a normal path under the default `tokenMode: 'both'`, not an edge
case. See [Service Mesh](service-mesh.md) for the full S2S trust model.

Mode is `config.serviceMesh.tokenMode` (`'token' | 'secret' | 'both'`, default `'both'`):
- **`'token'`** — requires a valid S2S JWT in the `Authorization: Bearer` header, verified against
  the local service-key registry. `req.serviceCaller.source = 'token'`.
- **`'secret'`** — legacy shared-secret fallback: compares the `x-internal-service-secret` header
  against `config.serviceMesh.sharedSecret`, trusting the `x-service-name` header for the caller's
  claimed identity (**not cryptographically verified** under this mode).
  `req.serviceCaller.source = 'legacy-secret'`.
- **`'both'`** — tries the token first if a bearer is present; on verification *failure* it logs a
  warning before falling back to the secret check, but a **missing** bearer falls back silently
  (no warning) rather than rejecting outright.

`opts.ownServiceName` (or `config.serviceMesh.ownServiceName`) is this service's own name — the
token's expected `aud`.

Throws:
- `SERVICE_NOT_CONFIGURED` (500) — mode allows the secret fallback but no `sharedSecret` is
  configured.
- `SERVICE_AUTH_FAILED` (401) — secret mismatch, or token verification failed under `mode: 'token'`
  (no fallback), or neither check ran.

## `requireServiceCallerMiddleware(...allowedCallers)`

```ts
function requireServiceCallerMiddleware(...allowedCallers: string[]): RequestHandler
```

Pins an internal endpoint to a specific set of upstream services by name. Must run **after**
`serviceContextMiddleware`. Name-allowlist only — not an RBAC decision (this package has no
scope-catalogue concept).

Throws:
- `requireServiceCallerMiddleware(...names)` throws a plain `Error` synchronously if called with
  zero arguments (it's a factory function, not a class — no `new` involved).
- `UNAUTHENTICATED` (401) — `req.serviceCaller` unset (i.e. `serviceContextMiddleware` wasn't
  mounted first).
- `FORBIDDEN` (403) — `req.serviceCaller.name` not in the allowlist.

Logs a warning (not an error) when `req.serviceCaller.source === 'legacy-secret'` — the caller's
identity was trusted, not cryptographically verified.

## `validateBody(schema)` / `validateQuery(schema)`

```ts
function validateBody(schema: { parse: (input: unknown) => unknown }): RequestHandler
function validateQuery(schema: { parse: (input: unknown) => unknown }): RequestHandler
```

Both accept any object with a zod-compatible `.parse()` method — every schema exported under
[`schemas`](router-and-schemas.md) works directly, and you can pass your own zod schema too.

- **`validateBody`** reassigns `req.body = schema.parse(req.body)` — works unchanged on Express 4
  and 5 (`req.body` is writable on both).
- **`validateQuery`** does **not** reassign `req.query`. Express 5 makes `req.query` a read-only
  getter, so the parsed result is stored on **`req.validatedQuery`** instead — handlers read
  `req.validatedQuery`, not `req.query`, after this middleware runs. This is a deliberate
  API difference between the two — don't expect `req.query` to reflect validation/coercion.

Both throw `VALIDATION_ERROR` (400) on parse failure, wrapping the underlying zod error as
`cause`.

## `cookieParser`

```ts
const cookieParser: (...args: unknown[]) => RequestHandler
```

A convenience re-export of the `cookie-parser` npm package (a peer dependency — your app must
install it). Mount it before any handler that reads `req.cookies` (i.e. before
`authContextMiddleware` and any password/magic-link/WebAuthn/SSO handler that reads or sets the
`access_token`/`refresh_token` cookies).

## Mounting order

```js
app.use(cookieParser());
app.use(express.json());
app.use('/auth', buildRouter());
```

If wiring handlers individually rather than via `buildRouter()` (see
[Router & Schemas](router-and-schemas.md)), mount `validateBody`/`validateQuery` before the
handler, and `authContextMiddleware()` before any handler that reads `req.auth`.

## Related

- [Errors](errors.md) — every code above.
- [Cache Interface](cache-interface.md) — the revocation-cache fail-closed behavior.
- [Repository Adapters](repository-adapters.md) — `SessionRepository.findByJti`.
- [Service Mesh](service-mesh.md) — the S2S trust model behind `serviceContextMiddleware`.
- [Router & Schemas](router-and-schemas.md) — the exported zod schemas these middlewares consume.
