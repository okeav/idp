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

Steps: extract token → `verifyAccessToken` → check the revocation cache for
`revoked-refresh-token:<jti>` (fail-closed — see [Cache Interface](cache-interface.md)) → set
`req.auth`.

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
- `TOKEN_REVOKED` (401) — token's `jti` found in the revocation cache.
- `CACHE_UNAVAILABLE` (503) — cache adapter errored during the revocation check.

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
- [Service Mesh](service-mesh.md) — the S2S trust model behind `serviceContextMiddleware`.
- [Router & Schemas](router-and-schemas.md) — the exported zod schemas these middlewares consume.
