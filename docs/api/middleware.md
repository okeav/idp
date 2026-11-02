---
title: "Middleware"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "middleware", "express"]
description: "authContextMiddleware, requireRecentAuth, CSRF origin checks, serviceContextMiddleware, requireServiceCallerMiddleware, validateBody/validateQuery, cookieParser, and idpErrorHandler."
---

# Middleware

## `authContextMiddleware(opts?)`

```ts
function authContextMiddleware(opts?: {
  issuer?: string;                 // default: config.issuer
  audience?: string | string[];    // the aud a first-party token must carry; default: config.issuer
  accept?: Array<'first-party' | 'oauth2-user' | 'oauth2-client'>; // default: ['first-party']
  optional?: boolean;
}): RequestHandler
```

Authenticates the caller and sets:

```ts
req.auth = {
  userId?: string;     // the token's sub — undefined for 'oauth2-client' (client_credentials) tokens
  email?: string;
  claims: Record<string, unknown>; // whatever opaque object was put on the token at issuance
  tokenKind: 'first-party' | 'oauth2-user' | 'oauth2-client';
  clientId?: string;   // OAuth2 tokens only
  scopes?: string[];   // OAuth2 tokens only: the granted scopes
  tokenMeta: { issuedAt: number; expiresAt: number; jti: string; authTime: number | null };
}
```

`tokenMeta.authTime` is the token's `auth_time` (Unix seconds): when the user last actually logged
in, carried unchanged across refreshes — `null` if the token has none. It's what
[`requireRecentAuth()`](#requirerecentauthopts) checks.

Accepts either the `access_token` cookie (browser flows, paired with `cookieParser()`) or an
`Authorization: Bearer <token>` header (API/service clients) — cookie wins if both are present. A
non-string cookie value (e.g. a `j:`-prefixed JSON cookie) is ignored.

Steps: extract token → [CSRF origin check](#csrf-origin-check) (cookie-authenticated requests
only) → `verifyAccessToken` (with `issuer`, `audience`, `accept`) → revocation check (below) → set
`req.auth`.

### Which tokens are accepted (`accept`, `audience`)

By default only **first-party** tokens — the ones this IdP's own login/refresh issues — whose
`aud` is the issuer. A token the IdP issued to a third-party OAuth2 client (`aud` = that client)
is refused with 401 `INVALID_TOKEN`, so a relying party a user authorized can never act as that
user on the IdP's own routes. See [Access-token kinds](tokens-rs256.md#access-token-kinds).

- A resource server that serves OAuth2 clients opts in with `accept: ['oauth2-user']` (and/or
  `'oauth2-client'` for `client_credentials` machine tokens) — and must then check
  `req.auth.scopes` itself:

  ```js
  app.get('/api/orders',
    authContextMiddleware({ accept: ['first-party', 'oauth2-user'] }),
    (req, res, next) => {
      if (req.auth.tokenKind !== 'first-party' && !req.auth.scopes.includes('orders:read')) {
        return res.status(403).json({ error: 'INSUFFICIENT_SCOPE' });
      }
      next();
    },
    listOrders,
  );
  ```

- A first-party token you minted with a custom `audience` (`issueAccessToken(..., { audience })`)
  needs `authContextMiddleware({ audience })`.
- For an `oauth2-client` token there is no user: `req.auth.userId` is `undefined` (the client id is
  in `req.auth.clientId`).
- `opts.accept` must be a non-empty array of known kinds — anything else throws when the
  middleware is created.

### Revocation check (`config.session.verifyOnEachRequest`)

**On (the default since 0.3.0)**: the middleware looks up the token's session row by `jti`
(`sessionRepository.findByJti` — each session's `jti` equals its paired access token's `jti`) on
every request, and rejects 401 `TOKEN_REVOKED` if the row is missing, revoked, expired, or belongs
to a different user. Logout, logout-all, password reset/change, session revocation, account
deletion, OIDC end-session, refresh rotation, refresh-token reuse detection, OAuth2 token
revocation, consent revocation and client deactivation all revoke session rows, so each takes
effect on **every instance immediately**, not just the one that handled it.

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

This check is what `verifyAccessToken` alone does **not** do — a resource server that calls
`verifyAccessToken` directly accepts a revoked session's token until it expires.

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
- `CSRF_ORIGIN_REJECTED` (403) — a cookie-authenticated state-changing request from an untrusted
  origin (see below).
- Whatever `verifyAccessToken` throws (`TOKEN_EXPIRED`, `INVALID_TOKEN`, both 401) for a present-
  but-invalid token — including a token whose kind isn't in `accept` or whose audience is wrong.
- `TOKEN_REVOKED` (401) — token's `jti` found in the revocation cache, or its session row is
  missing/revoked/expired/another user's.
- `SESSION_STORE_UNAVAILABLE` (503) — `findByJti` errored (verification on).
- `CACHE_UNAVAILABLE` (503) — cache adapter errored during the revocation check (verification off,
  or a `sessionless` token).

Every rejection is logged via `logger.warn({ err, path: req.originalUrl }, 'authContextMiddleware rejected request')`
before being passed to `next(err)`.

## `requireRecentAuth(opts?)`

```ts
function requireRecentAuth(opts?: { maxAgeSeconds?: number }): RequestHandler
```

A step-up gate for changes that would let a stolen session outlive itself. Mount it **after**
`authContextMiddleware()`. It passes only when `req.auth.tokenMeta.authTime` — the user's last
real login (password + MFA, magic link, SSO, passkey; a token refresh doesn't count) — is within
`maxAgeSeconds` (default `config.session.recentAuthMaxAgeSeconds`, 900 = 15 minutes). Otherwise it
answers 401 `REAUTHENTICATION_REQUIRED`: the client sends the user through a login again and
retries with the new token.

A token without `auth_time` — one minted through the public `issueAccessToken()` without
`authTime`, or refreshed from a session created before 0.4.0 — never counts as recent. An
`auth_time` more than 60 s in the future is refused too. `maxAgeSeconds`, if given, must be a
positive integer (checked when the middleware is created).

`buildRouter()` mounts it on passkey registration (`/webauthn/registration/options` and
`/verify`), `DELETE /me/passkeys/:credentialId`, `POST /me/mfa/setup` and `/me/mfa/confirm`, and
`DELETE /me`. Use it on your own sensitive routes the same way:

```js
import { authContextMiddleware, requireRecentAuth } from '@okeav/idp-core';

app.post('/api/billing/payout-account',
  authContextMiddleware(),
  requireRecentAuth({ maxAgeSeconds: 300 }),
  updatePayoutAccount);
```

## CSRF origin check

A cookie is attached by the browser whoever builds the request; `SameSite=Lax` keeps it off
cross-*site* POSTs, but not off requests from a sibling subdomain (same site, different origin),
and not at all under `cookies.sameSite: 'none'`. So a **state-changing** request (anything but
`GET`/`HEAD`/`OPTIONS`) whose credential is a **cookie** must also come from a trusted origin:

- `Sec-Fetch-Site: same-origin` → allowed.
- An `Origin` header → it must be the issuer's origin or one of `config.cookies.trustedOrigins`
  (env `IDP_COOKIE_TRUSTED_ORIGINS`, comma-separated) — exact `scheme://host[:port]` strings.
- Neither header → not a browser → allowed. (A `Sec-Fetch-Site` other than `same-origin`/`none`
  with no `Origin` is refused.)

Anything else is refused with 403 `CSRF_ORIGIN_REJECTED`. The check runs in
`authContextMiddleware` when the token came from the `access_token` cookie, in `POST /refresh`
when the refresh token came from the `refresh_token` cookie, and in `POST /logout` when no
`refreshToken` is in the body. Requests authenticated with an `Authorization: Bearer` header (or a
refresh token in the body) are unaffected — a browser never attaches those on its own.

```js
cookies: {
  trustedOrigins: ['https://app.example.com', 'https://admin.example.com'],
}
```

## `serviceContextMiddleware(opts?)`

```ts
function serviceContextMiddleware(opts?: { ownServiceName?: string }): RequestHandler
```

Authenticates an inbound service-to-service request against this IDP's own service-key registry
(in-process — no HTTP round trip) and sets `req.serviceCaller`. **The shape is mode-dependent, not
uniform**: under `source: 'token'` it's `{ name, scopes, region, source }`; under
`source: 'legacy-secret'` it's only `{ name, source }` — no `scopes`/`region` keys at all, not even
empty. `scopes` are whatever the calling service put in its own token — not granted by anyone, so
never authorize on them alone. See [Service Mesh](service-mesh.md) for the full S2S trust model.

Mode is `config.serviceMesh.tokenMode` (`'token' | 'secret' | 'both'`, default **`'token'`**):
- **`'token'`** — requires a valid S2S JWT in the `Authorization: Bearer` header, verified against
  the local service-key registry. `req.serviceCaller.source = 'token'`.
- **`'secret'`** — legacy shared-secret fallback: compares the `x-internal-service-secret` header
  (in constant time) against `config.serviceMesh.sharedSecret`, trusting the `x-service-name`
  header for the caller's claimed identity (**not cryptographically verified** — anyone with the
  shared secret can claim any name). `req.serviceCaller.source = 'legacy-secret'`.
- **`'both'`** — tries the token first if a bearer is present; on verification *failure* it logs a
  warning before falling back to the secret check, and a **missing** bearer falls back silently.

`opts.ownServiceName` (or `config.serviceMesh.ownServiceName`) is this service's own name — the
token's expected `aud`. It's required in `'token'` and `'both'` mode.

Throws:
- `SERVICE_NOT_CONFIGURED` (500) — no `ownServiceName` (in `'token'`/`'both'` mode — it never
  falls back to the secret for that), or the mode allows the secret fallback but no `sharedSecret`
  is configured.
- Whatever token verification throws under `mode: 'token'` (no fallback).
- `SERVICE_AUTH_FAILED` (401) — secret mismatch, or no check could run.

## `requireServiceCallerMiddleware(...allowedCallers)`

```ts
function requireServiceCallerMiddleware(...allowedCallers: string[]): RequestHandler
```

Pins an internal endpoint to a specific set of upstream services by name. Must run **after**
`serviceContextMiddleware`. Name-allowlist only — not an RBAC decision (this package has no
scope-catalogue concept).

Shared-secret callers (`req.serviceCaller.source === 'legacy-secret'`) are **refused** with 403
`FORBIDDEN` — their name came from an unverified header — unless
`config.serviceMesh.allowLegacySecretCallers: true`, in which case they're let through with a
logged warning.

Throws:
- `requireServiceCallerMiddleware(...names)` throws a plain `Error` synchronously if called with
  zero arguments (it's a factory function, not a class — no `new` involved).
- `UNAUTHENTICATED` (401) — `req.serviceCaller` unset (i.e. `serviceContextMiddleware` wasn't
  mounted first).
- `FORBIDDEN` (403) — `req.serviceCaller.name` not in the allowlist, or a shared-secret caller
  without `allowLegacySecretCallers`.

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
`access_token`/`refresh_token` cookies, and before the SSO routes, which need their binding
cookie).

## `idpErrorHandler(opts?)`

```ts
function idpErrorHandler(opts?: { logger?: Logger }): ErrorRequestHandler
```

Handlers never shape error responses themselves — they call `next(err)` with an `IdpError`
(`{ code, httpStatus, status, statusCode, expose, message }`). `idpErrorHandler()` is an Express
error handler that is safe to expose to the internet; mount it **after** the router:

- An `IdpError` below 500 → `res.status(httpStatus).json({ error: code, message })`.
- A malformed JSON body → 400 `{ error: 'INVALID_REQUEST', message: 'Malformed request body' }`;
  an oversized body → 413 `{ error: 'PAYLOAD_TOO_LARGE', ... }` — fixed messages, never the
  parser's text (which echoes the request body).
- Anything else — an `IdpError` of 500+, a database error, a bug — answers its status (500 for
  non-`IdpError`s) with a bare `{ error: code }` / `{ error: 'INTERNAL_ERROR' }`: no message, stack
  or driver detail. It's logged through `opts.logger.error` if you pass one.

If you write your own handler, apply the same rule: only show `err.message` when `err.expose` is
true. See [Errors](errors.md).

## Response caching

Every response from `buildRouter()` carries `Cache-Control: no-store` (they may carry tokens,
codes or account data), except the public-key documents: `/.well-known/jwks.json` and `/keys/:kid`
send `Cache-Control: public, max-age=300`, and `/.well-known/openid-configuration` sends
`public, max-age=<ttls.discoveryCache>` (default 3600). If you mount handlers individually, set
`no-store` yourself.

## Mounting order

```js
import express from 'express';
import { buildRouter, cookieParser, idpErrorHandler } from '@okeav/idp-core';

app.use(cookieParser());
app.use(express.json());
app.use('/auth', buildRouter());
app.use(idpErrorHandler({ logger }));
```

If wiring handlers individually rather than via `buildRouter()` (see
[Router & Schemas](router-and-schemas.md)), mount `validateBody`/`validateQuery` before the
handler, `authContextMiddleware()` before any handler that reads `req.auth`, and
`requireRecentAuth()` after it where you need a fresh login.

## Related

- [Errors](errors.md) — every code above.
- [Tokens & Signing](tokens-rs256.md) — access-token kinds, `auth_time`, and `verifyAccessToken`.
- [Cache Interface](cache-interface.md) — the revocation-cache fail-closed behavior.
- [Repository Adapters](repository-adapters.md) — `SessionRepository.findByJti`.
- [Service Mesh](service-mesh.md) — the S2S trust model behind `serviceContextMiddleware`.
- [Router & Schemas](router-and-schemas.md) — the exported zod schemas these middlewares consume.
